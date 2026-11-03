"""分层数据集的组装与 manifest 生成。

产物按 tier（legit/abnormal/mutated）与 transport 双层分目录，
pcap 按 (tier, transport) 聚合为一个文件，保持会话内请求/响应连续。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..transport.link import sll_header
from ..transport.pcap import LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL, write_pcap
from .raw import write_raw


@dataclass(frozen=True)
class Artifact:
    """一条产物记录。

    一次操作 = 一个 Artifact：请求与响应都挂在同一条记录上，
    response 为 None 表示这次操作不应有响应（如畸形帧）。
    extra_frames 是应答之后的追加帧（成对变异规则的重放帧），它们同样
    进入会话 pcap，但不属于请求/应答配对。
    """

    id: str
    protocol: str
    transport: str
    op: str
    variant: str
    tier: str
    payload: bytes
    response: bytes | None = None
    extra_frames: tuple[bytes, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)
    parent_id: str | None = None
    mutation: dict[str, Any] | None = None


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def session_key(artifact: Artifact) -> str:
    """会话键：tier/protocol_transport。

    目录路径与 manifest 里的 pcap 索引都从这里派生，避免两处各写一遍
    格式而悄悄漂移。
    """
    return f"{artifact.tier}/{artifact.protocol}_{artifact.transport}"


def frame_roles(artifact: Artifact) -> list[bool]:
    """会话内每帧的方向：True 为客户端发出，False 为服务端应答。

    请求在前、应答在后，追加帧（重放）由客户端发出。
    """
    roles = [True]
    if artifact.response is not None:
        roles.append(False)
    roles.extend([True] * len(artifact.extra_frames))
    return roles


class DatasetBuilder:
    """收集产物并写出分层数据集。"""

    def __init__(
        self, name: str, root: Path, transport: dict[str, Any] | None = None
    ) -> None:
        self.name = name
        self.root = root
        self.transport = transport
        self.artifacts: list[Artifact] = []
        self._by_id: dict[str, Artifact] = {}
        self._packets: dict[str, list[bytes]] = {}
        self._positions: dict[str, tuple[str, int]] = {}
        self._response_positions: dict[str, tuple[str, int]] = {}

    def add(self, artifact: Artifact) -> None:
        """登记一条产物。"""
        self.artifacts.append(artifact)
        # 同 id 重复登记时以先登记的为准
        self._by_id.setdefault(artifact.id, artifact)

    def add_linked_packets(self, artifact_id: str, packets: list[bytes]) -> None:
        """把链路字节挂到它所属的 (tier, transport) 会话中。

        artifact_id 形如 ``<op>#<n>``，需与已登记的产物 id 对应。
        一次操作在会话里是连续的请求与响应，因此这里接受一组包：首个是
        请求，次个是响应，其后是追加帧。挂载时即记录各自在会话中的包
        序号，供 manifest 索引。
        """
        artifact = self._by_id.get(artifact_id)
        if artifact is None:
            raise KeyError(f"未登记的产物 id：{artifact_id!r}")
        if not packets:
            raise ValueError(f"产物 {artifact_id!r} 至少要挂一个包")
        roles = frame_roles(artifact)
        if len(packets) != len(roles):
            raise ValueError(
                f"产物 {artifact_id!r} 有 {len(roles)} 帧，却挂了 {len(packets)} 个包"
            )
        key = session_key(artifact)
        session = self._packets.setdefault(key, [])
        for offset, packet in enumerate(packets):
            index = len(session)
            session.append(packet)
            if offset == 0:
                self._positions[artifact_id] = (key, index)
            elif offset == 1:
                self._response_positions[artifact_id] = (key, index)

    def begin_session(self, key: str, packets: list[bytes]) -> None:
        """会话的前导包（TCP 握手）。

        必须在该会话的任何产物挂进来之前调用 —— 前导包要占住包序号，
        产物的 pcap_index 由此偏移。
        """
        session = self._packets.setdefault(key, [])
        if session:
            raise ValueError(f"会话 {key!r} 已经有包了，不能再插入前导包")
        session.extend(packets)

    def end_session(self, key: str, packets: list[bytes]) -> None:
        """会话的收尾包（TCP 挥手）。"""
        self._packets.setdefault(key, []).extend(packets)

    def write(self) -> Path:
        """写出数据集目录，返回根路径。"""
        return write_dataset(
            self.name,
            self.root,
            self.artifacts,
            self._packets,
            self._positions,
            self._response_positions,
            self.transport,
        )


def write_dataset(
    name: str,
    root: Path,
    artifacts: list[Artifact],
    packets: dict[str, list[bytes]],
    positions: dict[str, tuple[str, int]] | None = None,
    response_positions: dict[str, tuple[str, int]] | None = None,
    transport: dict[str, Any] | None = None,
) -> Path:
    """写出分层数据集与 manifest.json。

    positions 为「产物 id → (会话键, 包序号)」，response_positions 为响应
    帧的同类记录，由 DatasetBuilder 在挂载链路字节时记录，用于在 manifest
    中精确定位每条产物所在的请求包与响应包。

    只有 positions 命中的产物才会带上 ``pcap_file`` / ``pcap_index`` 字段；
    直接调用本函数而不传 positions 时，manifest 里不会有包位置信息。

    transport 是本次会话的传输层参数，写进 manifest 后，派生数据集（如
    变异数据集）可以据此原样重建链路封装。
    """
    root.mkdir(parents=True, exist_ok=True)
    positions = positions or {}
    response_positions = response_positions or {}

    counts: dict[str, int] = {}
    entries: list[dict[str, Any]] = []
    directions = _session_directions(artifacts, positions)

    for artifact in artifacts:
        tier_dir = root / session_key(artifact)
        frames_dir = tier_dir / "frames"
        write_raw(frames_dir, artifact.id, artifact.payload)

        counts[artifact.tier] = counts.get(artifact.tier, 0) + 1
        entry: dict[str, Any] = {
            "id": artifact.id,
            "protocol": artifact.protocol,
            "transport": artifact.transport,
            "op": artifact.op,
            "variant": artifact.variant,
            "tier": artifact.tier,
            "len": len(artifact.payload),
            "sha256": _sha256(artifact.payload),
            "meta": artifact.metadata,
        }
        position = positions.get(artifact.id)
        if position is not None:
            key, index = position
            entry["pcap_file"] = f"{key}/session.pcap"
            entry["pcap_index"] = index
            entry["pcap_frame_count"] = len(frame_roles(artifact))
        if artifact.response is not None:
            write_raw(frames_dir, f"{artifact.id}.resp", artifact.response)
            entry["resp_len"] = len(artifact.response)
            entry["resp_sha256"] = _sha256(artifact.response)
        response_position = response_positions.get(artifact.id)
        if response_position is not None:
            _, index = response_position
            entry["pcap_resp_index"] = index
        for offset, frame in enumerate(artifact.extra_frames, start=2):
            write_raw(frames_dir, f"{artifact.id}.frame{offset}", frame)
        if artifact.parent_id is not None:
            entry["parent_id"] = artifact.parent_id
        if artifact.mutation is not None:
            entry["mutation"] = artifact.mutation
        entries.append(entry)

    serial = bool(transport) and transport.get("kind") == "serial"
    for key, plist in packets.items():
        tier, transport_dir = key.split("/", 1)
        path = root / tier / transport_dir / "session.pcap"
        if serial:
            session_dirs = directions.get(key, [])
            write_pcap(
                path,
                [
                    sll_header(outgoing=session_dirs[index] if index < len(session_dirs) else True)
                    + packet
                    for index, packet in enumerate(plist)
                ],
                link_type=LINKTYPE_LINUX_SLL,
            )
        else:
            write_pcap(path, plist, link_type=LINKTYPE_ETHERNET)

    manifest: dict[str, Any] = {
        "dataset": name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "protocols": sorted({artifact.protocol for artifact in artifacts}),
        "counts": counts,
        "artifacts": entries,
    }
    if transport is not None:
        manifest["transport"] = transport
    (root / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return root


def _session_directions(
    artifacts: list[Artifact], positions: dict[str, tuple[str, int]]
) -> dict[str, list[bool]]:
    """推导每个会话里各包的方向。

    产物在会话里的包是连续的，方向由产物自身的帧序决定：请求由客户端
    发出，应答由服务端回送，追加帧是客户端的重放。
    """
    directions: dict[str, list[bool]] = {}
    for artifact in artifacts:
        position = positions.get(artifact.id)
        if position is None:
            continue
        key, index = position
        session_dirs = directions.setdefault(key, [])
        while len(session_dirs) < index:
            session_dirs.append(True)
        for offset, role in enumerate(frame_roles(artifact)):
            target = index + offset
            if target < len(session_dirs):
                session_dirs[target] = role
            else:
                session_dirs.append(role)
    return directions
