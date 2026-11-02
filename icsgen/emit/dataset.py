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

from ..transport.pcap import write_pcap
from .raw import write_raw


@dataclass(frozen=True)
class Artifact:
    """一条产物记录。

    一次操作 = 一个 Artifact：请求与响应都挂在同一条记录上，
    response 为 None 表示这次操作不应有响应（如畸形帧）。
    """

    id: str
    protocol: str
    transport: str
    op: str
    variant: str
    tier: str
    payload: bytes
    response: bytes | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    parent_id: str | None = None
    mutation: dict[str, Any] | None = None


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _session_key(artifact: Artifact) -> str:
    """会话键：tier/protocol_transport。

    目录路径与 manifest 里的 pcap 索引都从这里派生，避免两处各写一遍
    格式而悄悄漂移。
    """
    return f"{artifact.tier}/{artifact.protocol}_{artifact.transport}"


class DatasetBuilder:
    """收集产物并写出分层数据集。"""

    def __init__(self, name: str, root: Path) -> None:
        self.name = name
        self.root = root
        self.artifacts: list[Artifact] = []
        self._packets: dict[str, list[bytes]] = {}
        self._positions: dict[str, tuple[str, int]] = {}
        self._response_positions: dict[str, tuple[str, int]] = {}

    def add(self, artifact: Artifact) -> None:
        """登记一条产物。"""
        self.artifacts.append(artifact)

    def add_linked_packets(self, artifact_id: str, packets: list[bytes]) -> None:
        """把链路字节挂到它所属的 (tier, transport) 会话中。

        artifact_id 形如 ``<op>#<n>``，需与已登记的产物 id 对应。
        一次操作在会话里是连续的请求与响应，因此这里接受一组包：首个是
        请求，次个是响应。挂载时即记录各自在会话中的包序号，供 manifest 索引。
        """
        artifact = next((a for a in self.artifacts if a.id == artifact_id), None)
        if artifact is None:
            raise KeyError(f"未登记的产物 id：{artifact_id!r}")
        if not packets:
            raise ValueError(f"产物 {artifact_id!r} 至少要挂一个包")
        key = _session_key(artifact)
        session = self._packets.setdefault(key, [])
        for offset, packet in enumerate(packets):
            index = len(session)
            session.append(packet)
            if offset == 0:
                self._positions[artifact_id] = (key, index)
            elif offset == 1:
                self._response_positions[artifact_id] = (key, index)

    def write(self) -> Path:
        """写出数据集目录，返回根路径。"""
        return write_dataset(
            self.name,
            self.root,
            self.artifacts,
            self._packets,
            self._positions,
            self._response_positions,
        )


def write_dataset(
    name: str,
    root: Path,
    artifacts: list[Artifact],
    packets: dict[str, list[bytes]],
    positions: dict[str, tuple[str, int]] | None = None,
    response_positions: dict[str, tuple[str, int]] | None = None,
) -> Path:
    """写出分层数据集与 manifest.json。

    positions 为「产物 id → (会话键, 包序号)」，response_positions 为响应
    帧的同类记录，由 DatasetBuilder 在挂载链路字节时记录，用于在 manifest
    中精确定位每条产物所在的请求包与响应包。

    只有 positions 命中的产物才会带上 ``pcap_file`` / ``pcap_index`` 字段；
    直接调用本函数而不传 positions 时，manifest 里不会有包位置信息。
    """
    root.mkdir(parents=True, exist_ok=True)
    positions = positions or {}
    response_positions = response_positions or {}

    counts: dict[str, int] = {}
    entries: list[dict[str, Any]] = []

    for artifact in artifacts:
        tier_dir = root / _session_key(artifact)
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
        if artifact.response is not None:
            write_raw(frames_dir, f"{artifact.id}.resp", artifact.response)
            entry["resp_len"] = len(artifact.response)
            entry["resp_sha256"] = _sha256(artifact.response)
        response_position = response_positions.get(artifact.id)
        if response_position is not None:
            _, index = response_position
            entry["pcap_resp_index"] = index
        if artifact.parent_id is not None:
            entry["parent_id"] = artifact.parent_id
        if artifact.mutation is not None:
            entry["mutation"] = artifact.mutation
        entries.append(entry)

    for key, plist in packets.items():
        tier, transport_dir = key.split("/", 1)
        write_pcap(root / tier / transport_dir / "session.pcap", plist)

    manifest = {
        "dataset": name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "protocols": sorted({artifact.protocol for artifact in artifacts}),
        "counts": counts,
        "artifacts": entries,
    }
    (root / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return root
