"""Web 层的服务逻辑：协议查询、配置保存、生成调度、产物读取与预览。

这一层不 import FastAPI —— 业务逻辑可以脱离 HTTP 单独测试。
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..generator import build_dataset
from ..protocols.base import BuildContext
from ..protocols.registry import (
    available_protocols,
    get_adapter,
    get_catalog,
    transport_kind,
)
from ..spec.loader import ScenarioOperationModel, validate_operations
from ..spec.model import Operation, Scenario, Variant
from .models import ConfigPayload, OperationInput
from .store import WebStore

#: 单个操作的交互数量上限
MAX_COUNT_PER_OPERATION = 1000
#: 一次生成的总交互数量上限
MAX_TOTAL_COUNT = 5000


class WebError(ValueError):
    """Web 层请求不合法。"""


class NotFound(WebError):
    """目标不存在。"""


class AlreadyGenerated(WebError):
    """该配置已生成过。"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def list_protocols() -> list[dict[str, Any]]:
    """协议列表：名称、说明、传输、操作类型数与覆盖条目数。"""
    items = []
    for info in available_protocols():
        catalog = get_catalog(info.name)
        items.append(
            {
                "name": info.name,
                "summary": info.summary,
                # 给的是传输种类（tcp/serial），不是 catalog 里的传输名（tcp/rtu）——
                # 页面要回传的就是它，映射只应有一份，在注册表里。
                "transports": [transport_kind(name) for name in info.transports],
                "operation_count": catalog.count(),
                "coverage_count": catalog.coverage_count(),
            }
        )
    return items


def list_operations(protocol: str) -> list[dict[str, Any]]:
    """操作类型列表：名称、说明、功能码、可用变体与参数 schema。"""
    catalog = get_catalog(protocol)
    return [
        {
            "name": entry.name,
            "summary": entry.summary,
            "layout": entry.layout,
            "func_code": entry.func_code,
            "variants": list(entry.variants),
            "params": deepcopy(entry.params),
        }
        for entry in catalog.operations.values()
    ]


def _check_counts(operations: list[OperationInput]) -> None:
    """校验交互数量：单操作与总量各有上限。"""
    total = 0
    for index, item in enumerate(operations):
        if item.count < 1:
            raise WebError(f"第 {index} 条操作的交互数量必须不小于 1")
        if item.count > MAX_COUNT_PER_OPERATION:
            raise WebError(
                f"第 {index} 条操作的交互数量 {item.count} 超过单操作上限 "
                f"{MAX_COUNT_PER_OPERATION}"
            )
        total += item.count
    if total > MAX_TOTAL_COUNT:
        raise WebError(f"交互总数 {total} 超过总量上限 {MAX_TOTAL_COUNT}")


def save_config(store: WebStore, payload: ConfigPayload) -> dict[str, Any]:
    """保存一条配置记录。记录落盘后不可修改、不可删除。"""
    if not payload.operations:
        raise WebError("至少要选择一条操作")
    try:
        catalog = get_catalog(payload.protocol)
    except KeyError as exc:
        # KeyError 的消息里已经带上了可用协议列表（spec §12：提示可用协议列表）
        raise NotFound(str(exc)) from exc
    items = []
    for index, item in enumerate(payload.operations):
        try:
            variant = Variant(item.variant)
        except ValueError as exc:
            raise WebError(f"第 {index} 条操作的变体 {item.variant!r} 不合法") from exc
        items.append(
            ScenarioOperationModel(op=item.op, params=item.params, variant=variant)
        )
    validate_operations(catalog, items, context="提交的操作")
    _check_counts(payload.operations)
    record = {
        "id": f"cfg_{uuid.uuid4().hex[:12]}",
        "name": payload.name,
        # 本期没有用户维度，字段位先占住，将来加用户不用改存储格式（spec §17）
        "owner": None,
        "protocol": payload.protocol,
        "transport": payload.transport,
        "operations": [item.model_dump() for item in payload.operations],
        "created_at": _now(),
    }
    return store.save_config(record)


def build_scenario(config: dict[str, Any]) -> Scenario:
    """把一条配置记录展开成场景：每个操作按 count 重复。"""
    operations: list[Operation] = []
    for item in config.get("operations", []):
        operation = Operation(
            op=item["op"],
            params=item.get("params", {}),
            variant=Variant(item.get("variant", "normal")),
        )
        for _ in range(int(item.get("count", 1))):
            operations.append(operation)
    return Scenario(
        name=config.get("name", "web"),
        transport=config.get("transport", {}),
        operations=tuple(operations),
    )


def recover_orphan_generations(store: WebStore) -> int:
    """把「有 started 无终态」的生成标记为失败（spec §10.3 的启动孤儿恢复）。

    进程重启后，之前在跑的任务不会自己结束 —— 账本里会留下只有
    generation_started、没有终态事件的生成。启动时补一条 failed 事件，
    仍然是追加写入，历史行不被修改。

    返回被标记的生成数。
    """
    orphans = [
        generation["id"]
        for generation in store.list_generations()
        if generation.get("status") == "running"
    ]
    for generation_id in orphans:
        store.append_event(
            {
                "type": "generation_failed",
                "generation_id": generation_id,
                "error": "服务重启导致生成中断",
                "finished_at": _now(),
            }
        )
    return len(orphans)


class GenerationService:
    """发起生成任务并跟踪进度。"""

    def __init__(self, store: WebStore) -> None:
        self.store = store
        self._jobs: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        recover_orphan_generations(store)

    def start(self, config_id: str) -> dict[str, Any]:
        """发起一次生成。同一配置只能生成一次。"""
        config = self.store.get_config(config_id)
        if config is None:
            raise NotFound(f"配置记录 {config_id!r} 不存在")
        # 守卫与「追加 started 事件」必须原子 —— 否则两个并发请求会同时
        # 通过检查，把同一份配置生成两次（spec §6.3 / §12 的 409）。
        with self._lock:
            existing = self.store.generation_for_config(config_id)
            if existing is not None:
                raise AlreadyGenerated(f"该配置已生成过（{existing}），不能重复生成")
            generation_id = f"gen_{uuid.uuid4().hex[:12]}"
            output_dir = self.store.generation_dir(generation_id)
            self.store.append_event(
                {
                    "type": "generation_started",
                    "generation_id": generation_id,
                    "config_id": config_id,
                    "config_name": config.get("name"),
                    "output_dir": str(output_dir),
                    "created_at": _now(),
                }
            )
            job = {
                "generation_id": generation_id,
                "done": 0,
                "total": 0,
                "phase": "building",
                "error": None,
            }
            self._jobs[generation_id] = job
        thread = threading.Thread(
            target=self._run, args=(config, generation_id, output_dir, job), daemon=True
        )
        thread.start()
        return {"generation_id": generation_id, "status": "running"}

    def _run(
        self,
        config: dict[str, Any],
        generation_id: str,
        output_dir: Path,
        job: dict[str, Any],
    ) -> None:
        started = time.monotonic()
        try:
            scenario = build_scenario(config)
            adapter = get_adapter(config["protocol"])

            def on_progress(done: int, total: int) -> None:
                job["done"] = done
                job["total"] = total
                if done >= total:
                    job["phase"] = "writing"

            build_dataset(
                scenario, adapter, output_dir, name=generation_id, on_progress=on_progress
            )
            manifest = json.loads(
                (output_dir / "manifest.json").read_text(encoding="utf-8")
            )
            packet_count = sum(
                entry.get("pcap_frame_count", 0) for entry in manifest["artifacts"]
            )
            # 先落内存态，再追加事件：账本一旦出现 generation_succeeded，
            # 内存里的 phase 必须已经是 done —— 否则轮询会看到
            # 「状态成功、进度 85%」这种自相矛盾的组合
            # （写盘其实早就完成了，85% 才是谎报）。
            job["phase"] = "done"
            self.store.append_event(
                {
                    "type": "generation_succeeded",
                    "generation_id": generation_id,
                    "artifact_count": len(manifest["artifacts"]),
                    "packet_count": packet_count,
                    "duration_ms": int((time.monotonic() - started) * 1000),
                    "finished_at": _now(),
                }
            )
        except Exception as exc:  # 生成失败要落成事件，不能让线程静默死掉
            job["error"] = str(exc)
            job["phase"] = "failed"
            self.store.append_event(
                {
                    "type": "generation_failed",
                    "generation_id": generation_id,
                    "error": str(exc),
                    "finished_at": _now(),
                }
            )

    def state(self, generation_id: str) -> dict[str, Any] | None:
        """任务的内存状态；没有记录时返回 None。

        任务结束后条目仍留在内存里，phase 变成 done / failed ——
        调用方靠 phase 区分进行中与已结束。
        """
        with self._lock:
            job = self._jobs.get(generation_id)
            return dict(job) if job else None


def read_manifest(store: WebStore, generation_id: str) -> dict[str, Any] | None:
    """读生成目录的 manifest；数据集尚未写完或不存在时返回 None。"""
    path = store.generation_dir(generation_id) / "manifest.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _artifact_summaries(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """产物清单：页面上要显示的字段。"""
    return [
        {
            "id": entry["id"],
            "op": entry["op"],
            "variant": entry["variant"],
            "tier": entry["tier"],
            "protocol": entry["protocol"],
            "transport": entry["transport"],
            "len": entry["len"],
            "sha256": entry["sha256"],
            "has_response": "resp_len" in entry,
            "pcap_file": entry.get("pcap_file"),
            "pcap_index": entry.get("pcap_index"),
        }
        for entry in manifest["artifacts"]
    ]


def _percent(done: int, total: int, phase: str) -> float:
    """两阶段进度：生成帧占 0–85，写盘占 85–100；失败一律 0。"""
    if phase == "done":
        return 100.0
    if phase == "failed":
        # 失败不是进度 —— 重启后（没有内存任务）也是 0，两条路径必须一致。
        return 0.0
    if total <= 0:
        return 0.0
    if phase == "writing":
        return 85.0
    return round(done / total * 85, 1)


def generation_detail(
    store: WebStore, service: GenerationService, generation_id: str
) -> dict[str, Any]:
    """生成任务的完整状态：事件折叠出的状态 + 内存进度 + 产物清单。"""
    record = next(
        (item for item in store.list_generations() if item["id"] == generation_id), None
    )
    if record is None:
        raise NotFound(f"生成记录 {generation_id!r} 不存在")
    detail = dict(record)
    job = service.state(generation_id)
    if job is not None:
        detail["done"] = job["done"]
        detail["total"] = job["total"]
        detail["phase"] = job["phase"]
    else:
        detail["done"] = 0
        detail["total"] = 0
        # 没有内存任务说明生成已经结束：成功是 done，失败就保持 failed ——
        # 不能一律当 done，那会让失败的生成显示 100% 进度。
        detail["phase"] = "done" if detail["status"] == "succeeded" else detail["status"]
    detail["percent"] = _percent(detail["done"], detail["total"], detail["phase"])
    manifest = read_manifest(store, generation_id)
    detail["artifacts"] = _artifact_summaries(manifest) if manifest else []
    return detail


def _view_dict(view: Any) -> dict[str, Any]:
    return {
        "summary": view.summary,
        "fields": [{"name": field.name, "value": field.value} for field in view.fields],
        "is_exception": view.is_exception,
        "exception_code": view.exception_code,
    }


def artifact_detail(
    store: WebStore, generation_id: str, artifact_id: str
) -> dict[str, Any]:
    """一条产物的请求/响应帧 hex 与协议级解析结果。"""
    manifest = read_manifest(store, generation_id)
    if manifest is None:
        raise NotFound(f"生成记录 {generation_id!r} 的数据集不存在")
    entry = next(
        (item for item in manifest["artifacts"] if item["id"] == artifact_id), None
    )
    if entry is None:
        raise NotFound(f"产物 {artifact_id!r} 不存在")
    frames_dir = (
        store.generation_dir(generation_id)
        / entry["tier"]
        / f"{entry['protocol']}_{entry['transport']}"
        / "frames"
    )
    request_path = frames_dir / f"{artifact_id}.bin"
    if not request_path.exists():
        raise NotFound(f"产物 {artifact_id!r} 的请求帧文件不存在")
    request = request_path.read_bytes()
    response_path = frames_dir / f"{artifact_id}.resp.bin"
    response = response_path.read_bytes() if response_path.exists() else None
    adapter = get_adapter(entry["protocol"])
    ctx = BuildContext(transport=entry["transport"], unit_id=0xFF)
    request_view = adapter.inspect(entry["op"], request, ctx, "request")
    response_view = (
        adapter.inspect(entry["op"], response, ctx, "response") if response else None
    )
    return {
        "id": artifact_id,
        "op": entry["op"],
        "variant": entry["variant"],
        "tier": entry["tier"],
        "request": {"hex": request.hex(" "), "view": _view_dict(request_view)},
        "response": (
            {"hex": response.hex(" "), "view": _view_dict(response_view)}
            if response
            else None
        ),
    }
