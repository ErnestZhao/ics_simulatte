"""append-only 账本：配置记录与生成事件。

两份账本都只追加，不修改既有行 —— 配置记录与生成记录因此天然不可删改。
写入用进程内锁与文件锁串行化；读取时容错解码并跳过损坏行，避免单行问题拖垮整个页面。
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class Ledger:
    """一个只追加的 JSONL 账本。"""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        """追加一条记录并落盘，返回它。"""
        line = json.dumps(record, ensure_ascii=False)
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    handle.write(line + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        return record

    def read_all(self) -> list[dict[str, Any]]:
        """读出全部记录；空行、非法字节与解析失败的行被跳过并告警。

        逐行解码：某一行里有非法字节就整行作废，绝不让替换字符混进
        记录 —— 那会让调用方拿到一条内容被悄悄改过的数据。
        """
        try:
            raw_lines = self.path.read_bytes().splitlines()
        except FileNotFoundError:
            return []
        records: list[dict[str, Any]] = []
        for number, raw in enumerate(raw_lines, start=1):
            try:
                line = raw.decode("utf-8")
            except UnicodeDecodeError:
                logger.warning("跳过账本 %s 第 %d 行：不是合法 UTF-8", self.path, number)
                continue
            if number == 1:
                line = line.removeprefix("\ufeff")
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("跳过账本 %s 第 %d 行：不是合法 JSON", self.path, number)
                continue
            if not isinstance(record, dict):
                logger.warning("跳过账本 %s 第 %d 行：不是 JSON 对象", self.path, number)
                continue
            records.append(record)
        return records


class WebStore:
    """Web 层的持久化入口：两个账本 + 生成目录。"""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self._configs = Ledger(self.root / "configs.jsonl")
        self._events = Ledger(self.root / "events.jsonl")

    # ---- 配置记录 ----
    def save_config(self, record: dict[str, Any]) -> dict[str, Any]:
        """追加一条配置记录。记录落盘后不可修改、不可删除。"""
        return self._configs.append(record)

    def list_configs(self) -> list[dict[str, Any]]:
        return self._configs.read_all()

    def get_config(self, config_id: str) -> dict[str, Any] | None:
        for record in reversed(self._configs.read_all()):
            if record.get("id") == config_id:
                return record
        return None

    # ---- 生成事件 ----
    def append_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """追加一条生成事件。"""
        return self._events.append(event)

    def list_events(self) -> list[dict[str, Any]]:
        return self._events.read_all()

    def list_generations(self) -> list[dict[str, Any]]:
        """把事件流折叠成生成记录列表，最新的在前。"""
        generations: dict[str, dict[str, Any]] = {}
        order: list[str] = []
        for event in self.list_events():
            generation_id = event.get("generation_id")
            if not generation_id:
                continue
            if generation_id not in generations:
                generations[generation_id] = {
                    "id": generation_id,
                    "config_id": event.get("config_id"),
                    "config_name": event.get("config_name"),
                    "output_dir": event.get("output_dir"),
                    "status": "running",
                    "created_at": event.get("created_at"),
                    "finished_at": None,
                    "artifact_count": None,
                    "packet_count": None,
                    "duration_ms": None,
                    "error": None,
                }
                order.append(generation_id)
            kind = event.get("type")
            if kind == "generation_succeeded":
                generations[generation_id].update(
                    status="succeeded",
                    artifact_count=event.get("artifact_count"),
                    packet_count=event.get("packet_count"),
                    duration_ms=event.get("duration_ms"),
                    finished_at=event.get("finished_at"),
                )
            elif kind == "generation_failed":
                generations[generation_id].update(
                    status="failed",
                    error=event.get("error"),
                    finished_at=event.get("finished_at"),
                )
        return [generations[gid] for gid in reversed(order)]

    def generation_for_config(self, config_id: str) -> str | None:
        """返回该配置最近一次发起的生成 id；未发起过返回 None。"""
        for event in reversed(self.list_events()):
            if (
                event.get("type") == "generation_started"
                and event.get("config_id") == config_id
            ):
                return event.get("generation_id")
        return None

    def generations_by_config(self) -> dict[str, str]:
        """配置 id → 已发起的生成 id。"""
        mapping: dict[str, str] = {}
        for event in self.list_events():
            if event.get("type") == "generation_started":
                mapping[event.get("config_id")] = event.get("generation_id")
        return mapping

    def generation_dir(self, generation_id: str) -> Path:
        """一个生成任务的数据集目录。"""
        return self.root / "generations" / generation_id
