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


def _valid_id(value: Any) -> bool:
    """账本里的 id 必须是非空字符串。

    账本是磁盘上的持久化文件，会被截断、被手工改过 —— 形态不对的 id
    不该被当成一条记录，否则「同一配置只能生成一次」的守卫会在脏数据下失效。
    """
    return isinstance(value, str) and bool(value)


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
            if not _valid_id(generation_id):
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
            if event.get("type") != "generation_started":
                continue
            if event.get("config_id") != config_id:
                continue
            generation_id = event.get("generation_id")
            if _valid_id(generation_id):
                return generation_id
        return None

    def generations_by_config(self) -> dict[str, str]:
        """配置 id → 最近一次发起的生成 id。"""
        mapping: dict[str, str] = {}
        for event in reversed(self.list_events()):
            if event.get("type") != "generation_started":
                continue
            config_id = event.get("config_id")
            generation_id = event.get("generation_id")
            if not _valid_id(config_id) or not _valid_id(generation_id):
                continue
            mapping.setdefault(config_id, generation_id)
        return mapping

    def generation_dir(self, generation_id: str) -> Path:
        """一个生成任务的数据集目录。"""
        return self.root / "generations" / generation_id


class RootOwnerLock:
    """数据目录的所有者锁：同一目录同时只允许一个服务进程做启动孤儿恢复。

    用 flock 拿锁 —— 进程退出时由内核释放，不会留下需要人工清理的僵尸锁。
    拿不到锁说明**另一个进程正在用这个目录**，此时本进程不能执行孤儿恢复：
    把别人正在跑的任务判成孤儿，会往只追加的账本里写一条永远删不掉的假失败。

    锁文件放在数据目录根下（`.lock`），与账本同目录。
    """

    def __init__(self, root: Path) -> None:
        self.acquired = False
        self._handle = None
        path = Path(root) / ".lock"
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            handle = path.open("a+")
        except OSError as exc:
            # 拿不到锁文件（只读目录等）时不能断定「有人在用」，
            # 只能放弃独占权、退回无锁行为。
            logger.warning("打不开数据目录的锁文件 %s：%s", path, exc)
            return
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            handle.close()
            logger.warning("数据目录 %s 已被另一个服务进程占用", root)
            return
        self._handle = handle
        self.acquired = True

    def release(self) -> None:
        """释放锁。进程退出时内核也会释放，这里是给测试与优雅退出用的。"""
        if self._handle is None:
            return
        try:
            fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        self._handle.close()
        self._handle = None
        self.acquired = False

    def __del__(self) -> None:
        """对象被回收时关掉句柄。

        **这段兜底不能删** —— 句柄不关会在 GC 时触发
        `ResourceWarning: 未关闭的文件`，在 `-W error` 下直接变成测试失败
        （实测删掉后 `tests/test_web_service.py` 塌成 10 failed）。

        锁必须活到服务实例结束 —— 句柄提前关掉等于悄悄把锁释放了，
        让另一个实例以为自己是目录所有者。
        """
        handle = getattr(self, "_handle", None)
        if handle is None:
            return
        self._handle = None
        self.acquired = False
        try:
            handle.close()
        except Exception:  # 解释器退出期间关闭可能失败，忽略即可
            # 这里刻意不记日志：解释器退出期模块全局可能被拆掉，
            # 调用 logging 反而会在 __del__ 里抛出「Exception ignored」。
            pass
