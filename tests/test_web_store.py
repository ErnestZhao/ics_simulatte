"""Web 层的 append-only 账本。"""

import fcntl
import json
import logging
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

from icsgen.web.store import Ledger, WebStore


def test_ledger_appends_and_reads_back(tmp_path):
    ledger = Ledger(tmp_path / "records.jsonl")
    ledger.append({"id": "a"})
    ledger.append({"id": "b"})
    assert [record["id"] for record in ledger.read_all()] == ["a", "b"]


def test_ledger_never_modifies_existing_lines(tmp_path):
    path = tmp_path / "records.jsonl"
    ledger = Ledger(path)
    ledger.append({"id": "a", "value": 1})
    first = path.read_text(encoding="utf-8")
    ledger.append({"id": "b", "value": 2})
    assert path.read_text(encoding="utf-8").startswith(first)


def test_ledger_skips_corrupted_lines(tmp_path):
    path = tmp_path / "records.jsonl"
    path.write_text('{"id": "a"}\n\n{坏掉的行\n{"id": "b"}\n', encoding="utf-8")
    assert [record["id"] for record in Ledger(path).read_all()] == ["a", "b"]


def test_ledger_read_all_on_missing_file(tmp_path):
    assert Ledger(tmp_path / "nope.jsonl").read_all() == []


def test_ledger_concurrent_appends_do_not_interleave(tmp_path):
    """并发追加不能互相交错 —— 每一行都得是完整的一条 JSON（spec §13.1）。"""
    ledger = Ledger(tmp_path / "records.jsonl")
    thread_count, per_thread = 4, 20

    def worker(index: int) -> None:
        for step in range(per_thread):
            ledger.append({"thread": index, "step": step})

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(thread_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    records = ledger.read_all()
    assert len(records) == thread_count * per_thread
    assert {(r["thread"], r["step"]) for r in records} == {
        (i, s) for i in range(thread_count) for s in range(per_thread)
    }


def test_store_saves_and_fetches_config(tmp_path):
    store = WebStore(tmp_path)
    record = store.save_config({"id": "cfg_1", "name": "配置"})
    assert record["id"] == "cfg_1"
    assert store.get_config("cfg_1")["name"] == "配置"
    assert store.get_config("cfg_missing") is None


def test_store_lists_generations_from_events(tmp_path):
    store = WebStore(tmp_path)
    store.append_event({
        "type": "generation_started", "generation_id": "gen_1",
        "config_id": "cfg_1", "config_name": "配置", "created_at": "t0",
    })
    store.append_event({
        "type": "generation_succeeded", "generation_id": "gen_1",
        "artifact_count": 3, "packet_count": 6, "duration_ms": 12,
    })
    generations = store.list_generations()
    assert len(generations) == 1
    assert generations[0]["status"] == "succeeded"
    assert generations[0]["artifact_count"] == 3


def test_store_marks_running_generation(tmp_path):
    store = WebStore(tmp_path)
    store.append_event({
        "type": "generation_started", "generation_id": "gen_1",
        "config_id": "cfg_1", "config_name": "配置", "created_at": "t0",
    })
    assert store.list_generations()[0]["status"] == "running"


def test_store_finds_generation_for_config(tmp_path):
    store = WebStore(tmp_path)
    store.append_event({
        "type": "generation_started", "generation_id": "gen_1",
        "config_id": "cfg_1", "config_name": "配置", "created_at": "t0",
    })
    assert store.generation_for_config("cfg_1") == "gen_1"
    assert store.generation_for_config("cfg_other") is None
    assert store.generations_by_config() == {"cfg_1": "gen_1"}


def test_store_generation_dir_is_under_root(tmp_path):
    store = WebStore(tmp_path)
    assert store.generation_dir("gen_1") == tmp_path / "generations" / "gen_1"


def test_ledger_skips_non_object_lines(tmp_path):
    """不是 JSON 对象的行不是记录，跳过 —— 单行损坏不能让页面 500。"""
    path = tmp_path / "records.jsonl"
    path.write_text('{"id": "a"}\n[1, 2, 3]\n"不是记录"\n42\nnull\n{"id": "b"}\n', encoding="utf-8")
    assert [record["id"] for record in Ledger(path).read_all()] == ["a", "b"]


def test_generation_for_config_returns_latest(tmp_path):
    """同一配置多次发起时，两个方法必须指向同一个（最近一次）生成。"""
    store = WebStore(tmp_path)
    for generation_id in ("gen_1", "gen_2"):
        store.append_event({
            "type": "generation_started", "generation_id": generation_id,
            "config_id": "cfg_1", "config_name": "配置", "created_at": "t0",
        })
    assert store.generation_for_config("cfg_1") == "gen_2"
    assert store.generations_by_config() == {"cfg_1": "gen_2"}


def test_ledger_survives_invalid_utf8_bytes(tmp_path):
    """非法字节只毁掉那一行，其余记录仍要读得出来（spec §13.2）。"""
    path = tmp_path / "records.jsonl"
    path.write_bytes(b'{"id": "a"}\n\xff{"id": "b"}\n{"id": "c"}\n')
    assert [record["id"] for record in Ledger(path).read_all()] == ["a", "c"]


def test_ledger_skips_line_with_invalid_utf8_inside_value(tmp_path, caplog):
    """坏字节落在字段值里时，整行作废并告警，不能带着替换字符混进记录。"""
    path = tmp_path / "records.jsonl"
    path.write_bytes(b'{"id": "a"}\n{"id": "b", "name": "va\xfflue"}\n{"id": "c"}\n')
    with caplog.at_level(logging.WARNING, logger="icsgen.web.store"):
        records = Ledger(path).read_all()
    assert [record["id"] for record in records] == ["a", "c"]
    assert any("UTF-8" in message for message in caplog.messages)


def test_ledger_reads_leading_bom(tmp_path):
    """带 BOM 的文件不该丢掉首行记录。"""
    path = tmp_path / "records.jsonl"
    path.write_bytes(b'\xef\xbb\xbf{"id": "a"}\n{"id": "b"}\n')
    assert [record["id"] for record in Ledger(path).read_all()] == ["a", "b"]


def test_ledger_cross_process_appends_do_not_interleave(tmp_path):
    """多个进程同时追加同一账本，行不能交错（spec §14）。

    守的是「并发追加不交错」这条契约，不是 flock 本身 ——
    O_APPEND + 单次 write() 在本地文件系统上本来就原子，flock 是额外保险，
    由另一条用例单独钉住。
    """
    path = tmp_path / "records.jsonl"
    workers, per_worker = 4, 25
    code = (
        "import sys\n"
        "from pathlib import Path\n"
        "from icsgen.web.store import Ledger\n"
        "ledger = Ledger(Path(sys.argv[1]))\n"
        "index = int(sys.argv[2])\n"
        "for step in range(int(sys.argv[3])):\n"
        "    ledger.append({'worker': index, 'step': step})\n"
    )
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])}
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", code, str(path), str(index), str(per_worker)],
            env=env,
        )
        for index in range(workers)
    ]
    for proc in procs:
        assert proc.wait() == 0
    records = Ledger(path).read_all()
    assert len(records) == workers * per_worker
    assert {(r["worker"], r["step"]) for r in records} == {
        (i, s) for i in range(workers) for s in range(per_worker)
    }


def test_ledger_append_takes_an_exclusive_file_lock(tmp_path):
    """追加必须真的拿文件锁：别的进程持锁时追加要被挡住。

    跨进程用例只保证「行不交错」，而 O_APPEND 在本地文件系统上本身就够用，
    拿掉 flock 那个用例依然全绿 —— 这一条直接把 flock 的存在钉住。
    """
    path = tmp_path / "records.jsonl"
    path.touch()
    code = (
        "import sys\n"
        "from pathlib import Path\n"
        "from icsgen.web.store import Ledger\n"
        "Ledger(Path(sys.argv[1])).append({'worker': 1, 'step': 0})\n"
    )
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])}
    with path.open("a", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            proc = subprocess.Popen(
                [sys.executable, "-c", code, str(path)], env=env
            )
            try:
                # 子进程起动约 60ms 就走到 flock；等 1.5s 足够让「没拿锁」暴露出来
                time.sleep(1.5)
                assert proc.poll() is None, "追加没有等其他进程持有的文件锁"
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            assert proc.wait(timeout=30) == 0
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    assert [record["worker"] for record in Ledger(path).read_all()] == [1]


def test_ledger_warns_on_corrupted_line(tmp_path, caplog):
    """损坏行要告警，不能静默跳过（spec §13.2）。"""
    path = tmp_path / "records.jsonl"
    path.write_text('{"id": "a"}\n{坏掉的行\n{"id": "b"}\n', encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="icsgen.web.store"):
        records = Ledger(path).read_all()
    assert [record["id"] for record in records] == ["a", "b"]
    assert any("坏掉的行" in message or "不是合法 JSON" in message
               for message in caplog.messages)


def test_store_get_config_takes_latest_same_id(tmp_path):
    """同 id 多次保存时，取最后一次保存的那条。"""
    store = WebStore(tmp_path)
    store.save_config({"id": "cfg_1", "name": "第一版"})
    store.save_config({"id": "cfg_1", "name": "第二版"})
    assert store.get_config("cfg_1")["name"] == "第二版"
    assert len(store.list_configs()) == 2


def test_store_ignores_events_with_invalid_generation_id(tmp_path):
    """generation_id / config_id 不是非空字符串的事件不算一次生成。"""
    store = WebStore(tmp_path)
    store.append_event({
        "type": "generation_started", "generation_id": 42,
        "config_id": "cfg_1", "config_name": "配置", "created_at": "t0",
    })
    store.append_event({
        "type": "generation_started", "generation_id": "",
        "config_id": "cfg_2", "config_name": "配置", "created_at": "t0",
    })
    assert store.list_generations() == []
    assert store.generation_for_config("cfg_1") is None
    assert store.generations_by_config() == {}


def test_ledger_keeps_records_with_unicode_line_separators(tmp_path):
    """按字节切行：U+2028 之类的字符不算行分隔符，记录不能被劈成两半丢掉。

    str.splitlines() 会在 U+2028/U+2029/U+0085 处断行 —— 配置名由用户输入，
    含这类字符的记录会被整条静默丢弃。
    """
    name = "第一行\u2028第二行"
    path = tmp_path / "records.jsonl"
    path.write_text(
        json.dumps({"id": "a", "name": name}, ensure_ascii=False)
        + "\n"
        + json.dumps({"id": "b"}, ensure_ascii=False)
        + "\n",
        encoding="utf-8",
    )
    records = Ledger(path).read_all()
    assert [record["id"] for record in records] == ["a", "b"]
    assert records[0]["name"] == name
