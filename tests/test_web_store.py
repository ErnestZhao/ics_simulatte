"""Web 层的 append-only 账本。"""

import json
import threading

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
