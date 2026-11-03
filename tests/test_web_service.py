"""Web 服务层：协议查询、配置保存、生成调度与产物预览。"""

import json
import threading
import time

import pytest

from icsgen.spec.loader import ScenarioError
from icsgen.web.models import ConfigPayload, OperationInput
from icsgen.web.service import (
    AlreadyGenerated,
    MAX_COUNT_PER_OPERATION,
    MAX_TOTAL_COUNT,
    NotFound,
    WebError,
    GenerationService,
    _percent,
    artifact_detail,
    build_scenario,
    generation_detail,
    list_operations,
    list_protocols,
    save_config,
)
from icsgen.web.store import WebStore


def _payload(count=1, op="modbus.read_holding_registers"):
    return ConfigPayload(
        name="测试配置",
        protocol="modbus",
        transport={"kind": "tcp"},
        operations=[
            OperationInput(op=op, variant="normal", params={"start_addr": 0, "quantity": 3}, count=count)
        ],
    )


def _wait(generation_id, service, timeout=20.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        detail = generation_detail(service.store, service, generation_id)
        if detail["status"] != "running":
            return detail
        time.sleep(0.05)
    raise AssertionError("生成超时")


def test_list_protocols_reports_catalog_stats():
    protocols = list_protocols()
    assert protocols[0]["name"] == "modbus"
    assert protocols[0]["operation_count"] == 41
    assert protocols[0]["coverage_count"] == 192


def test_list_operations_exposes_params_schema():
    operations = list_operations("modbus")
    assert len(operations) == 41
    entry = next(o for o in operations if o["name"] == "modbus.read_holding_registers")
    assert entry["func_code"] == 3
    assert entry["variants"] == ["normal", "boundary", "exception"]
    assert entry["params"]["quantity"]["maximum"] == 125


def test_list_operations_unknown_protocol_raises():
    with pytest.raises(KeyError):
        list_operations("cip")


def test_save_config_records_selection(tmp_path):
    store = WebStore(tmp_path)
    record = save_config(store, _payload(count=5))
    assert record["id"].startswith("cfg_")
    assert record["operations"][0]["count"] == 5
    assert store.get_config(record["id"])["name"] == "测试配置"


def test_save_config_rejects_unknown_operation(tmp_path):
    store = WebStore(tmp_path)
    with pytest.raises(ScenarioError) as info:
        save_config(store, _payload(op="modbus.nope"))
    assert "不存在操作" in str(info.value)


def test_save_config_rejects_bad_param(tmp_path):
    store = WebStore(tmp_path)
    payload = ConfigPayload(
        name="坏参数",
        protocol="modbus",
        transport={"kind": "tcp"},
        operations=[OperationInput(op="modbus.read_holding_registers", params={"quantity": 9999})],
    )
    with pytest.raises(ScenarioError) as info:
        save_config(store, payload)
    assert "参数校验失败" in str(info.value)


def test_save_config_rejects_count_over_limit(tmp_path):
    store = WebStore(tmp_path)
    with pytest.raises(WebError, match="超过单操作上限"):
        save_config(store, _payload(count=MAX_COUNT_PER_OPERATION + 1))


def test_save_config_rejects_total_over_limit(tmp_path):
    store = WebStore(tmp_path)
    payload = ConfigPayload(
        name="太多",
        protocol="modbus",
        transport={"kind": "tcp"},
        operations=[
            OperationInput(op="modbus.read_holding_registers", count=MAX_COUNT_PER_OPERATION)
            for _ in range(MAX_TOTAL_COUNT // MAX_COUNT_PER_OPERATION + 1)
        ],
    )
    with pytest.raises(WebError, match="超过总量上限"):
        save_config(store, payload)


def test_percent_converts_two_phase_progress():
    """进度换算：构建阶段 0–85，写盘阶段 85，完成 100（spec §10.2）。"""
    assert _percent(0, 10, "building") == 0.0
    assert _percent(5, 10, "building") == 42.5
    assert _percent(10, 10, "building") == 85.0
    assert _percent(10, 10, "writing") == 85.0
    assert _percent(10, 10, "done") == 100.0
    assert _percent(0, 0, "building") == 0.0


def test_build_scenario_expands_count(tmp_path):
    scenario = build_scenario(
        {
            "name": "x",
            "transport": {"kind": "tcp"},
            "operations": [{"op": "modbus.read_holding_registers", "count": 3}],
        }
    )
    assert len(scenario.operations) == 3
    assert all(op.op == "modbus.read_holding_registers" for op in scenario.operations)


def test_generation_produces_artifacts(tmp_path):
    store = WebStore(tmp_path)
    service = GenerationService(store)
    config = save_config(store, _payload(count=3))
    started = service.start(config["id"])
    detail = _wait(started["generation_id"], service)
    assert detail["status"] == "succeeded"
    assert detail["artifact_count"] == 3
    assert len(detail["artifacts"]) == 3
    assert detail["percent"] == 100.0


def test_generation_cannot_run_twice_for_same_config(tmp_path):
    store = WebStore(tmp_path)
    service = GenerationService(store)
    config = save_config(store, _payload())
    started = service.start(config["id"])
    _wait(started["generation_id"], service)
    with pytest.raises(AlreadyGenerated):
        service.start(config["id"])


def test_generation_of_unknown_config_raises(tmp_path):
    service = GenerationService(WebStore(tmp_path))
    with pytest.raises(NotFound):
        service.start("cfg_nope")


def test_artifact_detail_decodes_request_and_response(tmp_path):
    store = WebStore(tmp_path)
    service = GenerationService(store)
    config = save_config(store, _payload())
    started = service.start(config["id"])
    detail = _wait(started["generation_id"], service)
    artifact_id = detail["artifacts"][0]["id"]
    info = artifact_detail(store, started["generation_id"], artifact_id)
    # MBAP 头：事务 id（首条交互为 0）+ 协议 id（恒为 0）
    assert info["request"]["hex"].startswith("00 00 00 00")
    assert info["response"] is not None
    assert info["request"]["view"]["fields"]


def test_artifact_detail_unknown_artifact_raises(tmp_path):
    store = WebStore(tmp_path)
    service = GenerationService(store)
    config = save_config(store, _payload())
    started = service.start(config["id"])
    _wait(started["generation_id"], service)
    with pytest.raises(NotFound):
        artifact_detail(store, started["generation_id"], "nope")


def test_startup_recovers_orphan_generations(tmp_path):
    """进程重启后，「有 started 无终态」的生成要补一条 failed（spec §10.3）。"""
    store = WebStore(tmp_path)
    store.append_event({
        "type": "generation_started", "generation_id": "gen_1",
        "config_id": "cfg_1", "config_name": "配置", "created_at": "t0",
        "output_dir": str(store.generation_dir("gen_1")),
    })
    GenerationService(store)  # 构造即触发启动恢复
    generation = store.list_generations()[0]
    assert generation["status"] == "failed"
    assert "重启" in generation["error"]


def test_save_config_rejects_unknown_protocol(tmp_path):
    """未注册协议要报 NotFound —— HTTP 层映射成 404（spec §12）。"""
    store = WebStore(tmp_path)
    payload = ConfigPayload(
        name="未知协议",
        protocol="cip",
        transport={"kind": "tcp"},
        operations=[OperationInput(op="modbus.read_holding_registers")],
    )
    with pytest.raises(NotFound, match="未注册协议"):
        save_config(store, payload)


def test_failed_generation_does_not_report_full_progress(tmp_path):
    """失败的生成不能显示 100% 进度（重启后没有内存任务，只能靠事件折叠出的状态）。"""
    store = WebStore(tmp_path)
    store.append_event({
        "type": "generation_started", "generation_id": "gen_1",
        "config_id": "cfg_1", "config_name": "配置", "created_at": "t0",
        "output_dir": str(store.generation_dir("gen_1")),
    })
    service = GenerationService(store)  # 触发孤儿恢复 → 标记为 failed
    detail = generation_detail(store, service, "gen_1")
    assert detail["status"] == "failed"
    assert detail["phase"] == "failed"
    assert detail["percent"] == 0.0


def test_concurrent_start_generates_config_only_once(tmp_path, monkeypatch):
    """并发发起同一个配置的生成，只能成功一次（spec §6.3 / §12 的 409）。"""

    def fake_build_dataset(scenario, adapter, root, name=None, on_progress=None):
        (root / "manifest.json").write_text(
            json.dumps({"artifacts": []}), encoding="utf-8"
        )
        if on_progress is not None:
            on_progress(1, 1)
        return root

    monkeypatch.setattr("icsgen.web.service.build_dataset", fake_build_dataset)
    store = WebStore(tmp_path)
    record = save_config(store, _payload(count=1))
    service = GenerationService(store)
    workers = 8
    barrier = threading.Barrier(workers)
    succeeded: list[str] = []
    rejected: list[str] = []

    def worker() -> None:
        barrier.wait()
        try:
            result = service.start(record["id"])
        except AlreadyGenerated as exc:
            rejected.append(str(exc))
        else:
            succeeded.append(result["generation_id"])

    threads = [threading.Thread(target=worker) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)

    assert len(succeeded) == 1
    assert len(rejected) == workers - 1
    started = [
        event
        for event in store.list_events()
        if event.get("type") == "generation_started"
    ]
    assert len(started) == 1


def test_failed_generation_reports_zero_percent(tmp_path):
    """失败的生成进度是 0 —— 不能按已完成的交互数报个半截进度。"""
    assert _percent(3, 10, "failed") == 0.0
    assert _percent(0, 0, "failed") == 0.0


def test_list_operations_does_not_expose_cached_params():
    """拿到的 params 是副本 —— 改它不能污染进程内缓存的 catalog（增量 1 的 lru_cache）。"""
    first = list_operations("modbus")
    first[0]["params"]["quantity"]["maximum"] = 999
    second = list_operations("modbus")
    assert second[0]["params"]["quantity"]["maximum"] != 999
