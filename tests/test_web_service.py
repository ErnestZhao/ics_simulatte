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


def test_save_config_rejects_unknown_transport_field(tmp_path):
    """传输配置里的未知字段要在保存时就报错（复审 F-2）。

    报错要发生在写账本之前：配置记录一旦落进只追加的账本就删不掉，
    而且「只能生成一次」的名额会被占掉 —— 用户将无法重试这条配置。
    """
    store = WebStore(tmp_path)
    payload = _payload()
    payload.transport = {"kind": "tcp", "bogus_key": 1}
    with pytest.raises(WebError) as info:
        save_config(store, payload)
    assert "bogus_key" in str(info.value)
    assert "未知字段" in str(info.value)
    # 账本里不能留下这条记录
    assert store.list_configs() == []


def test_save_config_checks_count_before_unknown_operation(tmp_path):
    """数量检查要排在操作存在性检查之前（复审 F-4）。

    数量是表单级的粗粒度检查（用户填错），操作名是下拉选出来的（不会错）。
    """
    store = WebStore(tmp_path)
    with pytest.raises(WebError) as info:
        save_config(store, _payload(count=99999, op="modbus.does_not_exist"))
    message = str(info.value)
    assert "超过单操作上限" in message
    assert "不存在操作" not in message


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


def test_second_instance_does_not_mark_live_generation_failed(tmp_path):
    """另一个服务进程在跑时，本进程不能把它的在跑任务判成孤儿（spec §10.3）。

    flock 的锁按 open file description 算 —— 同一进程里第二次 open 同一个
    锁文件会拿到另一个 description，因此第二个实例同样拿不到锁。这个场景
    在单进程内就能复现，不需要真的起子进程。
    """
    first = GenerationService(WebStore(tmp_path))   # 第一个实例：拿到锁
    store = WebStore(tmp_path)
    store.append_event({
        "type": "generation_started", "generation_id": "gen_live",
        "config_id": "cfg_1", "config_name": "配置", "created_at": "t0",
        "output_dir": str(store.generation_dir("gen_live")),
    })
    second = GenerationService(store)                # 第二个实例：拿不到锁
    assert first.owner_lock.acquired is True
    assert second.owner_lock.acquired is False
    generation = store.list_generations()[0]
    assert generation["status"] == "running"
    assert generation["error"] is None


def test_orphan_recovery_runs_after_owner_releases_the_lock(tmp_path):
    """所有者退出（释放锁）后，新实例要执行启动孤儿恢复（spec §10.3）。"""
    store = WebStore(tmp_path)
    owner = GenerationService(store)
    store.append_event({
        "type": "generation_started", "generation_id": "gen_1",
        "config_id": "cfg_1", "config_name": "配置", "created_at": "t0",
        "output_dir": str(store.generation_dir("gen_1")),
    })
    owner.owner_lock.release()          # 模拟原来的进程退出了
    GenerationService(store)            # 新实例拿到锁 → 执行孤儿恢复
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
    """并发发起同一个配置的生成，只能成功一次（spec §6.3 / §12 的 409）。

    把「读守卫」这一拍拉长，让竞态必现 —— 不靠线程调度的运气。
    """
    original_lookup = WebStore.generation_for_config

    def slow_lookup(self, config_id):
        # 拉长「读到 None」与「追加 started 事件」之间的窗口：
        # 没有互斥时，8 个线程必然同时读到 None；加了锁则被串行化，
        # 只有第一个读到 None，其余读到已存在的生成。
        #
        # sleep 必须放在「读完」之后而不是之前：放在之前只是把 8 个线程的
        # 读操作对齐到同一时刻，可读→追加之间仍是微秒级窗口 —— 某个线程
        # 若被调度推迟到别人追加之后才去读，就会看到已存在的生成而误判成
        # 「守卫生效」，竞态被漏过去（实测约 3 成漏报）。
        # 放在读完之后，8 个线程必然全部先读到 None，再各自进入追加，
        # 窗口大到必然被撞上（实测 40/40 检出）。
        result = original_lookup(self, config_id)
        time.sleep(0.05)
        return result

    monkeypatch.setattr(WebStore, "generation_for_config", slow_lookup)

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


def test_success_event_is_appended_after_phase_is_done(tmp_path, monkeypatch):
    """账本追加 succeeded 事件的那一刻，内存里的 phase 必须是 done。

    否则页面会显示「状态成功、进度 85%」—— 写盘其实早就完成了。
    """
    store = WebStore(tmp_path)
    service = GenerationService(store)
    config = save_config(store, _payload(count=1))
    observed: list[str] = []
    original_append = WebStore.append_event

    def spy(self, event):
        if event.get("type") == "generation_succeeded":
            observed.append(service.state(event["generation_id"])["phase"])
        return original_append(self, event)

    monkeypatch.setattr(WebStore, "append_event", spy)
    started = service.start(config["id"])
    _wait(started["generation_id"], service)
    assert observed == ["done"]


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


def test_save_config_rejects_invalid_session_mode(tmp_path):
    """非法会话形态要在写账本之前报错 —— 记录落盘就删不掉了。"""
    store = WebStore(tmp_path)
    payload = ConfigPayload(
        name="非法形态",
        transport={"kind": "tcp", "session": "bogus"},
        operations=[OperationInput(op="modbus.read_holding_registers", count=1)],
    )
    with pytest.raises(WebError) as excinfo:
        save_config(store, payload)
    assert "bogus" in str(excinfo.value)
    assert store.list_configs() == []
