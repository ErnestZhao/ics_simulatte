"""页面渲染：工作台、记录页与生成详情。"""

import time
from pathlib import Path

from fastapi.testclient import TestClient

import icsgen.web
from icsgen.web.app import create_app


def _client(tmp_path):
    return TestClient(create_app(tmp_path))


def _generate(client, count=1):
    payload = {
        "name": "页面配置",
        "protocol": "modbus",
        "transport": {"kind": "tcp"},
        "operations": [
            {
                "op": "modbus.read_holding_registers",
                "variant": "normal",
                "params": {"start_addr": 0, "quantity": 3},
                "count": count,
            }
        ],
    }
    config_id = client.post("/api/configs", json=payload).json()["id"]
    generation_id = client.post("/api/generations", json={"config_id": config_id}).json()[
        "generation_id"
    ]
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        detail = client.get(f"/api/generations/{generation_id}").json()
        if detail["status"] != "running":
            break
        time.sleep(0.05)
    return generation_id


def test_workbench_lists_protocol_and_operations(tmp_path):
    client = _client(tmp_path)
    body = client.get("/").text
    assert "modbus" in body
    assert "41 个操作类型" in body
    assert "/static/app.js" in body


def test_workbench_transport_options_come_from_api(tmp_path):
    """传输选项来自 API 给出的传输种类，不能按协议名硬编码（spec §2.2）。"""
    client = _client(tmp_path)
    kinds = client.get("/api/protocols").json()[0]["transports"]
    assert kinds == ["tcp", "serial"]
    body = client.get("/").text
    assert 'data-transports="{}"'.format(",".join(kinds)) in body

    # 脚本必须从 API 给出的属性取传输种类，而不是按协议名硬编码 ——
    # 只断言页面属性的话，脚本里再写一遍协议名分支也照样能过。
    script = (Path(icsgen.web.__file__).parent / "static" / "app.js").read_text(
        encoding="utf-8"
    )
    assert "dataset.transports" in script
    # 脚本里不得出现协议名、传输种类名或十六进制字面量 —— 一律走 API 返回的
    # catalog（spec §7：新增协议时 Web 层不改代码）。这条是「纯 Python 约束下
    # 能给 JS 的最强防护」：JS 没有行为测试，只能钉住它不硬编码协议事实。
    for literal in ("modbus", "serial", "0x"):
        assert literal not in script, literal


def test_records_page_shows_saved_config(tmp_path):
    client = _client(tmp_path)
    payload = {
        "name": "记录里的配置",
        "protocol": "modbus",
        "transport": {"kind": "tcp"},
        "operations": [
            {
                "op": "modbus.read_holding_registers",
                "variant": "normal",
                "params": {"quantity": 3},
                "count": 4,
            }
        ],
    }
    client.post("/api/configs", json=payload)
    body = client.get("/records").text
    assert "记录里的配置" in body
    assert "不可修改" in body


def test_generation_page_shows_artifacts_and_download_links(tmp_path):
    client = _client(tmp_path)
    generation_id = _generate(client)
    body = client.get(f"/generations/{generation_id}").text
    assert "modbus.read_holding_registers" in body
    assert "archive.zip" in body
    assert ".bin" in body


def test_generation_page_encodes_artifact_id(tmp_path):
    """产物 id 里有 #，下载链接必须编码 —— 否则浏览器会在 # 处截断请求。"""
    client = _client(tmp_path)
    generation_id = _generate(client)
    body = client.get(f"/generations/{generation_id}").text
    assert "modbus.read_holding_registers%23001" in body
    assert "frames/modbus.read_holding_registers#001" not in body


def test_generation_page_shows_progress_while_running(tmp_path):
    """生成进行中时，页面要显示进度条。"""
    client = _client(tmp_path)
    store = client.app.state.store
    store.append_event(
        {
            "type": "generation_started",
            "generation_id": "gen_running",
            "config_id": "cfg_1",
            "config_name": "进行中的配置",
            "created_at": "t0",
            "output_dir": str(store.generation_dir("gen_running")),
        }
    )
    body = client.get("/generations/gen_running").text
    assert "progress" in body
