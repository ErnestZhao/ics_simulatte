"""HTTP 层：JSON API 与页面路由。"""

from urllib.parse import quote

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from icsgen.web.app import _generation_base, create_app
from icsgen.web.store import WebStore


@pytest.fixture()
def client(tmp_path):
    return TestClient(create_app(tmp_path))


def test_api_protocols(client):
    response = client.get("/api/protocols")
    assert response.status_code == 200
    data = response.json()
    assert data[0]["name"] == "modbus"
    assert data[0]["operation_count"] == 41
    assert data[0]["coverage_count"] == 192


def test_api_operations(client):
    response = client.get("/api/protocols/modbus/operations")
    assert response.status_code == 200
    operations = response.json()
    assert len(operations) == 41
    entry = next(o for o in operations if o["name"] == "modbus.read_holding_registers")
    assert entry["params"]["quantity"]["default"] == 3


def test_api_operations_unknown_protocol(client):
    assert client.get("/api/protocols/cip/operations").status_code == 404


def test_api_save_and_list_configs(client):
    payload = {
        "name": "接口配置",
        "protocol": "modbus",
        "transport": {"kind": "tcp"},
        "operations": [
            {
                "op": "modbus.read_holding_registers",
                "variant": "normal",
                "params": {"start_addr": 0, "quantity": 3},
                "count": 2,
            }
        ],
    }
    response = client.post("/api/configs", json=payload)
    assert response.status_code == 201
    config_id = response.json()["id"]
    listing = client.get("/api/configs").json()
    assert any(item["id"] == config_id for item in listing)


def test_api_save_config_rejects_bad_param(client):
    payload = {
        "name": "坏参数",
        "protocol": "modbus",
        "transport": {"kind": "tcp"},
        "operations": [
            {
                "op": "modbus.read_holding_registers",
                "variant": "normal",
                "params": {"quantity": 9999},
                "count": 1,
            }
        ],
    }
    response = client.post("/api/configs", json=payload)
    assert response.status_code == 422
    assert "参数校验失败" in response.json()["detail"]


def test_api_generation_lifecycle(client):
    payload = {
        "name": "生成配置",
        "protocol": "modbus",
        "transport": {"kind": "tcp"},
        "operations": [
            {
                "op": "modbus.read_holding_registers",
                "variant": "normal",
                "params": {"start_addr": 0, "quantity": 3},
                "count": 2,
            }
        ],
    }
    config_id = client.post("/api/configs", json=payload).json()["id"]
    started = client.post("/api/generations", json={"config_id": config_id})
    assert started.status_code == 201
    generation_id = started.json()["generation_id"]

    import time

    deadline = time.monotonic() + 20
    detail = {}
    while time.monotonic() < deadline:
        detail = client.get(f"/api/generations/{generation_id}").json()
        if detail["status"] != "running":
            break
        time.sleep(0.05)
    assert detail["status"] == "succeeded"
    assert detail["artifact_count"] == 2
    assert len(detail["artifacts"]) == 2
    assert detail["percent"] == 100.0

    artifact_id = detail["artifacts"][0]["id"]
    # 产物 id 形如 "modbus.read_holding_registers#001" —— 里的 '#' 是 URL 的
    # fragment 分隔符，不编码的话 httpx 只会把 '#' 之前的内容发给服务端。
    preview = client.get(
        f"/api/generations/{generation_id}/artifacts/{quote(artifact_id, safe='')}"
    ).json()
    assert preview["request"]["hex"]
    assert preview["request"]["view"]["fields"]

    listing = client.get("/api/generations").json()
    assert any(item["id"] == generation_id for item in listing)


def test_api_generation_twice_returns_conflict(client):
    payload = {
        "name": "只能一次",
        "protocol": "modbus",
        "transport": {"kind": "tcp"},
        "operations": [
            {
                "op": "modbus.read_holding_registers",
                "variant": "normal",
                "params": {"quantity": 3},
                "count": 1,
            }
        ],
    }
    config_id = client.post("/api/configs", json=payload).json()["id"]
    assert client.post("/api/generations", json={"config_id": config_id}).status_code == 201
    conflict = client.post("/api/generations", json={"config_id": config_id})
    assert conflict.status_code == 409


def test_api_generation_unknown_config_returns_404(client):
    assert client.post("/api/generations", json={"config_id": "cfg_nope"}).status_code == 404


def test_api_has_no_delete_or_update_routes(client):
    """记录不可删改 —— 不存在任何删除或修改记录的路由。"""
    paths = {route.path for route in client.app.routes}
    for path in paths:
        assert "configs" not in path or path == "/api/configs"
    methods = {
        (route.path, method)
        for route in client.app.routes
        for method in getattr(route, "methods", set())
    }
    assert ("/api/configs", "DELETE") not in methods
    assert ("/api/configs", "PUT") not in methods
    assert ("/api/configs", "PATCH") not in methods
    assert ("/api/generations", "DELETE") not in methods


def test_api_download_returns_file(client):
    payload = {
        "name": "下载配置",
        "protocol": "modbus",
        "transport": {"kind": "tcp"},
        "operations": [
            {
                "op": "modbus.read_holding_registers",
                "variant": "normal",
                "params": {"quantity": 3},
                "count": 1,
            }
        ],
    }
    config_id = client.post("/api/configs", json=payload).json()["id"]
    generation_id = client.post("/api/generations", json={"config_id": config_id}).json()[
        "generation_id"
    ]
    import time

    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        detail = client.get(f"/api/generations/{generation_id}").json()
        if detail["status"] != "running":
            break
        time.sleep(0.05)
    artifact = detail["artifacts"][0]
    # 帧文件名就是产物 id（Task 4 的 id 形如 "…#001"），'#' 必须编码。
    file_path = (
        f"{artifact['tier']}/{artifact['protocol']}_{artifact['transport']}/frames/"
        f"{artifact['id']}.bin"
    )
    response = client.get(
        f"/api/generations/{generation_id}/download/{quote(file_path, safe='/')}"
    )
    assert response.status_code == 200
    # MBAP 头：事务 id（首条交互是 0）+ 协议 id（0）—— 简报里写的
    # b"\x00\x01" 永远不会成立，事务 id 取的是 index % 0x10000。
    assert response.content.startswith(b"\x00\x00\x00\x00")


def test_api_archive_downloads_zip(client):
    payload = {
        "name": "打包配置",
        "protocol": "modbus",
        "transport": {"kind": "tcp"},
        "operations": [
            {
                "op": "modbus.read_holding_registers",
                "variant": "normal",
                "params": {"quantity": 3},
                "count": 1,
            }
        ],
    }
    config_id = client.post("/api/configs", json=payload).json()["id"]
    generation_id = client.post("/api/generations", json={"config_id": config_id}).json()[
        "generation_id"
    ]
    import time

    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        detail = client.get(f"/api/generations/{generation_id}").json()
        if detail["status"] != "running":
            break
        time.sleep(0.05)
    response = client.get(f"/api/generations/{generation_id}/archive.zip")
    assert response.status_code == 200
    assert response.content[:2] == b"PK"


def test_pages_render(client):
    assert client.get("/").status_code == 200
    assert client.get("/records").status_code == 200


def test_api_rejects_generation_id_traversal(client):
    """越界的生成 id 一律 404 —— 否则账本本身都能被下载走（spec §12）。"""
    assert client.get("/api/generations/%2e%2e/download/events.jsonl").status_code == 404
    assert client.get("/api/generations/%2e%2e/archive.zip").status_code == 404


def test_generation_base_rejects_unsafe_ids(tmp_path):
    """生成目录只能落在账本的 generations 目录里。"""
    store = WebStore(tmp_path)
    for generation_id in ["..", "../../etc", "a/b", "gen_x/../../..", ""]:
        with pytest.raises(HTTPException) as info:
            _generation_base(store, generation_id)
        assert info.value.status_code == 404
