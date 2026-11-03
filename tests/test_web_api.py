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


def test_api_save_config_rejects_unknown_transport_field(client):
    """传输配置里的未知字段必须在保存时报出来（复审 F-2）。

    配置记录一旦落进只追加的账本就删不掉，而且「只能生成一次」的名额会被
    占掉 —— 用户没法重试这条配置。校验必须发生在写账本之前。
    """
    payload = {
        "name": "未知传输字段",
        "protocol": "modbus",
        "transport": {"kind": "tcp", "bogus_key": 1},
        "operations": [
            {
                "op": "modbus.read_holding_registers",
                "variant": "normal",
                "params": {"quantity": 3},
                "count": 1,
            }
        ],
    }
    response = client.post("/api/configs", json=payload)
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert "bogus_key" in detail
    # 报错要是中文提示，不是 JavaScript 风格的异常文本
    assert "未知字段" in detail
    # 账本里不能留下这条记录
    assert client.get("/api/configs").json() == []


def test_api_save_config_reports_count_limit_before_unknown_operation(client):
    """数量检查要排在操作存在性检查之前（复审 F-4）。

    数量是表单级的粗粒度检查（用户填错），操作名是下拉选出来的（不会错）。
    两条错误同时命中时先报数量 —— spec §12 没规定，但粗粒度优先更友好。
    """
    payload = {
        "name": "超限",
        "protocol": "modbus",
        "transport": {"kind": "tcp"},
        "operations": [
            {
                "op": "modbus.does_not_exist",
                "variant": "normal",
                "params": {},
                "count": 99999,
            }
        ],
    }
    response = client.post("/api/configs", json=payload)
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert "超过单操作上限" in detail
    assert "不存在操作" not in detail


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
    assert detail["status"] == "succeeded", detail
    response = client.get(f"/api/generations/{generation_id}/archive.zip")
    assert response.status_code == 200
    assert response.content[:2] == b"PK"


def test_archive_does_not_follow_symlinks(client, tmp_path):
    """归档不能跟随符号链接把生成目录外的内容打进去（复审 F-1）。

    同目录的下载路由做了 is_relative_to 校验会拒绝这类文件，两条同类路由
    的防护强度必须一致。
    """
    import zipfile

    payload = {
        "name": "符号链接配置",
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
    assert detail["status"] == "succeeded", detail

    # 目录外的一份「机密」文件，以及指向它的符号链接
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"SECRET BYTES")
    store = client.app.state.store
    base = store.generation_dir(generation_id)
    (base / "link.bin").symlink_to(outside)

    response = client.get(f"/api/generations/{generation_id}/archive.zip")
    assert response.status_code == 200
    archive_path = base.parent / f"{generation_id}.zip"
    with zipfile.ZipFile(archive_path) as bundle:
        names = bundle.namelist()
        assert f"{generation_id}/link.bin" not in names
        # 目录外的内容一个字节都不能进归档
        for name in names:
            assert b"SECRET BYTES" not in bundle.read(name)


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
