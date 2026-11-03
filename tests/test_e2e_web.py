"""端到端：网页路径与 CLI 路径产出同一份字节。"""

import io
import json
import time
import zipfile
from pathlib import Path
from urllib.parse import quote

from fastapi.testclient import TestClient

from icsgen.generator import build_dataset
from icsgen.protocols.modbus.adapter import load_modbus_adapter
from icsgen.spec.model import Operation, Scenario, Variant
from icsgen.web.app import create_app


def _wait(client, generation_id, timeout=20.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        detail = client.get(f"/api/generations/{generation_id}").json()
        if detail["status"] != "running":
            # 生成失败时要看到失败原因，而不是后面 KeyError: 'artifacts'
            assert detail["status"] == "succeeded", detail
            return detail
        time.sleep(0.05)
    raise AssertionError("生成超时")


def test_web_output_matches_cli_output_byte_for_byte(tmp_path):
    """同一组操作，网页路径与 CLI 路径生成的帧必须逐字节相同。"""
    payload = {
        "name": "一致性",
        "protocol": "modbus",
        "transport": {"kind": "tcp"},
        "operations": [
            {
                "op": "modbus.read_holding_registers",
                "variant": "normal",
                "params": {"start_addr": 0, "quantity": 3},
                "count": 2,
            },
            {
                "op": "modbus.write_multiple_registers",
                "variant": "exception",
                "params": {"start_addr": 100, "quantity": 2, "values": [1, 2]},
                "count": 1,
            },
        ],
    }
    client = TestClient(create_app(tmp_path / "web"))
    config_id = client.post("/api/configs", json=payload).json()["id"]
    generation_id = client.post("/api/generations", json={"config_id": config_id}).json()[
        "generation_id"
    ]
    detail = _wait(client, generation_id)

    scenario = Scenario(
        name="一致性",
        transport={"kind": "tcp"},
        operations=(
            Operation(op="modbus.read_holding_registers", params={"start_addr": 0, "quantity": 3}),
            Operation(op="modbus.read_holding_registers", params={"start_addr": 0, "quantity": 3}),
            Operation(
                op="modbus.write_multiple_registers",
                params={"start_addr": 100, "quantity": 2, "values": [1, 2]},
                variant=Variant.EXCEPTION,
            ),
        ),
    )
    cli_root = build_dataset(
        scenario, load_modbus_adapter(), tmp_path / "cli", name="一致性"
    )
    web_root = tmp_path / "web" / "generations" / generation_id

    web_manifest = json.loads((web_root / "manifest.json").read_text(encoding="utf-8"))
    cli_manifest = json.loads((cli_root / "manifest.json").read_text(encoding="utf-8"))
    assert [e["id"] for e in web_manifest["artifacts"]] == [
        e["id"] for e in cli_manifest["artifacts"]
    ]
    assert len(web_manifest["artifacts"]) == 3

    for entry in web_manifest["artifacts"]:
        rel = (
            Path(entry["tier"])
            / f"{entry['protocol']}_{entry['transport']}"
            / "frames"
            / f"{entry['id']}.bin"
        )
        assert (web_root / rel).read_bytes() == (cli_root / rel).read_bytes(), entry["id"]


def test_config_and_generation_records_are_immutable(tmp_path):
    """配置与生成记录没有删除/修改入口（验收指标 6）。"""
    client = TestClient(create_app(tmp_path / "web"))
    payload = {
        "name": "只读",
        "protocol": "modbus",
        "transport": {"kind": "tcp"},
        "operations": [
            {
                "op": "modbus.read_holding_registers",
                "variant": "normal",
                "params": {"start_addr": 0, "quantity": 3},
                "count": 1,
            }
        ],
    }
    config_id = client.post("/api/configs", json=payload).json()["id"]
    generation_id = client.post("/api/generations", json={"config_id": config_id}).json()[
        "generation_id"
    ]
    _wait(client, generation_id)

    for method in ("delete", "put", "patch"):
        for path in (f"/api/configs/{config_id}", f"/api/generations/{generation_id}"):
            response = client.request(method.upper(), path, json={"name": "改过了"})
            assert response.status_code in (404, 405), (method, path, response.status_code)


def test_generation_cannot_run_twice(tmp_path):
    """同一配置只能生成一次，二次生成返回 409（验收指标 6）。"""
    client = TestClient(create_app(tmp_path / "web"))
    payload = {
        "name": "只生成一次",
        "protocol": "modbus",
        "transport": {"kind": "tcp"},
        "operations": [
            {
                "op": "modbus.read_holding_registers",
                "variant": "normal",
                "params": {"start_addr": 0, "quantity": 3},
                "count": 1,
            }
        ],
    }
    config_id = client.post("/api/configs", json=payload).json()["id"]
    first = client.post("/api/generations", json={"config_id": config_id})
    assert first.status_code == 201
    _wait(client, first.json()["generation_id"])

    second = client.post("/api/generations", json={"config_id": config_id})
    assert second.status_code == 409


def test_generation_outputs_are_downloadable(tmp_path):
    """生成完成后可下载单帧文件与整包归档（验收指标 2）。"""
    client = TestClient(create_app(tmp_path / "web"))
    payload = {
        "name": "下载",
        "protocol": "modbus",
        "transport": {"kind": "tcp"},
        "operations": [
            {
                "op": "modbus.read_holding_registers",
                "variant": "normal",
                "params": {"start_addr": 0, "quantity": 3},
                "count": 1,
            }
        ],
    }
    config_id = client.post("/api/configs", json=payload).json()["id"]
    generation_id = client.post("/api/generations", json={"config_id": config_id}).json()[
        "generation_id"
    ]
    detail = _wait(client, generation_id)
    artifact = detail["artifacts"][0]

    rel = (
        f"{artifact['tier']}/{artifact['protocol']}_{artifact['transport']}"
        f"/frames/{quote(artifact['id'])}.bin"
    )
    single = client.get(f"/api/generations/{generation_id}/download/{rel}")
    assert single.status_code == 200
    # MBAP 头的事务 id 与协议 id（都是 0），以及功能码 0x03（读保持寄存器）。
    # 长度字段与单元 id 是生成细节（生成器里写死 0xFF），变了不该让这条用例红 ——
    # 与 Task 7 的下载用例同一把尺子。
    assert single.content[:4] == b"\x00\x00\x00\x00"
    assert single.content[7:8] == b"\x03"

    archive = client.get(f"/api/generations/{generation_id}/archive.zip")
    assert archive.status_code == 200
    with zipfile.ZipFile(io.BytesIO(archive.content)) as bundle:
        names = bundle.namelist()
    assert f"{generation_id}/manifest.json" in names
    assert any(name.endswith(".bin") for name in names)


def test_generation_artifact_count_matches_sum_of_counts(tmp_path):
    """交互数量生效：产物条数 == Σ count（验收指标 3）。"""
    client = TestClient(create_app(tmp_path / "web"))
    payload = {
        "name": "数量",
        "protocol": "modbus",
        "transport": {"kind": "tcp"},
        "operations": [
            {
                "op": "modbus.read_holding_registers",
                "variant": "normal",
                "params": {"start_addr": 0, "quantity": 3},
                "count": 3,
            },
            {
                "op": "modbus.read_coils",
                "variant": "normal",
                "params": {"start_addr": 0, "quantity": 8},
                "count": 2,
            },
        ],
    }
    config_id = client.post("/api/configs", json=payload).json()["id"]
    generation_id = client.post("/api/generations", json={"config_id": config_id}).json()[
        "generation_id"
    ]
    detail = _wait(client, generation_id)
    assert detail["status"] == "succeeded"
    assert len(detail["artifacts"]) == 5
