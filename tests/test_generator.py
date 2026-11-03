"""Modbus 适配器与生成流水线。"""

import json
from pathlib import Path

from icsgen.generator import build_dataset
from icsgen.protocols.modbus.adapter import load_modbus_adapter
from icsgen.spec.catalog import load_catalog
from icsgen.spec.loader import load_scenario
from icsgen.spec.model import Scenario, Tier, Variant

CATALOG_PATH = Path(__file__).resolve().parents[1] / "icsgen" / "protocols" / "modbus" / "catalog.yaml"


def _catalog():
    return load_catalog(CATALOG_PATH)


def test_adapter_exposes_catalog_entries():
    adapter = load_modbus_adapter()
    catalog = _catalog()
    assert adapter.name == "modbus"
    assert set(adapter.operations) == set(catalog.operations)


def test_build_request_frame_starts_with_mbap():
    from icsgen.protocols.base import BuildContext
    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    op = Operation(op="modbus.read_holding_registers", params={"start_addr": 0, "quantity": 3})
    frame = adapter.build(op, BuildContext(transaction_id=1, unit_id=0xFF))
    assert frame.payload[:7] == b"\x00\x01\x00\x00\x00\x06\xff"
    assert frame.payload[7] == 0x03
    assert frame.metadata["fc"] == 3


def test_build_exception_variant_marks_metadata():
    from icsgen.protocols.base import BuildContext
    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    op = Operation(
        op="modbus.read_holding_registers",
        params={"quantity": 3},
        variant=Variant.EXCEPTION,
    )
    frame = adapter.build(op, BuildContext())
    assert frame.metadata["is_exception"] is True
    assert frame.metadata["exception_code"] == 2


def test_build_rtu_variant_produces_crc():
    from icsgen.protocols.base import BuildContext
    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    op = Operation(op="modbus.read_holding_registers", params={"quantity": 3})
    frame = adapter.build(op, BuildContext(transport="rtu"))
    assert frame.metadata["transport"] == "rtu"
    from icsgen.protocols.modbus.framing import parse_rtu

    parsed = parse_rtu(frame.payload)
    assert parsed["pdu"][0] == 0x03


def test_build_dataset_writes_manifest_and_frames(tmp_path):
    adapter = load_modbus_adapter()
    scenario = Scenario(
        name="demo",
        transport={"kind": "tcp"},
        operations=(),
    )
    from icsgen.spec.model import Operation

    scenario = Scenario(
        name="demo",
        transport={"kind": "tcp"},
        operations=(
            Operation(op="modbus.read_holding_registers", params={"quantity": 3}),
            Operation(op="modbus.write_multiple_registers", params={"quantity": 2}),
        ),
    )
    root = build_dataset(scenario, adapter, tmp_path / "ds", name="demo")
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["counts"]["legit"] == 2
    assert len(manifest["artifacts"]) == 2
    assert (root / "legit" / "modbus_tcp" / "frames").is_dir()


def test_build_dataset_separates_abnormal_tier(tmp_path):
    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    scenario = Scenario(
        name="demo",
        transport={"kind": "tcp"},
        operations=(
            Operation(op="modbus.read_holding_registers", params={"quantity": 3}),
            Operation(
                op="modbus.read_holding_registers",
                params={"quantity": 3},
                variant=Variant.EXCEPTION,
            ),
        ),
    )
    root = build_dataset(scenario, adapter, tmp_path / "ds", name="demo")
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["counts"]["legit"] == 1
    assert manifest["counts"]["abnormal"] == 1
    assert (root / "abnormal" / "modbus_tcp" / "frames").is_dir()


def test_build_response_returns_normal_response():
    """正常变体的响应是 FC03 的正常响应：byte_count + 寄存器数据。"""
    from icsgen.protocols.base import BuildContext
    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    op = Operation(op="modbus.read_holding_registers", params={"start_addr": 0, "quantity": 3})
    frame = adapter.build_response(op, BuildContext(transaction_id=1, unit_id=0xFF))
    assert frame is not None
    assert frame.payload[:7] == b"\x00\x01\x00\x00\x00\x09\xff"
    assert frame.payload[7] == 0x03
    assert frame.payload[8] == 6


def test_build_response_returns_exception_response():
    """异常变体的响应是 FC|0x80 + 异常码。"""
    from icsgen.protocols.base import BuildContext
    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    op = Operation(
        op="modbus.read_holding_registers",
        params={"quantity": 3},
        variant=Variant.EXCEPTION,
    )
    frame = adapter.build_response(op, BuildContext(transaction_id=1, unit_id=0xFF))
    assert frame is not None
    assert frame.payload[7] == 0x83
    assert frame.payload[8] == 0x02


def test_malformed_variant_has_no_response():
    """畸形帧没有可解析的响应。"""
    from icsgen.protocols.base import BuildContext
    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    op = Operation(
        op="modbus.read_holding_registers",
        params={"quantity": 3},
        variant=Variant.MALFORMED,
    )
    assert adapter.build_response(op, BuildContext()) is None


def test_dataset_pairs_request_and_response(tmp_path):
    """一次操作在 pcap 里是连续的请求与响应两包。"""
    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    scenario = Scenario(
        name="demo",
        transport={"kind": "tcp"},
        operations=(Operation(op="modbus.read_holding_registers", params={"quantity": 3}),),
    )
    root = build_dataset(scenario, adapter, tmp_path / "ds", name="demo")
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    entry = manifest["artifacts"][0]
    assert entry["pcap_index"] == 0
    assert entry["pcap_resp_index"] == 1
    assert entry["resp_len"] > 0
    frames = root / "legit" / "modbus_tcp" / "frames"
    assert (frames / f"{entry['id']}.resp.bin").exists()
