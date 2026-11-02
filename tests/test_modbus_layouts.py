"""Modbus 字段布局与操作目录。"""

from pathlib import Path

from icsgen.codec.decoder import decode
from icsgen.codec.encoder import encode
from icsgen.protocols.modbus.layouts import (
    DIAGNOSTIC_SUBFUNCTIONS,
    LAYOUTS,
    get_layout,
)
from icsgen.spec.catalog import load_catalog

CATALOG_PATH = Path(__file__).resolve().parents[1] / "icsgen" / "protocols" / "modbus" / "catalog.yaml"


def test_all_layouts_have_request_and_response():
    for name, layout in LAYOUTS.items():
        assert isinstance(layout.request, tuple), name
        assert isinstance(layout.response, tuple), name


def test_get_layout_unknown_raises():
    try:
        get_layout("fc99")
    except KeyError as exc:
        assert "fc99" in str(exc)
    else:
        raise AssertionError("应当抛出 KeyError")


def test_fc03_round_trip():
    layout = get_layout("fc03")
    raw = encode(layout.request, {"start_addr": 0, "quantity": 3})
    assert raw == b"\x00\x00\x00\x03"
    assert decode(layout.request, raw) == {"start_addr": 0, "quantity": 3}


def test_fc10_byte_count_is_two_times_value_count():
    """FC10 的 byte_count 等于寄存器数量的两倍。"""
    layout = get_layout("fc10")
    raw = encode(
        layout.request,
        {"start_addr": 100, "quantity": 2, "values": [0xDEAD, 0xBEEF]},
    )
    assert raw == b"\x00\x64\x00\x02\x04\xde\xad\xbe\xef"


def test_fc0f_values_are_bytes():
    layout = get_layout("fc0f")
    raw = encode(
        layout.request,
        {"start_addr": 0, "quantity": 8, "values": b"\xff"},
    )
    assert raw == b"\x00\x00\x00\x08\x01\xff"


def test_fc08_carries_sub_function():
    layout = get_layout("fc08")
    raw = encode(layout.request, {"sub_function": 0x0004, "data": 0x0000})
    assert raw == b"\x00\x04\x00\x00"


def test_diagnostic_subfunction_table_has_twenty_one_entries():
    assert len(DIAGNOSTIC_SUBFUNCTIONS) == 21
    assert DIAGNOSTIC_SUBFUNCTIONS[0x0004] == "Force Listen Only Mode"
    assert DIAGNOSTIC_SUBFUNCTIONS[0x0015] == "Get Clear Modbus Plus Request"


def test_catalog_declares_operation_types_and_transports():
    catalog = load_catalog(CATALOG_PATH)
    assert catalog.protocol == "modbus"
    assert catalog.count() == 41
    assert catalog.transports == ("tcp", "rtu")


def test_catalog_coverage_count_meets_floor():
    """覆盖条目数 = Σ(每个操作类型的变体数) × 传输数，是 §15 丰富度指标的度量口径。"""
    catalog = load_catalog(CATALOG_PATH)
    assert catalog.coverage_count() >= 90, f"覆盖条目数 {catalog.coverage_count()} 低于下限 90"


def test_every_catalog_entry_references_existing_layout():
    catalog = load_catalog(CATALOG_PATH)
    for name in catalog.operations:
        entry = catalog.get(name)
        assert entry.layout in LAYOUTS, f"{name} 引用了不存在的布局 {entry.layout}"


def test_diagnostic_operations_cover_all_subfunctions():
    """21 个诊断子功能各自是一个操作类型。"""
    catalog = load_catalog(CATALOG_PATH)
    diag = [n for n in catalog.operations if n.startswith("modbus.diagnostics.")]
    assert len(diag) == 21


def test_all_entries_declare_normal_variant():
    catalog = load_catalog(CATALOG_PATH)
    for name, entry in catalog.operations.items():
        assert "normal" in entry.variants, f"{name} 未声明 normal 变体"
