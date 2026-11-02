"""Modbus 字段布局与操作目录。"""

from pathlib import Path

import pytest

from icsgen.codec.decoder import decode
from icsgen.codec.encoder import encode
from icsgen.protocols.modbus.layouts import (
    DIAGNOSTIC_SUBFUNCTIONS,
    LAYOUTS,
    get_layout,
)
from icsgen.spec.catalog import load_catalog

CATALOG_PATH = Path(__file__).resolve().parents[1] / "icsgen" / "protocols" / "modbus" / "catalog.yaml"

#: catalog 中允许出现的全部变体
KNOWN_VARIANTS = {"normal", "boundary", "exception", "illegal_fc", "malformed"}


def test_all_layouts_have_request_and_response():
    for name, layout in LAYOUTS.items():
        assert isinstance(layout.request, tuple), name
        assert isinstance(layout.response, tuple), name


def test_get_layout_unknown_raises():
    with pytest.raises(KeyError, match="fc99"):
        get_layout("fc99")


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


def test_fc16_mask_write_carries_three_fields():
    """FC16 掩码写寄存器 = 起始地址 + 与掩码 + 或掩码。"""
    layout = get_layout("fc16")
    raw = encode(layout.request, {"start_addr": 1, "and_mask": 0xFF00, "or_mask": 0x00FF})
    assert raw == b"\x00\x01\xff\x00\x00\xff"
    assert decode(layout.request, raw) == {
        "start_addr": 1,
        "and_mask": 0xFF00,
        "or_mask": 0x00FF,
    }


def test_fc18_response_matches_spec():
    """FC18 响应 = byte_count(2 + 2×元素数) + fifo_count(元素数) + FIFO 数据。"""
    layout = get_layout("fc18")
    raw = encode(layout.response, {"fifo_values": [1, 2, 3]})
    assert raw == b"\x00\x08\x00\x03\x00\x01\x00\x02\x00\x03"
    assert decode(layout.response, raw) == {
        "byte_count": 8,
        "fifo_count": 3,
        "fifo_values": [1, 2, 3],
    }


def test_fc14_request_matches_spec():
    """FC14 读文件记录请求 = byte_count(7) + 引用类型 + 文件号 + 记录号 + 记录长度。"""
    layout = get_layout("fc14")
    raw = encode(
        layout.request,
        {"reference_type": 6, "file_number": 4, "record_number": 0, "record_length": 1},
    )
    assert raw == b"\x07\x06\x00\x04\x00\x00\x00\x01"


def test_fc14_response_length_fields():
    """FC14 响应的 byte_count = 数据长度 + 2，file_response_length = 数据长度 + 1。"""
    layout = get_layout("fc14")
    raw = encode(layout.response, {"record_data": b"\x00\x01\x00\x02"})
    assert raw == b"\x06\x05\x06\x00\x01\x00\x02"
    assert decode(layout.response, raw) == {
        "byte_count": 6,
        "file_response_length": 5,
        "reference_type": 6,
        "record_data": b"\x00\x01\x00\x02",
    }


def test_fc15_request_length_fields():
    """FC15 写文件记录：byte_count = 数据长度 + 7，record_length = 寄存器数。"""
    layout = get_layout("fc15")
    raw = encode(layout.request, {"record_data": b"\x00\x01\x00\x02"})
    assert raw == b"\x0b\x06\x00\x00\x00\x00\x00\x02\x00\x01\x00\x02"


def test_fc15_decodes_record_data():
    """FC15 记录长度以寄存器计，字节数是它的两倍。"""
    layout = get_layout("fc15")
    raw = b"\x0b\x06\x00\x00\x00\x00\x00\x02\x00\x01\x00\x02"
    assert decode(layout.request, raw) == {
        "byte_count": 11,
        "reference_type": 6,
        "file_number": 0,
        "record_number": 0,
        "record_length": 2,
        "record_data": b"\x00\x01\x00\x02",
    }


def test_fc11_report_slave_id_length():
    """FC11 响应 = byte_count(标识长度 + 1) + 标识 + 运行指示状态。"""
    layout = get_layout("fc11")
    raw = encode(layout.response, {"slave_id": b"PLC-1"})
    assert raw == b"\x06PLC-1\xff"
    assert decode(layout.response, raw) == {
        "byte_count": 6,
        "slave_id": b"PLC-1",
        "run_indicator_status": 0xFF,
    }


def test_fc0c_event_log_count_is_element_count():
    """FC0C 的 event_log_count 是事件条数，不是字节数。"""
    layout = get_layout("fc0c")
    raw = encode(layout.response, {"log": [0x0001, 0x0002]})
    assert raw == b"\x00\x00\x00\x00\x00\x00\x02\x00\x01\x00\x02"
    assert decode(layout.response, raw) == {
        "status": 0,
        "event_count": 0,
        "message_count": 0,
        "event_log_count": 2,
        "log": [1, 2],
    }


def test_fc17_request_layout():
    """FC17 请求的 write_byte_count = 写入寄存器数 × 2。"""
    layout = get_layout("fc17")
    raw = encode(
        layout.request,
        {
            "read_addr": 0,
            "read_quantity": 2,
            "write_addr": 10,
            "write_quantity": 1,
            "write_values": [0x1234],
        },
    )
    assert raw == b"\x00\x00\x00\x02\x00\x0a\x00\x01\x02\x12\x34"


def test_fc17_response_layout():
    """FC17 响应与 FC03 同构：byte_count + 寄存器数组。"""
    layout = get_layout("fc17")
    raw = encode(layout.response, {"values": [1, 2]})
    assert raw == b"\x04\x00\x01\x00\x02"


def test_fc2b_response_carries_single_object():
    """FC2B 响应带一个对象：对象长度 + 对象值。"""
    layout = get_layout("fc2b")
    raw = encode(layout.response, {"object_value": b"\x01\x02"})
    assert raw == b"\x0e\x01\x83\x00\x00\x01\x00\x02\x01\x02"
    assert decode(layout.response, raw)["object_value"] == b"\x01\x02"


def test_diagnostic_subfunction_table_has_twenty_one_entries():
    assert len(DIAGNOSTIC_SUBFUNCTIONS) == 21
    assert DIAGNOSTIC_SUBFUNCTIONS[0x0004] == "Force Listen Only Mode"
    assert DIAGNOSTIC_SUBFUNCTIONS[0x0015] == "Get Clear Modbus Plus Request"


def test_catalog_declares_operation_types_and_transports():
    catalog = load_catalog(CATALOG_PATH)
    assert catalog.protocol == "modbus"
    assert catalog.count() == 41
    assert catalog.transports == ("tcp", "rtu")


def test_catalog_declares_ninety_six_variants():
    """catalog 声明的 (操作类型, 变体) 组合共 96 个。"""
    catalog = load_catalog(CATALOG_PATH)
    total = sum(len(entry.variants) for entry in catalog.operations.values())
    assert total == 96


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
    """21 个诊断子功能各自是一个操作类型，且子功能码与诊断表一致。"""
    catalog = load_catalog(CATALOG_PATH)
    diag = [n for n in catalog.operations if n.startswith("modbus.diagnostics.")]
    assert len(diag) == 21
    declared = {
        catalog.get(name).params["sub_function"]["default"] for name in diag
    }
    assert declared == set(DIAGNOSTIC_SUBFUNCTIONS)


def test_every_catalog_entry_declares_known_variants():
    catalog = load_catalog(CATALOG_PATH)
    for name, entry in catalog.operations.items():
        assert entry.variants, f"{name} 未声明任何变体"
        for variant in entry.variants:
            assert variant in KNOWN_VARIANTS, f"{name} 声明了未知变体 {variant!r}"


def test_catalog_covers_all_variant_kinds():
    """normal/boundary/exception/illegal_fc 都由 catalog 声明；malformed 只由变异引擎产生。"""
    catalog = load_catalog(CATALOG_PATH)
    kinds = {v for entry in catalog.operations.values() for v in entry.variants}
    assert kinds == {"normal", "boundary", "exception", "illegal_fc"}


def test_illegal_function_code_entry_declares_abnormal_variants():
    """非法功能码是协议级异常，只能用 abnormal 层的变体。"""
    catalog = load_catalog(CATALOG_PATH)
    entry = catalog.get("modbus.illegal_function_code")
    assert entry.func_code == 99
    assert set(entry.variants) == {"illegal_fc", "exception"}
