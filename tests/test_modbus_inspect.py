"""Modbus 帧的协议级解析。"""

from icsgen.protocols.base import BuildContext
from icsgen.protocols.modbus.adapter import load_modbus_adapter
from icsgen.protocols.modbus.framing import build_mbap, build_pdu, build_rtu
from icsgen.protocols.modbus.inspect import inspect_frame
from icsgen.protocols.modbus.layouts import get_layout
from icsgen.spec.model import Operation


def _field_map(view):
    return {field.name: field.value for field in view.fields}


def test_inspect_tcp_request_reports_mbap_fields():
    pdu = build_pdu(3, b"\x00\x00\x00\x03")
    frame = build_mbap(1, 0xFF, pdu)
    layout = get_layout("fc03")
    view = inspect_frame(layout, frame, BuildContext(transport="tcp"), "request")
    fields = _field_map(view)
    assert fields["事务 id"] == "1"
    assert fields["单元 id"] == "255"
    assert fields["功能码"] == "0x03"
    assert fields["start_addr"] == "0"
    assert fields["quantity"] == "3"
    assert view.is_exception is False


def test_inspect_tcp_response_decodes_layout_fields():
    pdu = build_pdu(3, b"\x06\x00\x01\x00\x02\x00\x03")
    frame = build_mbap(1, 0xFF, pdu)
    layout = get_layout("fc03")
    view = inspect_frame(layout, frame, BuildContext(transport="tcp"), "response")
    fields = _field_map(view)
    assert fields["byte_count"] == "6"
    assert fields["values"] == "1, 2, 3"


def test_inspect_detects_exception_response():
    pdu = build_pdu(0x83, b"\x02")
    frame = build_mbap(1, 0xFF, pdu)
    layout = get_layout("fc03")
    view = inspect_frame(layout, frame, BuildContext(transport="tcp"), "response")
    assert view.is_exception is True
    assert view.exception_code == 2
    assert "0x03" in view.summary


def test_inspect_exception_summary_distinguishes_base_code_and_wire_byte():
    """摘要里的基础功能码与线上字节要分得清，别让用户以为数据自相矛盾。"""
    pdu = build_pdu(0x83, b"\x02")
    frame = build_mbap(1, 0xFF, pdu)
    layout = get_layout("fc03")
    view = inspect_frame(layout, frame, BuildContext(transport="tcp"), "response")
    assert "0x03" in view.summary
    assert "0x83" in view.summary
    # 字段表的「功能码」是线上字节 —— 协议事实。
    assert _field_map(view)["功能码"] == "0x83"
    assert "None" not in view.summary


def test_inspect_exception_without_code_byte_omits_field():
    """异常响应只有功能码字节时，异常码字段不存在，也不能显示成 None。"""
    pdu = build_pdu(0x83, b"")
    frame = build_mbap(1, 0xFF, pdu)
    layout = get_layout("fc03")
    view = inspect_frame(layout, frame, BuildContext(transport="tcp"), "response")
    fields = _field_map(view)
    assert "异常码" not in fields
    assert view.exception_code is None
    assert "None" not in view.summary
    assert "异常码缺失" in view.summary
    assert "0x03" in view.summary
    assert "0x83" in view.summary


def test_inspect_rtu_frame_reports_unit_id():
    pdu = build_pdu(3, b"\x00\x00\x00\x03")
    frame = build_rtu(0x11, pdu)
    layout = get_layout("fc03")
    view = inspect_frame(layout, frame, BuildContext(transport="rtu"), "request")
    assert _field_map(view)["从站地址"] == "17"


def test_inspect_bad_crc_degrades_without_raising():
    """畸形帧也是数据集的一部分，解析失败不能抛异常。"""
    frame = b"\x11\x03\x00\x00\x00\x03\x00\x00"
    layout = get_layout("fc03")
    view = inspect_frame(layout, frame, BuildContext(transport="rtu"), "request")
    assert "解析失败" in view.summary
    assert view.fields == ()


def test_inspect_truncated_frame_degrades_without_raising():
    layout = get_layout("fc03")
    view = inspect_frame(layout, b"\x00\x01", BuildContext(transport="tcp"), "request")
    assert "解析失败" in view.summary


def test_adapter_inspect_resolves_layout_by_operation_name():
    """布局按操作名定位 —— 诊断子功能共享 fc08，按功能码反查会取错布局。"""
    adapter = load_modbus_adapter()
    pdu = build_pdu(3, b"\x00\x00\x00\x03")
    frame = build_mbap(1, 0xFF, pdu)
    view = adapter.inspect(
        "modbus.read_holding_registers", frame, BuildContext(transport="tcp"), "request"
    )
    assert _field_map(view)["quantity"] == "3"


def test_inspect_covers_every_catalog_layout():
    """验收指标 5：Modbus 全部 19 个布局的请求与响应字段都要解得出来。"""
    adapter = load_modbus_adapter()
    layouts = set()
    for name in adapter.catalog.operations:
        entry = adapter.catalog.get(name)
        layouts.add(entry.layout)
        operation = Operation(op=name, params={})
        ctx = BuildContext(transaction_id=1, unit_id=0xFF, transport="tcp", seed=0)

        request = adapter.build(operation, ctx)
        request_view = adapter.inspect(name, request.payload, ctx, "request")
        assert "解析失败" not in request_view.summary, name
        assert request_view.fields, name

        response = adapter.build_response(operation, ctx)
        if response is None:
            continue
        response_view = adapter.inspect(name, response.payload, ctx, "response")
        assert "解析失败" not in response_view.summary, name
        assert response_view.fields, name
    assert len(layouts) == 19
