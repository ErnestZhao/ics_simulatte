"""Modbus 变体语义：同一操作的正常/边界/异常/非法功能码形态。"""

from icsgen.protocols.modbus.layouts import get_layout
from icsgen.protocols.modbus.variants import plan_variant
from icsgen.spec.model import Variant


def test_normal_plan_uses_given_params():
    layout = get_layout("fc03")
    plan = plan_variant(layout, "modbus.read_holding_registers", 3, {"start_addr": 5, "quantity": 3}, Variant.NORMAL)
    assert plan.func_code == 3
    assert plan.request_values["start_addr"] == 5
    assert plan.request_values["quantity"] == 3
    assert plan.is_exception is False


def test_boundary_plan_uses_upper_bound():
    """边界变体把 quantity 顶到上界 125。"""
    layout = get_layout("fc03")
    plan = plan_variant(
        layout,
        "modbus.read_holding_registers",
        3,
        {"start_addr": 0, "quantity": 3},
        Variant.BOUNDARY,
        maxima={"quantity": 125},
    )
    assert plan.request_values["quantity"] == 125


def test_exception_plan_marks_exception():
    layout = get_layout("fc03")
    plan = plan_variant(layout, "modbus.read_holding_registers", 3, {"quantity": 3}, Variant.EXCEPTION)
    assert plan.is_exception is True
    assert plan.metadata["exception_code"] == 2


def test_illegal_function_code_variant_marks_exception():
    """非法功能码由 catalog 条目的 func_code 决定，响应是异常响应。"""
    layout = get_layout("fc01")
    plan = plan_variant(
        layout,
        "modbus.illegal_function_code",
        99,
        {"quantity": 1},
        Variant.ILLEGAL_FC,
    )
    assert plan.func_code == 99
    assert plan.is_exception is True
    assert plan.metadata["illegal_function_code"] == 99
    assert plan.metadata["exception_code"] == 1


def test_malformed_variant_has_no_response():
    layout = get_layout("fc03")
    plan = plan_variant(layout, "modbus.read_holding_registers", 3, {"quantity": 3}, Variant.MALFORMED)
    assert plan.response_values == {}
    assert plan.metadata["malformed"] is True


def test_response_values_populated_for_normal():
    layout = get_layout("fc03")
    plan = plan_variant(layout, "modbus.read_holding_registers", 3, {"quantity": 3}, Variant.NORMAL)
    assert "values" in plan.response_values
    assert len(plan.response_values["values"]) == 3


def test_response_byte_count_matches_value_count():
    """FC03 响应的 byte_count 应等于寄存器数的两倍。"""
    layout = get_layout("fc03")
    plan = plan_variant(layout, "modbus.read_holding_registers", 3, {"quantity": 3}, Variant.NORMAL)
    assert plan.response_values["byte_count"] == 6
    assert len(plan.response_values["values"]) == 3


def test_bit_read_response_is_packed_to_bytes():
    """FC01 响应数据按位打包：9 个线圈占 2 字节，不是 9 字节。"""
    layout = get_layout("fc01")
    plan = plan_variant(layout, "modbus.read_coils", 1, {"quantity": 9}, Variant.NORMAL)
    assert plan.response_values["byte_count"] == 2
    assert plan.response_values["values"] == b"\x00\x00"


def test_boundary_plan_pushes_array_elements_to_maximum():
    """边界变体把数组参数的每个元素都顶到元素上界。"""
    layout = get_layout("fc10")
    plan = plan_variant(
        layout,
        "modbus.write_multiple_registers",
        16,
        {"quantity": 2, "values": [1, 2]},
        Variant.BOUNDARY,
        maxima={"values": 0xFFFF},
    )
    assert plan.request_values["values"] == [0xFFFF, 0xFFFF]


def test_file_write_response_length_fields_are_consistent():
    """FC15 响应的 byte_count 与 record_length 必须与记录数据自洽。"""
    layout = get_layout("fc15")
    plan = plan_variant(
        layout,
        "modbus.write_file_record",
        21,
        {"record_data": b"\x00\x01\x00\x02"},
        Variant.NORMAL,
    )
    assert plan.request_values["record_length"] == 2
    assert plan.request_values["byte_count"] == 11
    assert plan.response_values["record_length"] == 2
    assert plan.response_values["byte_count"] == 11
    assert len(plan.response_values["record_data"]) == 4
