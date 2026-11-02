"""Modbus 功能码的字段布局。

布局描述请求与响应 PDU 的字节结构（不含功能码字节本身，功能码由适配器
单独拼装）。诊断子功能的 21 个变体共享 fc08 布局，仅子功能码默认值不同。
"""

from __future__ import annotations

from icsgen.codec.fields import Field, Layout

#: FC0x08 诊断子功能全集（Modbus Application Protocol 规范）
DIAGNOSTIC_SUBFUNCTIONS: dict[int, str] = {
    0x0000: "Return Query Data",
    0x0001: "Restart Communications Option",
    0x0002: "Return Diagnostic Register",
    0x0003: "Change ASCII Input Delimiter",
    0x0004: "Force Listen Only Mode",
    0x0005: "Change Byte Count",
    0x0006: "Change Word Count",
    0x0008: "Get/Modify Modbus Plus Parameters",
    0x000A: "Clear Counters and Diagnostic Register",
    0x000B: "Return Bus Message Count",
    0x000C: "Return Bus Communication Error Count",
    0x000D: "Return Bus Exception Error Count",
    0x000E: "Return Slave Message Count",
    0x000F: "Return Slave No Response Count",
    0x0010: "Return Slave NAK Count",
    0x0011: "Return Slave Busy Count",
    0x0012: "Return Bus Character Overrun Count",
    0x0014: "Clear Overrun Counter and Flag",
    0x0015: "Get Clear Modbus Plus Request",
    0x0017: "Return I/O Overrun Count",
    0x0018: "Clear I/O Overrun Counter and Flag",
}

_READ_LAYOUT = Layout(
    request=(Field("start_addr", "uint16"), Field("quantity", "uint16")),
    response=(
        Field("byte_count", "uint8", count_of="values", adjust=lambda n: n * 2),
        Field("values", "uint16", count_from="byte_count", len_from_request="quantity"),
    ),
)

_WRITE_SINGLE_LAYOUT = Layout(
    request=(Field("start_addr", "uint16"), Field("value", "uint16")),
    response=(Field("start_addr", "uint16"), Field("value", "uint16")),
)

_FILE_REQUEST_FIELDS = (
    Field("reference_type", "uint16"),
    Field("file_number", "uint16"),
    Field("record_number", "uint16"),
    Field("record_length", "uint16"),
)

_FILE_RESPONSE_FIELDS = (
    Field("file_response_length", "uint16"),
    Field("reference_type", "uint16"),
    Field("file_number", "uint16"),
    Field("record_number", "uint16"),
)

LAYOUTS: dict[str, Layout] = {
    "fc01": _READ_LAYOUT,
    "fc02": _READ_LAYOUT,
    "fc03": _READ_LAYOUT,
    "fc04": _READ_LAYOUT,
    "fc05": _WRITE_SINGLE_LAYOUT,
    "fc06": _WRITE_SINGLE_LAYOUT,
    "fc07": Layout(request=(), response=(Field("status", "uint8"),)),
    "fc08": Layout(
        request=(Field("sub_function", "uint16"), Field("data", "uint16")),
        response=(Field("sub_function", "uint16"), Field("data", "uint16")),
    ),
    "fc0b": Layout(
        request=(),
        response=(Field("status", "uint16"), Field("event_count", "uint16")),
    ),
    "fc0c": Layout(
        request=(),
        response=(
            Field("status", "uint16"),
            Field("event_count", "uint16"),
            Field("message_count", "uint16"),
            Field("event_log_count", "uint16"),
            Field("log_length", "uint8", count_of="log"),
            Field("log", "bytes", count_from="log_length"),
        ),
    ),
    "fc0f": Layout(
        request=(
            Field("start_addr", "uint16"),
            Field("quantity", "uint16"),
            Field("byte_count", "uint8", count_of="values"),
            Field("values", "bytes", count_from="byte_count"),
        ),
        response=(Field("start_addr", "uint16"), Field("quantity", "uint16")),
    ),
    "fc10": Layout(
        request=(
            Field("start_addr", "uint16"),
            Field("quantity", "uint16"),
            Field("byte_count", "uint8", count_of="values", adjust=lambda n: n * 2),
            Field("values", "uint16", count_from="byte_count"),
        ),
        response=(Field("start_addr", "uint16"), Field("quantity", "uint16")),
    ),
    "fc11": Layout(
        request=(),
        response=(
            Field("byte_count", "uint8", count_of="slave_id"),
            Field("slave_id", "bytes", count_from="byte_count"),
        ),
    ),
    "fc12": Layout(
        request=_FILE_REQUEST_FIELDS,
        response=_FILE_RESPONSE_FIELDS
        + (
            Field("record_data_length", "uint16"),
            Field("data_length", "uint16"),
            Field("data", "bytes", count_from="data_length"),
        ),
    ),
    "fc14": Layout(
        request=_FILE_REQUEST_FIELDS,
        response=_FILE_RESPONSE_FIELDS
        + (
            Field("record_data_length", "uint16"),
            Field("data_length", "uint16"),
            Field("data", "bytes", count_from="data_length"),
        ),
    ),
    "fc15": Layout(
        request=_FILE_REQUEST_FIELDS,
        response=_FILE_RESPONSE_FIELDS + (Field("record_length", "uint16"),),
    ),
    "fc16": Layout(
        request=(Field("mask", "uint16"), Field("value", "uint16")),
        response=(Field("mask", "uint16"), Field("value", "uint16")),
    ),
    "fc17": Layout(
        request=(
            Field("read_addr", "uint16"),
            Field("read_quantity", "uint16"),
            Field("write_addr", "uint16"),
            Field("write_quantity", "uint16"),
            Field("write_byte_count", "uint8", count_of="write_values", adjust=lambda n: n * 2),
            Field("write_values", "uint16", count_from="write_byte_count", len_from_request="write_quantity"),
            Field("read_byte_count", "uint8", count_of="read_values", adjust=lambda n: n * 2),
            Field("read_values", "uint16", count_from="read_byte_count", len_from_request="read_quantity"),
        ),
        response=(
            Field("read_addr", "uint16"),
            Field("read_quantity", "uint16"),
            Field("write_addr", "uint16"),
            Field("write_quantity", "uint16"),
            Field("write_byte_count", "uint8", count_of="write_values", adjust=lambda n: n * 2),
            Field("write_values", "uint16", count_from="write_byte_count", len_from_request="write_quantity"),
            Field("read_byte_count", "uint8", count_of="read_values", adjust=lambda n: n * 2),
            Field("read_values", "uint16", count_from="read_byte_count", len_from_request="read_quantity"),
        ),
    ),
    "fc18": Layout(
        request=(),
        response=(
            Field("byte_count", "uint16", count_of="fifo_values"),
            Field("fifo_values", "uint16", count_from="byte_count"),
        ),
    ),
    "fc2b": Layout(
        request=(
            Field("mei_type", "uint8"),
            Field("read_device_id_code", "uint8"),
            Field("object_id", "uint8"),
        ),
        response=(
            Field("mei_type", "uint8"),
            Field("read_device_id_code", "uint8"),
            Field("conformity_level", "uint8"),
            Field("more_follows", "uint8"),
            Field("next_object_id", "uint8"),
            Field("number_of_objects", "uint8"),
            Field("object_id", "uint8"),
            Field("object_size", "uint8"),
            Field("object_value", "bytes", count_from="object_size"),
        ),
    ),
}


def get_layout(name: str) -> Layout:
    """按名称取布局，不存在时抛 KeyError。"""
    try:
        return LAYOUTS[name]
    except KeyError as exc:
        raise KeyError(f"不存在布局 {name!r}，可用布局：{sorted(LAYOUTS)}") from exc
