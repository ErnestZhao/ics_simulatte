"""Modbus 功能码的字段布局。

布局描述请求与响应 PDU 的字节结构（不含功能码字节本身，功能码由适配器
单独拼装）。字段结构对照 Modbus Application Protocol Specification V1.1b3；
长度字段的换算关系由 Field 的 count_of / count_from / adjust /
count_is_elements / count_adjust 声明。

诊断子功能的 21 个子功能各自是一个操作类型，共享 fc08 布局，仅子功能码
默认值不同。
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

#: FC0x01 / FC0x02 读位：响应数据按位打包，每 8 个线圈 1 字节
_BIT_READ_LAYOUT = Layout(
    request=(Field("start_addr", "uint16"), Field("quantity", "uint16")),
    response=(
        Field("byte_count", "uint8", count_of="values"),
        Field(
            "values",
            "bytes",
            count_from="byte_count",
            len_from_request="quantity",
            len_adjust=lambda n: (n + 7) // 8,
        ),
    ),
)

#: FC0x03 / FC0x04 读寄存器：响应数据每寄存器 2 字节
_REGISTER_READ_LAYOUT = Layout(
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

#: FC0x14 读文件记录请求：byte_count(7) + 引用类型 + 文件号 + 记录号 + 记录长度
_FILE_READ_REQUEST_FIELDS = (
    Field("byte_count", "uint8", default=7),
    Field("reference_type", "uint8", default=0x06),
    Field("file_number", "uint16", default=0),
    Field("record_number", "uint16", default=0),
    Field("record_length", "uint16", default=1),
)

#: FC0x14 读文件记录响应：两个长度字段都由记录数据长度推出
#: 记录数据以寄存器计（请求的 record_length 个寄存器），字节数是它的两倍
_FILE_READ_RESPONSE_FIELDS = (
    Field("byte_count", "uint8", count_of="record_data", adjust=lambda n: n + 2),
    Field("file_response_length", "uint8", count_of="record_data", adjust=lambda n: n + 1),
    Field("reference_type", "uint8", default=0x06),
    Field(
        "record_data",
        "bytes",
        count_from="file_response_length",
        count_adjust=lambda n: n - 1,
        len_from_request="record_length",
        len_adjust=lambda n: n * 2,
        default=b"\x00\x01\x00\x02",
    ),
)

#: FC0x15 写文件记录：请求与响应同构（响应是请求的回显）
_FILE_WRITE_FIELDS = (
    Field("byte_count", "uint8", count_of="record_data", adjust=lambda n: n + 7),
    Field("reference_type", "uint8", default=0x06),
    Field("file_number", "uint16", default=0),
    Field("record_number", "uint16", default=0),
    Field("record_length", "uint16", count_of="record_data", adjust=lambda n: n // 2),
    Field(
        "record_data",
        "bytes",
        count_from="record_length",
        count_is_elements=True,
        count_adjust=lambda n: n * 2,
        default=b"\x00\x01\x00\x02",
    ),
)

LAYOUTS: dict[str, Layout] = {
    "fc01": _BIT_READ_LAYOUT,
    "fc02": _BIT_READ_LAYOUT,
    "fc03": _REGISTER_READ_LAYOUT,
    "fc04": _REGISTER_READ_LAYOUT,
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
            Field("byte_count", "uint8", count_of="events", adjust=lambda n: n + 6),
            Field("status", "uint16", default=0),
            Field("event_count", "uint16", default=0),
            Field("message_count", "uint16", default=0),
            Field("events", "bytes", count_from="byte_count", count_adjust=lambda n: n - 6),
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
            Field("byte_count", "uint8", count_of="slave_id", adjust=lambda n: n + 1),
            Field(
                "slave_id",
                "bytes",
                count_from="byte_count",
                count_adjust=lambda n: n - 1,
                default=b"Pymodbus",
            ),
            Field("run_indicator_status", "uint8", default=0xFF),
        ),
    ),
    "fc14": Layout(
        request=_FILE_READ_REQUEST_FIELDS,
        response=_FILE_READ_RESPONSE_FIELDS,
    ),
    "fc15": Layout(
        request=_FILE_WRITE_FIELDS,
        response=_FILE_WRITE_FIELDS,
    ),
    "fc16": Layout(
        request=(
            Field("start_addr", "uint16"),
            Field("and_mask", "uint16"),
            Field("or_mask", "uint16"),
        ),
        response=(
            Field("start_addr", "uint16"),
            Field("and_mask", "uint16"),
            Field("or_mask", "uint16"),
        ),
    ),
    "fc17": Layout(
        request=(
            Field("read_addr", "uint16"),
            Field("read_quantity", "uint16"),
            Field("write_addr", "uint16"),
            Field("write_quantity", "uint16"),
            Field("write_byte_count", "uint8", count_of="write_values", adjust=lambda n: n * 2),
            Field("write_values", "uint16", count_from="write_byte_count"),
        ),
        response=(
            Field("byte_count", "uint8", count_of="values", adjust=lambda n: n * 2),
            Field("values", "uint16", count_from="byte_count", len_from_request="read_quantity"),
        ),
    ),
    "fc18": Layout(
        request=(Field("fifo_pointer_address", "uint16"),),
        response=(
            Field("byte_count", "uint16", count_of="fifo_values", adjust=lambda n: n * 2 + 2),
            Field("fifo_count", "uint16", count_of="fifo_values"),
            Field("fifo_values", "uint16", count_from="fifo_count", count_is_elements=True, default=(0, 1, 2, 3)),
        ),
    ),
    "fc2b": Layout(
        request=(
            Field("mei_type", "uint8", default=0x0E),
            Field("read_device_id_code", "uint8", default=0x01),
            Field("object_id", "uint8", default=0x00),
        ),
        response=(
            Field("mei_type", "uint8", default=0x0E),
            Field("read_device_id_code", "uint8", default=0x01),
            Field("conformity_level", "uint8", default=0x83),
            Field("more_follows", "uint8", default=0x00),
            Field("next_object_id", "uint8", default=0x00),
            Field("number_of_objects", "uint8", default=0x01),
            Field("object_id", "uint8", default=0x00),
            Field("object_size", "uint8", count_of="object_value"),
            Field("object_value", "bytes", count_from="object_size", default=b"\x01\x02"),
        ),
    ),
}


def get_layout(name: str) -> Layout:
    """按名称取布局，不存在时抛 KeyError。"""
    try:
        return LAYOUTS[name]
    except KeyError as exc:
        raise KeyError(f"不存在布局 {name!r}，可用布局：{sorted(LAYOUTS)}") from exc
