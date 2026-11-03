"""Modbus 帧的协议级解析：把裸帧拆成头、功能码与字段。

预览页要展示「事务 id / 单元 id / 功能码 / 异常码 / 各字段值」，
这些是协议知识，留在协议层而不是 Web 层。
"""

from __future__ import annotations

from typing import Any

from ...codec.decoder import DecodeError, decode
from ...codec.fields import Layout
from ..base import BuildContext, FrameField, FrameView
from . import framing


def _format(value: Any) -> str:
    """把解码出的取值格式化成显示用的一行。"""
    if isinstance(value, bytes):
        return value.hex(" ")
    if isinstance(value, list):
        return ", ".join(_format(item) for item in value)
    return str(value)


def _decode_fields(
    layout: Layout, data: bytes, direction: str
) -> tuple[list[FrameField], str | None]:
    """按布局解字段；解不出时返回空列表与失败原因。"""
    fields = layout.request if direction == "request" else layout.response
    try:
        values = decode(fields, data)
    except DecodeError as exc:
        return [], str(exc)
    return [FrameField(name=name, value=_format(value)) for name, value in values.items()], None


def inspect_frame(
    layout: Layout, payload: bytes, ctx: BuildContext, direction: str
) -> FrameView:
    """解析一帧 Modbus 请求或响应。

    解析失败（帧过短、CRC 不符）不抛错，返回只含失败原因的 FrameView。
    """
    try:
        if ctx.transport == "rtu":
            parsed = framing.parse_rtu(payload)
            header = [FrameField("从站地址", str(parsed["unit_id"]))]
        else:
            parsed = framing.parse_mbap(payload)
            header = [
                FrameField("事务 id", str(parsed["transaction_id"])),
                FrameField("协议 id", str(parsed["protocol_id"])),
                FrameField("长度", str(parsed["length"])),
                FrameField("单元 id", str(parsed["unit_id"])),
            ]
        pdu = parsed["pdu"]
    except ValueError as exc:
        return FrameView(summary=f"解析失败：{exc}")

    if not pdu:
        return FrameView(summary="空 PDU")

    func_code = pdu[0]
    if func_code & 0x80:
        code = pdu[1] if len(pdu) > 1 else None
        fields = [
            *header,
            FrameField("功能码", f"0x{func_code:02X}"),
            FrameField("异常码", str(code)),
        ]
        return FrameView(
            summary=f"Modbus 异常响应，功能码 0x{func_code & 0x7F:02X}，异常码 {code}",
            fields=tuple(fields),
            is_exception=True,
            exception_code=code,
        )

    decoded, error = _decode_fields(layout, pdu[1:], direction)
    fields = [*header, FrameField("功能码", f"0x{func_code:02X}"), *decoded]
    summary = f"Modbus 功能码 0x{func_code:02X}"
    if error:
        summary = f"{summary}（字段解析失败：{error}）"
    return FrameView(summary=summary, fields=tuple(fields))
