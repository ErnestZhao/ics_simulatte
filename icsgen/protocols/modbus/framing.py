"""Modbus 帧的组装与解析。

TCP 用 7 字节 MBAP 头（事务 id、协议 id、长度、单元 id），
RTU 用「地址 + PDU + CRC16」结构。
"""

from __future__ import annotations

from typing import Any

from .crc import crc16

#: MBAP 头长度
MBAP_HEADER_LEN = 7


def build_pdu(func_code: int, payload: bytes) -> bytes:
    """功能码 + PDU 数据。"""
    return bytes([func_code]) + payload


def build_mbap(transaction_id: int, unit_id: int, pdu: bytes) -> bytes:
    """组装 Modbus TCP 帧（MBAP 头 + PDU）。"""
    header = (
        transaction_id.to_bytes(2, "big")
        + b"\x00\x00"
        + (len(pdu) + 1).to_bytes(2, "big")
        + bytes([unit_id])
    )
    return header + pdu


def build_rtu(unit_id: int, pdu: bytes) -> bytes:
    """组装 Modbus RTU 帧（地址 + PDU + CRC16）。"""
    body = bytes([unit_id]) + pdu
    return body + crc16(body).to_bytes(2, "little")


def build_exception_pdu(func_code: int, exception_code: int) -> bytes:
    """组装异常响应 PDU：功能码置最高位，后跟异常码。"""
    return bytes([func_code | 0x80, exception_code])


def parse_mbap(data: bytes) -> dict[str, Any]:
    """解析 Modbus TCP 帧。"""
    if len(data) < MBAP_HEADER_LEN:
        raise ValueError(f"Modbus TCP 帧过短：{len(data)} 字节，至少需要 {MBAP_HEADER_LEN} 字节")
    transaction_id = int.from_bytes(data[0:2], "big")
    protocol_id = int.from_bytes(data[2:4], "big")
    length = int.from_bytes(data[4:6], "big")
    unit_id = data[6]
    return {
        "transaction_id": transaction_id,
        "protocol_id": protocol_id,
        "length": length,
        "unit_id": unit_id,
        "pdu": data[MBAP_HEADER_LEN:],
    }


def parse_rtu(data: bytes) -> dict[str, Any]:
    """解析 Modbus RTU 帧，并校验 CRC。"""
    if len(data) < 4:
        raise ValueError(f"Modbus RTU 帧过短：{len(data)} 字节")
    unit_id = data[0]
    body = data[:-2]
    received = int.from_bytes(data[-2:], "little")
    expected = crc16(body)
    if received != expected:
        raise ValueError(f"Modbus RTU 帧 CRC 校验失败：收到 {received:#06x}，期望 {expected:#06x}")
    return {"unit_id": unit_id, "pdu": data[1:-2]}
