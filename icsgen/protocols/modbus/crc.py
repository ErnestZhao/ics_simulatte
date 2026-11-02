"""Modbus RTU 的 CRC16 计算。

采用 Modbus 规范的多项式 0xA001（0x8005 的反转形式），初值 0xFFFF，
结果按低字节在前附加到帧尾。
"""

from __future__ import annotations


def crc16(data: bytes) -> int:
    """计算 Modbus RTU CRC16，返回 16 位整数。"""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc
