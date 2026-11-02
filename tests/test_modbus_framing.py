"""Modbus 组帧：MBAP、RTU 与 CRC16。"""

from icsgen.protocols.modbus.crc import crc16
from icsgen.protocols.modbus.framing import (
    build_exception_pdu,
    build_mbap,
    build_pdu,
    build_rtu,
    parse_mbap,
    parse_rtu,
)


def test_crc16_known_vector():
    """CRC-16/MODBUS 的标准校验值：ASCII "123456789" 的 CRC 为 0x4B37。

    该值取自 CRC catalogue，与任何字节序约定无关，用来锚定算法本身。
    """
    assert crc16(b"123456789") == 0x4B37


def test_crc16_rtu_vector_is_low_byte_first():
    """0x01 0x04 0x02 0xFF 0xFF 的 CRC 值为 0x80B8，线上按低字节在前附加。"""
    assert crc16(b"\x01\x04\x02\xff\xff") == 0x80B8
    assert crc16(b"\x01\x04\x02\xff\xff").to_bytes(2, "little") == b"\xb8\x80"


def test_crc16_empty_is_init_value():
    assert crc16(b"") == 0xFFFF


def test_build_pdu_prefixes_function_code():
    assert build_pdu(0x03, b"\x00\x00\x00\x03") == b"\x03\x00\x00\x00\x03"


def test_build_mbap_header():
    """MBAP 头：事务 id、协议 id、长度、单元 id。"""
    pdu = build_pdu(0x03, b"\x00\x00\x00\x03")
    frame = build_mbap(transaction_id=1, unit_id=0xFF, pdu=pdu)
    assert frame[:7] == b"\x00\x01\x00\x00\x00\x06\xff"
    assert len(frame) == 7 + len(pdu)
    assert frame[7:] == pdu


def test_build_mbap_length_field_counts_unit_and_pdu():
    pdu = build_pdu(0x03, b"\x00\x00\x00\x03")
    frame = build_mbap(transaction_id=0, unit_id=0x0A, pdu=pdu)
    length = int.from_bytes(frame[4:6], "big")
    assert length == 1 + len(pdu)


def test_parse_mbap_round_trip():
    pdu = build_pdu(0x03, b"\x00\x00\x00\x03")
    frame = build_mbap(transaction_id=7, unit_id=0x11, pdu=pdu)
    parsed = parse_mbap(frame)
    assert parsed["transaction_id"] == 7
    assert parsed["unit_id"] == 0x11
    assert parsed["pdu"] == pdu


def test_build_rtu_appends_crc_little_endian():
    pdu = build_pdu(0x03, b"\x00\x00\x00\x03")
    frame = build_rtu(unit_id=0x11, pdu=pdu)
    assert frame[0] == 0x11
    assert frame[1:-2] == pdu
    expected = crc16(frame[:-2])
    assert frame[-2:] == expected.to_bytes(2, "little")


def test_build_rtu_matches_known_wire_frame():
    """整帧字节锚定：地址 0x01、FC04、02 FF FF 的 RTU 帧是 01 04 02 FF FF B8 80。"""
    frame = build_rtu(unit_id=0x01, pdu=build_pdu(0x04, b"\x02\xff\xff"))
    assert frame == b"\x01\x04\x02\xff\xff\xb8\x80"


def test_parse_rtu_round_trip():
    pdu = build_pdu(0x03, b"\x00\x00\x00\x03")
    frame = build_rtu(unit_id=0x11, pdu=pdu)
    parsed = parse_rtu(frame)
    assert parsed["unit_id"] == 0x11
    assert parsed["pdu"] == pdu


def test_parse_rtu_rejects_bad_crc():
    pdu = build_pdu(0x03, b"\x00\x00\x00\x03")
    frame = bytearray(build_rtu(unit_id=0x11, pdu=pdu))
    frame[-1] ^= 0xFF
    try:
        parse_rtu(bytes(frame))
    except ValueError as exc:
        assert "CRC" in str(exc)
    else:
        raise AssertionError("应当拒绝 CRC 错误的 RTU 帧")


def test_build_exception_pdu():
    """异常响应：功能码置最高位 + 异常码。"""
    assert build_exception_pdu(0x03, 0x02) == b"\x83\x02"
