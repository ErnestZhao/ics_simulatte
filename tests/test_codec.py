"""字段表驱动的编解码内核。"""

import pytest

from icsgen.codec.decoder import decode
from icsgen.codec.encoder import CodecError, encode
from icsgen.codec.fields import Field, Layout


def test_encode_fixed_width_fields():
    fields = (Field("start_addr", "uint16"), Field("quantity", "uint16"))
    assert encode(fields, {"start_addr": 0x0001, "quantity": 0x0003}) == b"\x00\x01\x00\x03"


def test_encode_signed_field():
    fields = (Field("value", "int16"),)
    assert encode(fields, {"value": -2}) == b"\xff\xfe"


def test_encode_count_of_with_adjust():
    """byte_count 由 values 长度乘 2 得出。"""
    fields = (
        Field("byte_count", "uint8", count_of="values", adjust=lambda n: n * 2),
        Field("values", "uint16", count_from="byte_count"),
    )
    out = encode(fields, {"values": [0xDEAD, 0xBEEF]})
    assert out == b"\x04\xde\xad\xbe\xef"


def test_encode_bytes_array():
    fields = (Field("length", "uint8", count_of="data"), Field("data", "bytes", count_from="length"))
    assert encode(fields, {"data": b"\x01\x02"}) == b"\x02\x01\x02"


def test_encode_uses_default_when_value_missing():
    fields = (Field("unit_id", "uint8", default=0xFF),)
    assert encode(fields, {}) == b"\xff"


def test_encode_missing_required_field_raises():
    fields = (Field("start_addr", "uint16"),)
    with pytest.raises(CodecError, match="缺少字段"):
        encode(fields, {})


def test_encode_unknown_type_raises():
    fields = (Field("weird", "uint64"),)
    with pytest.raises(CodecError, match="未知字段类型"):
        encode(fields, {"weird": 1})


def test_decode_round_trip():
    fields = (
        Field("byte_count", "uint8", count_of="values", adjust=lambda n: n * 2),
        Field("values", "uint16", count_from="byte_count"),
    )
    raw = b"\x04\xde\xad\xbe\xef"
    assert decode(fields, raw) == {"byte_count": 4, "values": [0xDEAD, 0xBEEF]}


def test_decode_from_offset():
    fields = (Field("quantity", "uint16"),)
    assert decode(fields, b"\xff\xff\x00\x07", offset=2) == {"quantity": 7}


def test_decode_insufficient_data_raises():
    fields = (Field("start_addr", "uint16"),)
    with pytest.raises(Exception, match="数据不足"):
        decode(fields, b"\x00")


def test_layout_holds_request_and_response():
    layout = Layout(request=(Field("a", "uint8"),), response=(Field("b", "uint16"),))
    assert len(layout.request) == 1
    assert len(layout.response) == 1
