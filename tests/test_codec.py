"""字段表驱动的编解码内核。"""

import pytest

from icsgen.codec.decoder import DecodeError, decode
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


def test_bytes_field_round_trips():
    """bytes 型变长字段编码后能原样解码回来（编解码器对称）。"""
    fields = (Field("length", "uint8", count_of="data"), Field("data", "bytes", count_from="length"))
    encoded = encode(fields, {"data": b"\x01\x02"})
    assert encoded == b"\x02\x01\x02"
    assert decode(fields, encoded) == {"length": 2, "data": b"\x01\x02"}


def test_encode_bytes_value_out_of_range_raises():
    """bytes 类型的值域错误收敛为 CodecError，而不是裸 ValueError。"""
    fields = (Field("length", "uint8", count_of="data"), Field("data", "bytes", count_from="length"))
    with pytest.raises(CodecError, match="无法编码为 bytes"):
        encode(fields, {"data": [256]})


def test_decode_unknown_type_raises():
    """未知字段类型解码时报 DecodeError，而不是裸 KeyError。"""
    fields = (Field("n", "uint8"), Field("weird", "uint64", count_from="n"))
    with pytest.raises(DecodeError, match="未知字段类型"):
        decode(fields, b"\x02\x00")


def test_decode_count_is_elements_keeps_count():
    """被引用字段给出的是元素个数时不再除以元素宽度。"""
    fields = (
        Field("fifo_count", "uint16"),
        Field("fifo_values", "uint16", count_from="fifo_count", count_is_elements=True),
    )
    assert decode(fields, b"\x00\x03\x00\x01\x00\x02\x00\x03") == {
        "fifo_count": 3,
        "fifo_values": [1, 2, 3],
    }


def test_decode_count_adjust_transforms_element_count():
    """count_adjust 在换算后对元素个数做一次修正。"""
    fields = (
        Field("record_length", "uint16"),
        Field("record_data", "bytes", count_from="record_length", count_adjust=lambda n: n * 2),
    )
    assert decode(fields, b"\x00\x02\x00\x01\x00\x02") == {
        "record_length": 2,
        "record_data": b"\x00\x01\x00\x02",
    }


def test_encode_count_of_falls_back_to_referenced_default():
    """被引用数组没有取值时，长度字段按被引用字段的缺省值计算。"""
    fields = (
        Field("byte_count", "uint8", count_of="data", adjust=lambda n: n + 1),
        Field("data", "bytes", count_from="byte_count", default=b"\x01\x02"),
    )
    assert encode(fields, {}) == b"\x03\x01\x02"


def test_encode_count_from_falls_back_to_field_default():
    """数组字段没有取值时用字段缺省值。"""
    fields = (
        Field("byte_count", "uint8", count_of="data"),
        Field("data", "bytes", count_from="byte_count", default=b"\x01\x02"),
    )
    assert encode(fields, {}) == b"\x02\x01\x02"
