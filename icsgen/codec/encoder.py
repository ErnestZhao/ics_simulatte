"""按字段布局把取值字典编码成字节。"""

from __future__ import annotations

from typing import Any, Mapping

from .fields import FIELD_SIZES, Field


class CodecError(ValueError):
    """字段值无法按布局编码。"""


def _pack_value(ftype: str, value: Any) -> bytes:
    """把单个标量值按类型打包为大端字节。"""
    size = FIELD_SIZES.get(ftype)
    if size is None:
        raise CodecError(f"未知字段类型 {ftype!r}")
    try:
        if ftype == "bytes":
            # bytes 类型视作 1 字节元素：整数按单字节写出，字节串按原样写出
            if isinstance(value, int):
                return bytes([value])
            return bytes(value)
        return int(value).to_bytes(size, "big", signed=ftype.startswith("int"))
    except (TypeError, ValueError) as exc:
        raise CodecError(f"值 {value!r} 无法编码为 {ftype}") from exc


def encode(fields: tuple[Field, ...], values: Mapping[str, Any]) -> bytes:
    """按 fields 声明把 values 编码成字节。

    count_of 字段写入被引用数组的长度（经 adjust 换算）；
    count_from 字段直接写入 values 中对应数组的各元素。
    """
    out = bytearray()
    for f in fields:
        if f.count_of is not None:
            referenced = values.get(f.count_of)
            if referenced is None:
                raise CodecError(f"字段 {f.name!r} 依赖的 {f.count_of!r} 缺失")
            if isinstance(referenced, (list, tuple, bytes, bytearray)):
                count = len(referenced)
            else:
                count = int(referenced)
            if f.adjust is not None:
                count = f.adjust(count)
            out += _pack_value(f.type, count)
            continue
        if f.count_from is not None:
            items = values.get(f.name)
            if items is None:
                raise CodecError(f"缺少数组字段 {f.name!r}")
            # bytes 类型的变长字段，其元素是 1 字节整数或 1 字节字节串，
            # 两种形态都由 _pack_value 统一处理，编码结果与解码器对称。
            for item in items:
                out += _pack_value(f.type, item)
            continue
        if f.name not in values:
            if f.default is None:
                raise CodecError(f"缺少字段 {f.name!r} 的值")
            out += _pack_value(f.type, f.default)
            continue
        out += _pack_value(f.type, values[f.name])
    return bytes(out)
