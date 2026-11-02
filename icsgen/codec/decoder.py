"""按字段布局把字节解码成取值字典。"""

from __future__ import annotations

from typing import Any

from .fields import FIELD_SIZES, Field


class DecodeError(ValueError):
    """字节数据无法按布局解码。"""


def _unpack_value(ftype: str, data: bytes, offset: int) -> Any:
    """从 data 的 offset 处读出一个标量值。"""
    size = FIELD_SIZES.get(ftype)
    if size is None:
        raise DecodeError(f"未知字段类型 {ftype!r}")
    if offset + size > len(data):
        remaining = len(data) - offset
        raise DecodeError(f"数据不足：偏移 {offset} 需要 {size} 字节，实际剩余 {remaining} 字节")
    chunk = data[offset : offset + size]
    if ftype == "bytes":
        return chunk
    return int.from_bytes(chunk, "big", signed=ftype.startswith("int"))


def decode(fields: tuple[Field, ...], data: bytes, offset: int = 0) -> dict[str, Any]:
    """按 fields 声明把 data 解码成取值字典。

    count_from 字段的元素个数 = 被引用字段的值 ÷ 本字段类型宽度；
    被引用字段声明 count_is_elements 时不再除以宽度，count_adjust 再做一次修正。
    count_of 字段在解码时按普通定长字段处理。
    bytes 类型的变长字段解码为连续的 bytes 对象，与编码器对称。
    """
    values: dict[str, Any] = {}
    for f in fields:
        if f.count_from is not None:
            referenced = values.get(f.count_from)
            if referenced is None:
                raise DecodeError(f"字段 {f.name!r} 依赖的 {f.count_from!r} 尚未解码")
            width = FIELD_SIZES.get(f.type)
            if width is None:
                raise DecodeError(f"未知字段类型 {f.type!r}")
            count = int(referenced)
            if not f.count_is_elements:
                # 引用值是字节计数时换算成元素个数
                count = count // width
            if f.count_adjust is not None:
                count = f.count_adjust(count)
            if f.type == "bytes":
                # bytes 类型宽度为 1，长度即字节数，直接切片返回连续字节串
                if offset + count > len(data):
                    remaining = len(data) - offset
                    raise DecodeError(
                        f"数据不足：偏移 {offset} 需要 {count} 字节，实际剩余 {remaining} 字节"
                    )
                values[f.name] = data[offset : offset + count]
                offset += count
                continue
            items: list[Any] = []
            for _ in range(count):
                items.append(_unpack_value(f.type, data, offset))
                offset += width
            values[f.name] = items
            continue
        values[f.name] = _unpack_value(f.type, data, offset)
        offset += FIELD_SIZES[f.type]
    return values
