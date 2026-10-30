"""字段表驱动的编解码内核：字段声明与布局定义。

内核本身不含任何协议知识 —— 协议方通过声明 Field 序列描述报文的字节结构，
由 encoder / decoder 按声明完成转换。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

#: 各字段类型的字节宽度。bytes 视作 1 字节元素组成的数组。
FIELD_SIZES: dict[str, int] = {
    "uint8": 1,
    "int8": 1,
    "uint16": 2,
    "int16": 2,
    "uint32": 4,
    "int32": 4,
    "bytes": 1,
}


@dataclass(frozen=True)
class Field:
    """一个协议字段的声明。

    count_of:  编码时本字段的值由被引用字段的元素个数决定（被引用字段是数组时取其长度）
    count_from: 解码时本字段是变长数组，元素个数由被引用字段的值除以本字段类型宽度得出
    len_from_request: 构造响应时本数组的元素个数取自请求中的该参数，仅用于构造
    adjust:    写入长度字段前的换算函数，例如 Modbus 的 byte_count = len(values) * 2
    default:   缺省值，编码时 values 中缺少该字段则使用
    """

    name: str
    type: str
    count_of: str | None = None
    count_from: str | None = None
    len_from_request: str | None = None
    adjust: Callable[[int], int] | None = None
    default: Any = None


@dataclass(frozen=True)
class Layout:
    """一组字段的布局，描述某个操作类型的请求与响应结构。"""

    request: tuple[Field, ...] = ()
    response: tuple[Field, ...] = ()
