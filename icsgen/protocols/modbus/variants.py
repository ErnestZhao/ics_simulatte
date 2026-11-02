"""Modbus 变体语义。

同一操作在不同变体下的取值策略集中在这里：normal 取常规值，boundary 取
参数上界，exception 产生协议异常响应，illegal_fc 使用非法功能码，
malformed 构造长度字段与实际内容不符的畸形帧。

边界变体需要两个上界：``maxima`` 是标量参数的上界与数组元素的上界，
``max_counts`` 是数组参数的元素个数上界。两者都来自 catalog，缺一不可 ——
只顶元素值会让帧里的计数标量与实际内容自相矛盾。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from icsgen.codec.fields import Field, Layout
from icsgen.spec.model import Variant

#: 协议异常码：0x02 非法数据地址
DEFAULT_EXCEPTION_CODE = 0x02

#: 协议异常码：0x01 非法功能码
ILLEGAL_FUNCTION_EXCEPTION_CODE = 0x01


@dataclass(frozen=True)
class VariantPlan:
    """一个操作在特定变体下的完整取值方案。"""

    func_code: int
    request_values: dict[str, Any] = field(default_factory=dict)
    response_values: dict[str, Any] = field(default_factory=dict)
    is_exception: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


def _default_for(f: Field) -> Any:
    """给没有默认值的字段造一个合理的占位值。"""
    if f.type == "bytes":
        return b""
    return 0


def _array_placeholder(f: Field) -> Any:
    """给变长数组造一个类型正确的占位值（一个元素）。

    数组的元素个数来自长度字段、而长度字段又由数组长度推出时，数组无法
    反推，只能给一个最小长度的占位。占位必须是序列：给标量会让编码器在
    遍历数组时抛裸 TypeError。
    """
    if f.type == "bytes":
        return b"\x00"
    return [0]


def _element_count(f: Field, raw: int, from_request: bool = False) -> int:
    """把长度来源换算成元素个数。

    ``len_from_request`` 给出的已经是元素个数，再经 ``len_adjust`` 修正
    （FC01 的响应数据按位打包，字节数是线圈数 ÷ 8 向上取整）；
    ``count_from`` 给出的通常是字节计数，要除以元素宽度
    （bytes 型宽度为 1，除法无影响），再经 ``count_adjust`` 修正。
    """
    count = int(raw)
    if from_request:
        if f.len_adjust is not None:
            count = f.len_adjust(count)
        return count
    if not f.count_is_elements:
        count = count // (2 if f.type == "uint16" else 1)
    if f.count_adjust is not None:
        count = f.count_adjust(count)
    return count


def _apply_length_fields(fields: tuple[Field, ...], values: dict[str, Any]) -> None:
    """按数组长度算出长度字段（count_of），就地更新取值字典。"""
    for f in fields:
        if f.count_of is None:
            continue
        referenced = values.get(f.count_of)
        if isinstance(referenced, (list, tuple, bytes, bytearray)):
            count = len(referenced)
        else:
            count = int(referenced or 0)
        if f.adjust is not None:
            count = f.adjust(count)
        values[f.name] = count


def _build_values(layout: Layout, params: dict[str, Any]) -> dict[str, Any]:
    """按布局与参数填充取值字典。

    三遍处理：先填普通字段，再定出变长数组，最后由数组长度算出长度字段。
    参数优先，其次是字段声明的缺省值，最后才是占位值；变长数组若既没有
    参数也没有缺省值，按其长度来源补一份零填充数据。长度字段与数组内容
    必须自洽，否则编码出来的帧与声明的规模对不上。
    """
    values: dict[str, Any] = {}

    # 第一遍：普通字段
    for f in layout.request:
        if f.count_of is not None or f.count_from is not None:
            continue
        if f.name in params:
            values[f.name] = params[f.name]
        elif f.default is not None:
            values[f.name] = f.default
        else:
            values[f.name] = _default_for(f)

    # 第二遍：变长数组
    by_name = {f.name: f for f in layout.request}
    for f in layout.request:
        if f.count_from is None:
            continue
        if f.name in params:
            values[f.name] = params[f.name]
            continue
        if f.default is not None:
            values[f.name] = f.default
            continue
        source = by_name.get(f.count_from)
        raw = values.get(f.count_from) if source is not None else None
        if source is None or source.count_of is not None or raw is None:
            # 长度字段本身由数组长度推出，无法反推数组
            values[f.name] = _array_placeholder(f)
            continue
        count = _element_count(f, raw)
        values[f.name] = b"\x00" * count if f.type == "bytes" else [0] * count

    # 第三遍：长度字段
    _apply_length_fields(layout.request, values)
    return values


def _apply_boundary(
    layout: Layout,
    params: dict[str, Any],
    maxima: dict[str, int],
    max_counts: dict[str, int],
) -> dict[str, Any]:
    """把参数顶到上界。

    标量参数取其最大值；数组参数取最大元素个数（``max_counts``），并把每个
    元素顶到元素上界（``maxima``）。数组长度必须一起顶 —— 只顶元素值会让帧
    里的计数标量与实际内容对不上。
    """
    values = _build_values(layout, params)
    for name, maximum in maxima.items():
        current = values.get(name)
        if isinstance(current, bool):
            continue
        if isinstance(current, int):
            values[name] = maximum
        elif isinstance(current, (list, tuple)):
            values[name] = [maximum] * max_counts.get(name, len(current))
        elif isinstance(current, (bytes, bytearray)):
            values[name] = bytes([maximum & 0xFF]) * max_counts.get(name, len(current))
    _apply_length_fields(layout.request, values)
    return values


def _build_response(layout: Layout, request_values: dict[str, Any]) -> dict[str, Any]:
    """构造与请求规模匹配的响应取值。

    三遍处理：先定出各变长数组的长度，再填普通字段，最后由数组长度算出
    长度字段。顺序颠倒会让 FC03 响应的 byte_count 算成 0。
    """
    values: dict[str, Any] = {}

    # 第一遍：变长数组
    for f in layout.response:
        if f.count_from is None:
            continue
        source = f.len_from_request or f.count_from
        raw = request_values.get(source)
        if raw is None:
            # 长度来源不可得（它本身由数组长度推出），退回字段缺省值
            values[f.name] = f.default if f.default is not None else _array_placeholder(f)
            continue
        count = _element_count(f, raw, from_request=f.len_from_request is not None)
        values[f.name] = b"\x00" * count if f.type == "bytes" else [0] * count

    # 第二遍：普通字段
    for f in layout.response:
        if f.count_of is not None or f.count_from is not None:
            continue
        values[f.name] = f.default if f.default is not None else _default_for(f)

    # 第三遍：长度字段
    _apply_length_fields(layout.response, values)
    return values


def plan_variant(
    layout: Layout,
    op_name: str,
    func_code: int,
    params: dict[str, Any],
    variant: Variant,
    maxima: dict[str, int] | None = None,
    max_counts: dict[str, int] | None = None,
) -> VariantPlan:
    """为一个操作在特定变体下制定取值方案。

    maxima 是标量参数的上界与数组元素的上界，max_counts 是数组参数的元素
    个数上界；boundary 变体据此把参数顶到边界。
    """
    maxima = maxima or {}
    max_counts = max_counts or {}

    if variant is Variant.ILLEGAL_FC:
        # 非法功能码由 catalog 条目自身的 func_code 决定
        request_values = _build_values(layout, params)
        return VariantPlan(
            func_code=func_code,
            request_values=request_values,
            response_values={},
            is_exception=True,
            metadata={
                "op": op_name,
                "exception_code": ILLEGAL_FUNCTION_EXCEPTION_CODE,
                "illegal_function_code": func_code,
            },
        )

    if variant is Variant.MALFORMED:
        request_values = _build_values(layout, params)
        return VariantPlan(
            func_code=func_code,
            request_values=request_values,
            response_values={},
            is_exception=False,
            metadata={"op": op_name, "malformed": True},
        )

    if variant is Variant.BOUNDARY:
        request_values = _apply_boundary(layout, params, maxima, max_counts)
    else:
        request_values = _build_values(layout, params)

    response_values = _build_response(layout, request_values)

    if variant is Variant.EXCEPTION:
        return VariantPlan(
            func_code=func_code,
            request_values=request_values,
            response_values={},
            is_exception=True,
            metadata={"op": op_name, "exception_code": DEFAULT_EXCEPTION_CODE},
        )

    return VariantPlan(
        func_code=func_code,
        request_values=request_values,
        response_values=response_values,
        is_exception=False,
        metadata={"op": op_name},
    )
