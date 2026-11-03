"""场景 YAML 的加载与校验。

加载链路：YAML → pydantic 校验结构 → 逐个操作查 catalog → 用 catalog 声明的
参数 schema 校验参数 → 构造 Operation 列表。

Web 表单提交走同一条校验路径（validate_operations），因此参数 schema、
变体合法性、tier/variant 冲突的判定与错误文案在两条路径上完全一致。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Sequence

import yaml
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError

from .catalog import Catalog, OperationEntry
from .model import Operation, Scenario, Tier, Variant


class ScenarioError(ValueError):
    """场景文件不合法。"""


class ScenarioOperationModel(BaseModel):
    """场景中的一条操作声明。"""

    op: str
    params: dict[str, Any] = {}
    variant: Variant = Variant.NORMAL
    tier: Tier | None = None
    expect_response: bool = True


class ScenarioModel(BaseModel):
    """scenario.yaml 的结构。"""

    name: str
    description: str = ""
    transport: dict[str, Any] = {}
    operations: list[ScenarioOperationModel]


def _object_schema(entry: OperationEntry) -> dict[str, Any]:
    """把 catalog 的逐参数 schema 映射拼成对象级 JSON Schema。

    catalog 的 params 形如 {"quantity": {"type": "integer", ...}}，是
    「参数名 -> 该参数的 schema」的映射。直接交给 jsonschema 会被当成一份
    无约束的空 schema（关键字 quantity 不被识别），任何参数都能通过校验，
    因此必须显式包成对象级 schema。
    """
    return {
        "type": "object",
        "properties": entry.params,
        "additionalProperties": False,
    }


def _operation_label(context: str | None, index: int, name: str) -> str:
    """生成「第 N 条操作 <名字>」的定位串，context 为空时省略前缀。"""
    prefix = f"{context} " if context else ""
    return f"{prefix}第 {index} 条操作 {name!r}"


def _validate_params(entry: OperationEntry, params: dict[str, Any], label: str) -> None:
    """用 catalog 声明的参数 schema 校验操作参数。"""
    if not entry.params:
        if params:
            raise ScenarioError(f"{label} 不接受参数，但给出了 {params}")
        return
    validator = Draft202012Validator(_object_schema(entry))
    errors = sorted(validator.iter_errors(params), key=lambda e: list(e.path))
    if errors:
        details = "; ".join(f"{list(e.path) or '<根>'}: {e.message}" for e in errors)
        raise ScenarioError(f"{label} 参数校验失败：{details}")


def validate_operations(
    catalog: Catalog,
    items: Sequence[ScenarioOperationModel],
    context: str | None = None,
) -> tuple[Operation, ...]:
    """按 catalog 校验一组操作声明，返回构造好的 Operation 列表。

    context 是可选的定位前缀（如 "场景 <路径>" 或 "提交的操作"），
    只影响错误文案，不影响判定。
    """
    operations: list[Operation] = []
    for index, item in enumerate(items):
        try:
            entry = catalog.get(item.op)
        except KeyError as exc:
            raise ScenarioError(
                f"{_operation_label(context, index, item.op)}："
                f"catalog {catalog.protocol!r} 中不存在操作"
            ) from exc
        if item.variant.value not in entry.variants:
            raise ScenarioError(
                f"{_operation_label(context, index, entry.name)} 不支持的变体 "
                f"{item.variant.value!r}，可用变体：{entry.variants}"
            )
        _validate_params(entry, item.params, _operation_label(context, index, entry.name))
        try:
            operation = Operation(
                op=item.op,
                params=item.params,
                variant=item.variant,
                tier=item.tier,
                expect_response=item.expect_response,
            )
        except ValueError as exc:
            # tier 与 variant 冲突由 Operation 构造时发现，这里统一转成场景错误，
            # 保证对外只有 ScenarioError 一种失败形态。
            raise ScenarioError(
                f"{_operation_label(context, index, entry.name)} 的语义层与变体冲突：{exc}"
            ) from exc
        operations.append(operation)
    return tuple(operations)


def load_scenario(path: Path, catalog: Catalog) -> Scenario:
    """加载并校验场景文件，返回 Scenario。"""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    try:
        model = ScenarioModel.model_validate(raw)
    except ValidationError as exc:
        raise ScenarioError(f"场景 {path} 结构不合法：{exc}") from exc

    operations = validate_operations(catalog, model.operations, context=f"场景 {path}")

    return Scenario(
        name=model.name,
        description=model.description,
        transport=model.transport,
        operations=operations,
    )
