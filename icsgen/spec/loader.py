"""场景 YAML 的加载与校验。

加载链路：YAML → pydantic 校验结构 → 逐个操作查 catalog → 用 catalog 声明的
参数 schema 校验参数 → 构造 Operation 列表。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

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


def _validate_params(entry: OperationEntry, params: dict[str, Any], path: Path, index: int) -> None:
    """用 catalog 声明的参数 schema 校验操作参数。"""
    if not entry.params:
        if params:
            raise ScenarioError(
                f"场景 {path} 第 {index} 条操作 {entry.name!r} 不接受参数，但给出了 {params}"
            )
        return
    validator = Draft202012Validator(_object_schema(entry))
    errors = sorted(validator.iter_errors(params), key=lambda e: list(e.path))
    if errors:
        details = "; ".join(f"{list(e.path) or '<根>'}: {e.message}" for e in errors)
        raise ScenarioError(
            f"场景 {path} 第 {index} 条操作 {entry.name!r} 参数校验失败：{details}"
        )


def load_scenario(path: Path, catalog: Catalog) -> Scenario:
    """加载并校验场景文件，返回 Scenario。"""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    try:
        model = ScenarioModel.model_validate(raw)
    except ValidationError as exc:
        raise ScenarioError(f"场景 {path} 结构不合法：{exc}") from exc

    operations: list[Operation] = []
    for index, item in enumerate(model.operations):
        try:
            entry = catalog.get(item.op)
        except KeyError as exc:
            raise ScenarioError(
                f"场景 {path} 第 {index} 条操作 {item.op!r} 不存在操作"
            ) from exc
        if item.variant.value not in entry.variants:
            raise ScenarioError(
                f"场景 {path} 第 {index} 条操作 {entry.name!r} 不支持的变体 {item.variant.value!r}，"
                f"可用变体：{entry.variants}"
            )
        _validate_params(entry, item.params, path, index)
        operations.append(
            Operation(
                op=item.op,
                params=item.params,
                variant=item.variant,
                tier=item.tier,
                expect_response=item.expect_response,
            )
        )

    return Scenario(
        name=model.name,
        description=model.description,
        transport=model.transport,
        operations=tuple(operations),
    )
