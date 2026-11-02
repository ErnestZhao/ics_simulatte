"""操作目录（catalog）的加载与查询。

catalog 是操作类型的唯一事实源：每个条目声明操作名、所用布局、可用变体
与参数 schema。框架代码不感知任何具体操作。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class OperationEntry(BaseModel):
    """catalog 中的一个操作类型条目。"""

    name: str
    summary: str = ""
    layout: str
    tier: str = "legit"
    variants: list[str] = Field(default_factory=lambda: ["normal"])
    params: dict[str, Any] = Field(default_factory=dict)
    func_code: int | None = None


class CatalogModel(BaseModel):
    """catalog.yaml 的结构。"""

    protocol: str
    operations: list[OperationEntry]


@dataclass(frozen=True)
class Catalog:
    """已加载的操作目录。"""

    protocol: str
    operations: dict[str, OperationEntry]

    def get(self, name: str) -> OperationEntry:
        """按操作名取条目，不存在时抛 KeyError。"""
        try:
            return self.operations[name]
        except KeyError as exc:
            raise KeyError(f"catalog {self.protocol!r} 中不存在操作 {name!r}") from exc

    def count(self) -> int:
        """操作类型数量。"""
        return len(self.operations)


def load_catalog(path: Path) -> Catalog:
    """从 YAML 文件加载 catalog。"""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    model = CatalogModel.model_validate(raw)
    operations = {entry.name: entry for entry in model.operations}
    if len(operations) != len(model.operations):
        raise ValueError(f"catalog {path} 中存在重复的操作名")
    return Catalog(protocol=model.protocol, operations=operations)
