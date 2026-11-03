"""Web 层的请求体模型。

只依赖 pydantic —— 服务层要用它们，HTTP 层也要用它们。
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class OperationInput(BaseModel):
    """表单里的一条操作选择。"""

    op: str
    variant: str = "normal"
    params: dict[str, Any] = Field(default_factory=dict)
    count: int = 1


class ConfigPayload(BaseModel):
    """保存配置的请求体。"""

    name: str
    protocol: str = "modbus"
    transport: dict[str, Any] = Field(default_factory=dict)
    operations: list[OperationInput]


class GenerationPayload(BaseModel):
    """发起生成的请求体。"""

    config_id: str
