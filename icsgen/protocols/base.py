"""协议适配器的公共契约。

适配器只负责协议层的语义 —— 由 catalog 声明的操作与字段布局如何变成
协议帧。它不涉及 IP/TCP/以太等链路封装。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol

from ..spec.model import Operation


@dataclass(frozen=True)
class BuildContext:
    """构建协议帧时的会话级上下文。"""

    transaction_id: int = 0
    unit_id: int = 0xFF
    transport: str = "tcp"
    seed: int = 0


@dataclass(frozen=True)
class ProtocolFrame:
    """一条协议帧及其语义元数据。"""

    payload: bytes
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OperationSpec:
    """一个操作类型在适配器侧的描述。"""

    name: str
    summary: str
    layout: str
    variants: tuple[str, ...]
    params_schema: dict[str, Any]


@dataclass(frozen=True)
class FrameField:
    """帧的一个字段及其显示值。"""

    name: str
    value: str


@dataclass(frozen=True)
class FrameView:
    """一帧的协议级解析结果。

    summary 是一行摘要，fields 是逐字段的解析结果。解析失败时只给摘要，
    fields 为空 —— 畸形帧本就是数据集的一部分，预览不该因此失败。
    """

    summary: str
    fields: tuple[FrameField, ...] = ()
    is_exception: bool = False
    exception_code: int | None = None


class ProtocolAdapter(Protocol):
    """协议适配器契约。"""

    name: str
    operations: Mapping[str, OperationSpec]

    def build(self, op: Operation, ctx: BuildContext) -> ProtocolFrame: ...

    def build_response(self, op: Operation, ctx: BuildContext) -> ProtocolFrame | None: ...

    def inspect(self, op: str, payload: bytes, ctx: BuildContext, direction: str) -> FrameView:
        """解析一帧，direction 取 "request" 或 "response"。

        op 是操作名，用于定位字段布局 —— 不能按功能码反查布局：catalog 中
        多个操作共享功能码（21 个诊断子功能共享 fc08）。
        """
        ...
