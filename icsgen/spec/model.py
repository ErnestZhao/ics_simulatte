"""核心数据模型：语义层、变体、操作与场景。

语义层（Tier）描述产物在数据集中的归属，变体（Variant）描述同一操作的
语义形态。两者是固定映射关系，场景中显式声明 tier 时必须与变体一致。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Tier(str, Enum):
    """数据集语义分层。"""

    LEGIT = "legit"
    ABNORMAL = "abnormal"
    MUTATED = "mutated"


class Variant(str, Enum):
    """同一操作的语义形态。"""

    NORMAL = "normal"
    BOUNDARY = "boundary"
    EXCEPTION = "exception"
    ILLEGAL_FC = "illegal_fc"
    MALFORMED = "malformed"


#: 变体到语义层的固定映射
VARIANT_TIER: dict[Variant, Tier] = {
    Variant.NORMAL: Tier.LEGIT,
    Variant.BOUNDARY: Tier.LEGIT,
    Variant.EXCEPTION: Tier.ABNORMAL,
    Variant.ILLEGAL_FC: Tier.ABNORMAL,
    Variant.MALFORMED: Tier.ABNORMAL,
}


@dataclass(frozen=True)
class Operation:
    """一次协议操作。

    tier 省略时由 variant 推导；显式声明且与 variant 冲突时构造即报错。
    """

    op: str
    params: dict[str, Any] = field(default_factory=dict)
    variant: Variant = Variant.NORMAL
    tier: Tier | None = None
    expect_response: bool = True

    def __post_init__(self) -> None:
        expected = VARIANT_TIER[self.variant]
        if self.tier is None:
            object.__setattr__(self, "tier", expected)
        elif self.tier != expected:
            raise ValueError(
                f"操作 {self.op!r} 的 variant={self.variant.value} 隐含 tier="
                f"{expected.value}，与显式声明的 {self.tier.value} 冲突"
            )


@dataclass(frozen=True)
class Scenario:
    """一个场景：一次有序的协议操作序列 + 传输层配置。"""

    name: str
    description: str = ""
    transport: dict[str, Any] = field(default_factory=dict)
    operations: tuple[Operation, ...] = ()
