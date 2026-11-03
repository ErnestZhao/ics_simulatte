"""变异引擎：对合法报文做确定性变异。

同一 seed 与同一输入必得同一输出，产物带溯源信息（规则名、seed、偏移、
原始哈希）。
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass

from .rules import RULES, RULE_NAMES


@dataclass(frozen=True)
class MutatedFrame:
    """一条变异产物。"""

    payload: bytes
    rule: str
    seed: int
    offset: int
    original_sha256: str


def mutate(payload: bytes, rules: list[str], seed: int) -> list[MutatedFrame]:
    """对 payload 应用给定规则，返回全部变异结果。

    rules 中的 "all" 表示应用全部规则。规则名未知时抛 KeyError。
    """
    selected = list(RULE_NAMES) if "all" in rules else list(rules)
    for name in selected:
        if name not in RULES:
            raise KeyError(f"不存在变异规则 {name!r}，可用规则：{list(RULE_NAMES)}")

    original_hash = hashlib.sha256(payload).hexdigest()
    results: list[MutatedFrame] = []

    for name in selected:
        rule = RULES[name]
        rng = random.Random(f"{seed}:{name}")
        mutated = rule.apply(payload, rng)
        if mutated is None or mutated == payload:
            continue
        offset = _first_difference(payload, mutated)
        results.append(
            MutatedFrame(
                payload=mutated,
                rule=name,
                seed=seed,
                offset=offset,
                original_sha256=original_hash,
            )
        )
    return results


def _first_difference(original: bytes, mutated: bytes) -> int:
    """返回第一个不同的字节偏移，全同则为 0。"""
    for index, (a, b) in enumerate(zip(original, mutated)):
        if a != b:
            return index
    return min(len(original), len(mutated))
