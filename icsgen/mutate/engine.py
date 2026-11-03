"""变异引擎：对合法报文做确定性变异。

同一 seed 与同一输入必得同一输出，产物带溯源信息（规则名、seed、偏移、
原始哈希）。

变异的对象是一段会话的帧序列：单帧规则只改首帧，成对规则（重放、交错）
重排整段会话。溯源信息按整段会话的字节流计算。
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass
from typing import Sequence

from .rules import RULES, RULE_NAMES


@dataclass(frozen=True)
class MutatedFrame:
    """一条变异产物。

    frames 是变异后整段会话的帧序列：请求在前、应答在后。
    """

    frames: tuple[bytes, ...]
    rule: str
    seed: int
    offset: int
    original_sha256: str

    @property
    def payload(self) -> bytes:
        """变异后的首帧。"""
        return self.frames[0]


def mutate(payload: bytes, rules: list[str], seed: int) -> list[MutatedFrame]:
    """对单个帧应用给定规则，返回全部变异结果。

    需要成对帧的规则（重放、交错）在单帧输入下不适用。
    """
    return mutate_frames([payload], rules, seed)


def mutate_frames(
    frames: Sequence[bytes], rules: list[str], seed: int
) -> list[MutatedFrame]:
    """对一段会话的帧应用给定规则，返回全部变异结果。

    rules 中的 "all" 表示应用全部规则。规则名未知时抛 KeyError。
    """
    selected = list(RULE_NAMES) if "all" in rules else list(rules)
    for name in selected:
        if name not in RULES:
            raise KeyError(f"不存在变异规则 {name!r}，可用规则：{list(RULE_NAMES)}")

    original = b"".join(frames)
    original_hash = hashlib.sha256(original).hexdigest()
    results: list[MutatedFrame] = []

    for name in selected:
        rule = RULES[name]
        rng = random.Random(f"{seed}:{name}")
        mutated = rule.apply(frames, rng)
        if mutated is None:
            continue
        mutated_frames = tuple(mutated)
        if not mutated_frames:
            continue
        mutated_bytes = b"".join(mutated_frames)
        if mutated_bytes == original:
            continue
        offset = _first_difference(original, mutated_bytes)
        results.append(
            MutatedFrame(
                frames=mutated_frames,
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
