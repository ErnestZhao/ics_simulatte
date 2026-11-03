"""变异规则集。

每条规则接收原始字节与随机数发生器，返回变异后的字节；返回 None 表示
该规则在当前输入上不适用（例如需要成对帧的规则遇到单帧）。
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable, Sequence


@dataclass(frozen=True)
class MutationRule:
    """一条变异规则。"""

    name: str
    description: str
    apply: Callable[[bytes, random.Random], bytes | None]


def _different_value(current: int, rng: random.Random, candidates: Sequence[int]) -> int:
    """从候选值里挑一个与 current 不同的值。

    变异规则必须真的改变字节 —— 若写回的值与原值相同，引擎会把它当作
    「没有变化」丢弃，这条规则就等于没生效。因此凡是「写某个字节」的
    规则都要先排除原值。
    """
    return rng.choice([value for value in candidates if value != current])


def _bit_flip(data: bytes, rng: random.Random) -> bytes | None:
    if not data:
        return None
    buf = bytearray(data)
    index = rng.randrange(len(buf))
    bit = rng.randrange(8)
    buf[index] ^= 1 << bit
    return bytes(buf)


def _byte_flip(data: bytes, rng: random.Random) -> bytes | None:
    if not data:
        return None
    buf = bytearray(data)
    buf[rng.randrange(len(buf))] ^= 0xFF
    return bytes(buf)


def _byte_set(data: bytes, rng: random.Random) -> bytes | None:
    if not data:
        return None
    buf = bytearray(data)
    index = rng.randrange(len(buf))
    buf[index] = _different_value(buf[index], rng, range(256))
    return bytes(buf)


def _truncate(data: bytes, rng: random.Random) -> bytes | None:
    if len(data) < 2:
        return None
    return data[: rng.randrange(1, len(data))]


def _extend_garbage(data: bytes, rng: random.Random) -> bytes | None:
    extra = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 16)))
    return data + extra


def _length_field_corrupt(data: bytes, rng: random.Random) -> bytes | None:
    """篡改 Modbus MBAP 头的长度字段（第 4-5 字节）。"""
    if len(data) < 6:
        return None
    buf = bytearray(data)
    current = int.from_bytes(buf[4:6], "big")
    value = _different_value(current, rng, range(0x10000))
    buf[4:6] = value.to_bytes(2, "big")
    return bytes(buf)


def _func_code_corrupt(data: bytes, rng: random.Random) -> bytes | None:
    """篡改功能码字节。"""
    if not data:
        return None
    buf = bytearray(data)
    buf[0] = _different_value(buf[0], rng, range(1, 256))
    return bytes(buf)


def _address_corrupt(data: bytes, rng: random.Random) -> bytes | None:
    """篡改地址字段（第 2-3 字节）。"""
    if len(data) < 4:
        return None
    buf = bytearray(data)
    current = int.from_bytes(buf[2:4], "big")
    value = _different_value(current, rng, range(0x10000))
    buf[2:4] = value.to_bytes(2, "big")
    return bytes(buf)


def _value_extreme(data: bytes, rng: random.Random) -> bytes | None:
    """把某字节置为极值。"""
    if not data:
        return None
    buf = bytearray(data)
    index = rng.randrange(len(buf))
    buf[index] = _different_value(buf[index], rng, (0x00, 0xFF, 0x7F, 0x80))
    return bytes(buf)


def _crc_corrupt(data: bytes, rng: random.Random) -> bytes | None:
    """破坏尾部 CRC 字节。"""
    if len(data) < 3:
        return None
    buf = bytearray(data)
    buf[-1] ^= 0xFF
    return bytes(buf)


def _duplicate_replay(data: bytes, rng: random.Random) -> bytes | None:
    """复制整帧形成重放，需要成对输入，单帧时不适用。"""
    return None


def _interleave_frames(data: bytes, rng: random.Random) -> bytes | None:
    """交错两帧，需要成对输入，单帧时不适用。"""
    return None


RULES: dict[str, MutationRule] = {
    rule.name: rule
    for rule in (
        MutationRule("bit_flip", "翻转随机 bit", _bit_flip),
        MutationRule("byte_flip", "随机字节取反", _byte_flip),
        MutationRule("byte_set", "随机字节替换为随机值", _byte_set),
        MutationRule("truncate", "截断到随机长度", _truncate),
        MutationRule("extend_garbage", "追加随机垃圾字节", _extend_garbage),
        MutationRule("length_field_corrupt", "篡改长度字段", _length_field_corrupt),
        MutationRule("func_code_corrupt", "篡改功能码", _func_code_corrupt),
        MutationRule("address_corrupt", "篡改地址字段", _address_corrupt),
        MutationRule("value_extreme", "数值置为极值", _value_extreme),
        MutationRule("crc_corrupt", "破坏 CRC 字节", _crc_corrupt),
        MutationRule("duplicate_replay", "复制帧形成重放", _duplicate_replay),
        MutationRule("interleave_frames", "交错两帧", _interleave_frames),
    )
}

#: 全部规则名，按定义顺序
RULE_NAMES: tuple[str, ...] = tuple(RULES)
