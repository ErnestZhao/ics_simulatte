"""变异规则集。

每条规则接收一串帧与随机数发生器，返回变异后的帧序列；返回 None 表示
该规则在当前输入上不适用（例如需要成对帧的规则遇到单帧）。

规则的输入是「一段会话的帧序列」：单帧规则只改首帧、其余帧原样保留；
成对规则（重放、交错）重排整段会话。单帧调用方用 mutate_frames 的
frames=[单帧] 形式即可，语义与多帧一致。

帧序列的约定是「请求在前、应答在后」：成对规则产生的新帧一律追加在
末尾，这样请求帧与应答帧的位置不会漂移，产物才能与源产物一一对应。
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable, Sequence

#: 规则作用于会话的首帧
FrameRule = Callable[[bytes, random.Random], bytes | None]

#: 规则作用于整段会话，返回变异后的帧序列
SessionRule = Callable[[Sequence[bytes], random.Random], Sequence[bytes] | None]


@dataclass(frozen=True)
class MutationRule:
    """一条变异规则。"""

    name: str
    description: str
    apply: SessionRule


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


def _single_frame(rule: FrameRule) -> SessionRule:
    """把作用在单帧上的规则包成作用于整段会话的规则。

    只改首帧，其余帧原样保留 —— 变异的是这次交互的请求，响应仍是设备
    对合法请求的正常应答。
    """

    def apply(frames: Sequence[bytes], rng: random.Random) -> Sequence[bytes] | None:
        if not frames:
            return None
        mutated = rule(frames[0], rng)
        if mutated is None:
            return None
        return [mutated, *frames[1:]]

    return apply


def _duplicate_replay(frames: Sequence[bytes], rng: random.Random) -> Sequence[bytes] | None:
    """重放：在会话末尾把首帧原样再发一次。

    客户端拿到应答后重放同一请求，是重放攻击的典型形态。首帧追加到末尾
    而不是插到最前，请求帧与应答帧的相对位置保持不变。

    需要成对输入：单帧没有可重放的上下文。
    """
    if len(frames) < 2:
        return None
    return [*frames, frames[0]]


def _interleave_frames(frames: Sequence[bytes], rng: random.Random) -> Sequence[bytes] | None:
    """交错：前两帧的字节轮流出现，合并成一帧。

    交错破坏了两帧的边界，合并后的帧不再能拆回请求与应答，其余帧原样
    保留。

    需要成对输入：单帧没有可交错的另一帧。
    """
    if len(frames) < 2:
        return None
    out = bytearray()
    for group in zip(frames[0], frames[1]):
        out += bytes(group)
    return [bytes(out), *frames[2:]]


RULES: dict[str, MutationRule] = {
    rule.name: rule
    for rule in (
        MutationRule("bit_flip", "翻转随机 bit", _single_frame(_bit_flip)),
        MutationRule("byte_flip", "随机字节取反", _single_frame(_byte_flip)),
        MutationRule("byte_set", "随机字节替换为随机值", _single_frame(_byte_set)),
        MutationRule("truncate", "截断到随机长度", _single_frame(_truncate)),
        MutationRule("extend_garbage", "追加随机垃圾字节", _single_frame(_extend_garbage)),
        MutationRule(
            "length_field_corrupt", "篡改长度字段", _single_frame(_length_field_corrupt)
        ),
        MutationRule("func_code_corrupt", "篡改功能码", _single_frame(_func_code_corrupt)),
        MutationRule("address_corrupt", "篡改地址字段", _single_frame(_address_corrupt)),
        MutationRule("value_extreme", "数值置为极值", _single_frame(_value_extreme)),
        MutationRule("crc_corrupt", "破坏 CRC 字节", _single_frame(_crc_corrupt)),
        MutationRule("duplicate_replay", "复制帧形成重放", _duplicate_replay),
        MutationRule("interleave_frames", "交错两帧", _interleave_frames),
    )
}

#: 全部规则名，按定义顺序
RULE_NAMES: tuple[str, ...] = tuple(RULES)
