"""变异引擎：规则集与确定性。"""

import pytest

from icsgen.mutate.engine import mutate
from icsgen.mutate.rules import RULE_NAMES


def test_rule_set_has_twelve_rules():
    assert len(RULE_NAMES) == 12


def test_mutate_is_deterministic_for_same_seed():
    payload = bytes(range(20))
    first = mutate(payload, ["all"], seed=42)
    second = mutate(payload, ["all"], seed=42)
    assert [m.payload for m in first] == [m.payload for m in second]


def test_mutate_differs_across_seeds():
    payload = bytes(range(20))
    first = mutate(payload, ["all"], seed=1)
    second = mutate(payload, ["all"], seed=2)
    assert [m.payload for m in first] != [m.payload for m in second]


def test_every_rule_produces_a_mutation():
    """单帧适用的每条规则都应产生变异。

    duplicate_replay 与 interleave_frames 需要成对输入，单帧时不适用，
    单独断言其返回空结果。
    """
    payload = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x03"
    paired_only = {"duplicate_replay", "interleave_frames"}
    for name in RULE_NAMES:
        results = mutate(payload, [name], seed=7)
        if name in paired_only:
            assert results == [], f"规则 {name} 在单帧输入下应返回空结果"
            continue
        assert results, f"规则 {name} 未产生任何变异"
        assert all(m.rule == name for m in results)


def test_mutation_records_original_hash():
    import hashlib

    payload = b"\x01\x02\x03"
    result = mutate(payload, ["bit_flip"], seed=1)[0]
    assert result.original_sha256 == hashlib.sha256(payload).hexdigest()


def test_truncate_shortens_payload():
    payload = bytes(range(20))
    result = mutate(payload, ["truncate"], seed=3)[0]
    assert len(result.payload) < len(payload)


def test_func_code_corrupt_changes_first_byte():
    payload = b"\x03\x00\x00\x00\x03"
    result = mutate(payload, ["func_code_corrupt"], seed=5)[0]
    assert result.payload[0] != 0x03


def test_mutated_payload_differs_from_original():
    payload = bytes(range(20))
    for result in mutate(payload, ["all"], seed=9):
        assert result.payload != payload


def test_unknown_rule_raises():
    with pytest.raises(KeyError):
        mutate(b"\x00", ["no_such_rule"], seed=1)
