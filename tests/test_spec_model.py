"""核心数据模型的语义层与变体映射规则。"""

import pytest

from icsgen.spec.model import VARIANT_TIER, Operation, Scenario, Tier, Variant


def test_variant_tier_mapping_is_complete():
    """每个变体都必须有确定的语义层归属。"""
    assert set(VARIANT_TIER) == set(Variant)
    assert VARIANT_TIER[Variant.NORMAL] is Tier.LEGIT
    assert VARIANT_TIER[Variant.BOUNDARY] is Tier.LEGIT
    assert VARIANT_TIER[Variant.EXCEPTION] is Tier.ABNORMAL
    assert VARIANT_TIER[Variant.ILLEGAL_FC] is Tier.ABNORMAL
    assert VARIANT_TIER[Variant.MALFORMED] is Tier.ABNORMAL


def test_tier_defaults_to_variant_mapping():
    """未显式声明 tier 时，tier 由 variant 推导。"""
    op = Operation(op="modbus.read_coils", variant=Variant.EXCEPTION)
    assert op.tier is Tier.ABNORMAL


def test_conflicting_tier_is_rejected():
    """显式 tier 与 variant 冲突时报错。"""
    with pytest.raises(ValueError, match="冲突"):
        Operation(op="modbus.read_coils", variant=Variant.NORMAL, tier=Tier.ABNORMAL)


def test_operation_defaults():
    op = Operation(op="modbus.read_coils")
    assert op.params == {}
    assert op.variant is Variant.NORMAL
    assert op.tier is Tier.LEGIT
    assert op.expect_response is True


def test_scenario_is_immutable_container():
    scenario = Scenario(name="demo", operations=(Operation(op="modbus.read_coils"),))
    assert scenario.operations[0].op == "modbus.read_coils"
    with pytest.raises(Exception):
        scenario.name = "other"  # type: ignore[misc]
