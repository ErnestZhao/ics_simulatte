"""catalog 加载与场景校验。"""

import pytest
import yaml

from icsgen.spec.catalog import Catalog, load_catalog
from icsgen.spec.loader import (
    ScenarioError,
    ScenarioOperationModel,
    load_scenario,
    validate_operations,
)
from icsgen.spec.model import Tier, Variant


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(yaml.safe_dump(content, allow_unicode=True), encoding="utf-8")
    return p


CATALOG = {
    "protocol": "demo",
    "operations": [
        {
            "name": "demo.read_holding",
            "summary": "读保持寄存器",
            "layout": "fc03",
            "variants": ["normal", "boundary"],
            "params": {
                "quantity": {"type": "integer", "minimum": 1, "maximum": 125, "default": 1}
            },
        }
    ],
}


def test_load_catalog(tmp_path):
    path = _write(tmp_path, "catalog.yaml", CATALOG)
    catalog = load_catalog(path)
    assert catalog.protocol == "demo"
    assert catalog.count() == 1
    entry = catalog.get("demo.read_holding")
    assert entry.layout == "fc03"
    assert entry.params["quantity"]["maximum"] == 125


def test_catalog_unknown_operation_raises(tmp_path):
    path = _write(tmp_path, "catalog.yaml", CATALOG)
    catalog = load_catalog(path)
    with pytest.raises(KeyError, match="不存在操作"):
        catalog.get("demo.nope")


def test_duplicate_operation_name_rejected(tmp_path):
    bad = {
        "protocol": "demo",
        "operations": [CATALOG["operations"][0], CATALOG["operations"][0]],
    }
    path = _write(tmp_path, "catalog.yaml", bad)
    with pytest.raises(ValueError, match="重复"):
        load_catalog(path)


def test_load_scenario_validates_params(tmp_path):
    cat_path = _write(tmp_path, "catalog.yaml", CATALOG)
    catalog = load_catalog(cat_path)
    scn_path = _write(
        tmp_path,
        "scenario.yaml",
        {
            "name": "s1",
            "operations": [{"op": "demo.read_holding", "params": {"quantity": 3}}],
        },
    )
    scenario = load_scenario(scn_path, catalog)
    assert scenario.name == "s1"
    assert scenario.operations[0].params == {"quantity": 3}
    assert scenario.operations[0].tier is Tier.LEGIT


def test_load_scenario_rejects_unknown_op(tmp_path):
    cat_path = _write(tmp_path, "catalog.yaml", CATALOG)
    catalog = load_catalog(cat_path)
    scn_path = _write(
        tmp_path,
        "scenario.yaml",
        {"name": "s1", "operations": [{"op": "demo.unknown"}]},
    )
    with pytest.raises(ScenarioError, match="不存在操作"):
        load_scenario(scn_path, catalog)


def test_load_scenario_rejects_out_of_range_param(tmp_path):
    cat_path = _write(tmp_path, "catalog.yaml", CATALOG)
    catalog = load_catalog(cat_path)
    scn_path = _write(
        tmp_path,
        "scenario.yaml",
        {"name": "s1", "operations": [{"op": "demo.read_holding", "params": {"quantity": 500}}]},
    )
    with pytest.raises(ScenarioError, match="参数校验失败"):
        load_scenario(scn_path, catalog)


def test_load_scenario_rejects_unsupported_variant(tmp_path):
    cat_path = _write(tmp_path, "catalog.yaml", CATALOG)
    catalog = load_catalog(cat_path)
    scn_path = _write(
        tmp_path,
        "scenario.yaml",
        {"name": "s1", "operations": [{"op": "demo.read_holding", "variant": "exception"}]},
    )
    with pytest.raises(ScenarioError, match="不支持的变体"):
        load_scenario(scn_path, catalog)


def test_load_scenario_rejects_unknown_param(tmp_path):
    """catalog 未声明的参数一律拒绝 —— catalog 是操作参数的唯一事实源。"""
    cat_path = _write(tmp_path, "catalog.yaml", CATALOG)
    catalog = load_catalog(cat_path)
    scn_path = _write(
        tmp_path,
        "scenario.yaml",
        {"name": "s1", "operations": [{"op": "demo.read_holding", "params": {"bogus": 1}}]},
    )
    with pytest.raises(ScenarioError, match="参数校验失败"):
        load_scenario(scn_path, catalog)


def test_load_scenario_rejects_tier_variant_conflict(tmp_path):
    """显式 tier 与 variant 冲突时按场景错误报告，而不是逃逸裸 ValueError。"""
    cat_path = _write(tmp_path, "catalog.yaml", CATALOG)
    catalog = load_catalog(cat_path)
    scn_path = _write(
        tmp_path,
        "scenario.yaml",
        {
            "name": "s1",
            "operations": [
                {"op": "demo.read_holding", "variant": "boundary", "tier": "abnormal"}
            ],
        },
    )
    with pytest.raises(ScenarioError, match="冲突"):
        load_scenario(scn_path, catalog)


def test_load_catalog_rejects_unknown_param_type(tmp_path):
    """catalog 里的参数 schema 引用未知类型时报错，而不是逃逸第三方异常。"""
    bad = {
        "protocol": "demo",
        "operations": [
            {
                "name": "demo.read_holding",
                "layout": "fc03",
                "params": {"quantity": {"type": "not-a-real-type"}},
            }
        ],
    }
    path = _write(tmp_path, "catalog.yaml", bad)
    with pytest.raises(ValueError, match="schema 非法"):
        load_catalog(path)


def test_load_catalog_rejects_non_object_param_schema(tmp_path):
    """catalog 里的参数 schema 不是对象时报错。"""
    bad = {
        "protocol": "demo",
        "operations": [
            {
                "name": "demo.read_holding",
                "layout": "fc03",
                "params": {"quantity": "integer"},
            }
        ],
    }
    path = _write(tmp_path, "catalog.yaml", bad)
    with pytest.raises(ValueError, match="必须是对象"):
        load_catalog(path)


def test_validate_operations_reports_unknown_op(tmp_path):
    cat_path = _write(tmp_path, "catalog.yaml", CATALOG)
    catalog = load_catalog(cat_path)
    items = [ScenarioOperationModel(op="demo.unknown")]
    with pytest.raises(ScenarioError, match="不存在操作"):
        validate_operations(catalog, items)


def test_validate_operations_reports_bad_param(tmp_path):
    cat_path = _write(tmp_path, "catalog.yaml", CATALOG)
    catalog = load_catalog(cat_path)
    items = [ScenarioOperationModel(op="demo.read_holding", params={"quantity": 500})]
    with pytest.raises(ScenarioError, match="参数校验失败"):
        validate_operations(catalog, items)


def test_validate_operations_rejects_unsupported_variant(tmp_path):
    cat_path = _write(tmp_path, "catalog.yaml", CATALOG)
    catalog = load_catalog(cat_path)
    items = [ScenarioOperationModel(op="demo.read_holding", variant=Variant.EXCEPTION)]
    with pytest.raises(ScenarioError, match="不支持的变体"):
        validate_operations(catalog, items)


def test_validate_operations_rejects_tier_variant_conflict(tmp_path):
    cat_path = _write(tmp_path, "catalog.yaml", CATALOG)
    catalog = load_catalog(cat_path)
    items = [
        ScenarioOperationModel(op="demo.read_holding", variant=Variant.BOUNDARY, tier=Tier.ABNORMAL)
    ]
    with pytest.raises(ScenarioError, match="冲突"):
        validate_operations(catalog, items)


def test_validate_operations_returns_operations(tmp_path):
    cat_path = _write(tmp_path, "catalog.yaml", CATALOG)
    catalog = load_catalog(cat_path)
    items = [ScenarioOperationModel(op="demo.read_holding", params={"quantity": 3})]
    operations = validate_operations(catalog, items)
    assert len(operations) == 1
    assert operations[0].params == {"quantity": 3}
    assert operations[0].tier is Tier.LEGIT


def test_validate_operations_context_appears_in_message(tmp_path):
    cat_path = _write(tmp_path, "catalog.yaml", CATALOG)
    catalog = load_catalog(cat_path)
    items = [ScenarioOperationModel(op="demo.unknown")]
    with pytest.raises(ScenarioError, match="提交的操作"):
        validate_operations(catalog, items, context="提交的操作")
