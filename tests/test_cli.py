"""命令行界面。"""

import json

from typer.testing import CliRunner

from icsgen.cli import app

runner = CliRunner()


def test_catalog_count_reports_number():
    """--count 输出覆盖条目数，是 §15 丰富度指标的 CI 口径。"""
    result = runner.invoke(app, ["catalog", "--protocol", "modbus", "--count"])
    assert result.exit_code == 0, result.output
    count = int(result.stdout.strip())
    assert count >= 90


def test_ops_list_lists_operation_names():
    result = runner.invoke(app, ["ops", "list", "--protocol", "modbus"])
    assert result.exit_code == 0, result.output
    assert "modbus.read_holding_registers" in result.stdout


def test_ops_list_json_output_is_parseable():
    result = runner.invoke(app, ["ops", "list", "--protocol", "modbus", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert any(item["name"] == "modbus.read_coils" for item in data)


def test_ops_show_prints_summary():
    result = runner.invoke(app, ["ops", "show", "modbus.read_holding_registers"])
    assert result.exit_code == 0, result.output
    assert "读保持寄存器" in result.stdout


def test_validate_rejects_bad_scenario(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("name: bad\noperations:\n  - op: modbus.not_exists\n", encoding="utf-8")
    result = runner.invoke(app, ["validate", str(bad)])
    assert result.exit_code != 0
    assert "不存在操作" in result.output


def test_generate_writes_dataset(tmp_path):
    scenario = tmp_path / "s.yaml"
    scenario.write_text(
        "name: demo\ntransport:\n  kind: tcp\noperations:\n"
        "  - op: modbus.read_holding_registers\n    params: {quantity: 3}\n",
        encoding="utf-8",
    )
    out = tmp_path / "ds"
    result = runner.invoke(app, ["generate", str(scenario), "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert (out / "manifest.json").exists()


def test_mutate_creates_mutated_tier(tmp_path):
    scenario = tmp_path / "s.yaml"
    scenario.write_text(
        "name: demo\ntransport:\n  kind: tcp\noperations:\n"
        "  - op: modbus.read_holding_registers\n    params: {quantity: 3}\n",
        encoding="utf-8",
    )
    src = tmp_path / "ds"
    runner.invoke(app, ["generate", str(scenario), "-o", str(src)])
    dst = tmp_path / "fuzz"
    result = runner.invoke(
        app, ["mutate", str(src), "-o", str(dst), "--rules", "all", "--seed", "42"]
    )
    assert result.exit_code == 0, result.output
    assert (dst / "manifest.json").exists()
    manifest = json.loads((dst / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["counts"].get("mutated", 0) > 0
