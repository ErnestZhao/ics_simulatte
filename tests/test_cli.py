"""命令行界面。"""

import json

from scapy.all import IP
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


def test_manifest_records_transport_spec(tmp_path):
    """传输层参数写进 manifest，变异数据集据此还原链路封装。"""
    scenario = tmp_path / "s.yaml"
    scenario.write_text(
        "name: demo\ntransport:\n  kind: tcp\n  src_ip: 10.0.0.1\n"
        "  dst_ip: 10.0.0.2\n  dport: 502\noperations:\n"
        "  - op: modbus.read_holding_registers\n    params: {quantity: 3}\n",
        encoding="utf-8",
    )
    out = tmp_path / "ds"
    runner.invoke(app, ["generate", str(scenario), "-o", str(out)])
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["transport"]["kind"] == "tcp"
    assert manifest["transport"]["src_ip"] == "10.0.0.1"
    assert manifest["transport"]["dst_ip"] == "10.0.0.2"
    assert manifest["transport"]["dport"] == 502


def test_mutated_tier_has_session_pcap(tmp_path):
    """变异层与其它层结构一致：也要有 session.pcap。"""
    from scapy.all import rdpcap

    scenario = tmp_path / "s.yaml"
    scenario.write_text(
        "name: demo\ntransport:\n  kind: tcp\n  src_ip: 10.0.0.1\n"
        "  dst_ip: 10.0.0.2\noperations:\n"
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
    manifest = json.loads((dst / "manifest.json").read_text(encoding="utf-8"))
    pcap = dst / "mutated" / "modbus_tcp" / "session.pcap"
    assert pcap.exists()
    packets = rdpcap(str(pcap))
    expected = sum(entry["pcap_frame_count"] for entry in manifest["artifacts"])
    assert len(packets) == expected
    # 链路参数沿用源数据集
    assert packets[0][IP].src == "10.0.0.1"
    assert packets[0][IP].dst == "10.0.0.2"


def test_mutated_artifact_points_at_its_packet(tmp_path):
    """manifest 里能定位到变异产物所在的包。"""
    from scapy.all import TCP, rdpcap

    scenario = tmp_path / "s.yaml"
    scenario.write_text(
        "name: demo\ntransport:\n  kind: tcp\noperations:\n"
        "  - op: modbus.read_holding_registers\n    params: {quantity: 3}\n",
        encoding="utf-8",
    )
    src = tmp_path / "ds"
    runner.invoke(app, ["generate", str(scenario), "-o", str(src)])
    dst = tmp_path / "fuzz"
    runner.invoke(app, ["mutate", str(src), "-o", str(dst), "--rules", "all", "--seed", "42"])
    manifest = json.loads((dst / "manifest.json").read_text(encoding="utf-8"))
    packets = rdpcap(str(dst / "mutated" / "modbus_tcp" / "session.pcap"))
    frames = dst / "mutated" / "modbus_tcp" / "frames"
    for entry in manifest["artifacts"]:
        assert entry["pcap_file"] == "mutated/modbus_tcp/session.pcap"
        assert entry["mutation"]["rule"]
        assert entry["parent_id"]
        request = (frames / f"{entry['id']}.bin").read_bytes()
        assert bytes(packets[entry["pcap_index"]][TCP].payload) == request
        if "pcap_resp_index" in entry:
            response = (frames / f"{entry['id']}.resp.bin").read_bytes()
            assert bytes(packets[entry["pcap_resp_index"]][TCP].payload) == response


def test_replay_rule_adds_a_third_packet(tmp_path):
    """重放规则在会话末尾追加一帧，产物记录三帧。"""
    from scapy.all import TCP, rdpcap

    scenario = tmp_path / "s.yaml"
    scenario.write_text(
        "name: demo\ntransport:\n  kind: tcp\noperations:\n"
        "  - op: modbus.read_holding_registers\n    params: {quantity: 3}\n",
        encoding="utf-8",
    )
    src = tmp_path / "ds"
    runner.invoke(app, ["generate", str(scenario), "-o", str(src)])
    dst = tmp_path / "fuzz"
    runner.invoke(
        app,
        ["mutate", str(src), "-o", str(dst), "--rules", "duplicate_replay", "--seed", "1"],
    )
    manifest = json.loads((dst / "manifest.json").read_text(encoding="utf-8"))
    entry = manifest["artifacts"][0]
    assert entry["pcap_frame_count"] == 3
    packets = rdpcap(str(dst / "mutated" / "modbus_tcp" / "session.pcap"))
    assert len(packets) == 3
    # 重放的是原请求帧
    request = (dst / "mutated" / "modbus_tcp" / "frames" / f"{entry['id']}.bin").read_bytes()
    assert bytes(packets[2][TCP].payload) == request


def test_serial_dataset_pcap_uses_linux_sll(tmp_path):
    """串口传输的 pcap 以 Linux SLL 记录，帧体是裸协议字节。"""
    scenario = tmp_path / "s.yaml"
    scenario.write_text(
        "name: demo\ntransport:\n  kind: serial\noperations:\n"
        "  - op: modbus.read_holding_registers\n    params: {quantity: 3}\n",
        encoding="utf-8",
    )
    src = tmp_path / "ds"
    runner.invoke(app, ["generate", str(scenario), "-o", str(src)])
    dst = tmp_path / "fuzz"
    runner.invoke(app, ["mutate", str(src), "-o", str(dst), "--rules", "all", "--seed", "42"])
    for pcap in (src / "legit" / "modbus_rtu" / "session.pcap", dst / "mutated" / "modbus_rtu" / "session.pcap"):
        assert pcap.exists()
        # pcap 全局头第 20 字节起是链路类型
        assert int.from_bytes(pcap.read_bytes()[20:24], "little") == 113
    manifest = json.loads((dst / "manifest.json").read_text(encoding="utf-8"))
    entry = manifest["artifacts"][0]
    raw = (dst / "mutated" / "modbus_rtu" / "frames" / f"{entry['id']}.bin").read_bytes()
    data = (dst / "mutated" / "modbus_rtu" / "session.pcap").read_bytes()
    # SLL 头 16 字节之后是裸协议帧
    assert raw in data
