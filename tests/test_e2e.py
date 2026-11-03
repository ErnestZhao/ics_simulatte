"""端到端：场景 → 数据集 → 校验。"""

import json
from pathlib import Path

from scapy.all import IP, rdpcap

from icsgen.generator import build_dataset
from icsgen.protocols.modbus.adapter import load_modbus_adapter
from icsgen.spec.catalog import load_catalog
from icsgen.spec.loader import load_scenario

ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "icsgen" / "protocols" / "modbus" / "catalog.yaml"
SCENARIO_PATH = ROOT / "scenarios" / "modbus_demo.yaml"


def test_demo_scenario_loads():
    catalog = load_catalog(CATALOG_PATH)
    scenario = load_scenario(SCENARIO_PATH, catalog)
    assert scenario.name == "modbus_demo"
    assert len(scenario.operations) >= 4


def test_demo_scenario_covers_both_tiers():
    catalog = load_catalog(CATALOG_PATH)
    scenario = load_scenario(SCENARIO_PATH, catalog)
    tiers = {op.tier.value for op in scenario.operations}
    assert "legit" in tiers
    assert "abnormal" in tiers


def test_end_to_end_dataset_is_consistent(tmp_path):
    catalog = load_catalog(CATALOG_PATH)
    scenario = load_scenario(SCENARIO_PATH, catalog)
    adapter = load_modbus_adapter()
    root = build_dataset(scenario, adapter, tmp_path / "ds", name=scenario.name)

    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["counts"]["legit"] >= 2
    assert manifest["counts"]["abnormal"] >= 1

    for entry in manifest["artifacts"]:
        frame = root / entry["tier"] / f"{entry['protocol']}_{entry['transport']}" / "frames" / f"{entry['id']}.bin"
        assert frame.exists(), f"缺少帧文件 {frame}"
        assert frame.stat().st_size == entry["len"]


def test_generated_pcap_is_parseable(tmp_path):
    catalog = load_catalog(CATALOG_PATH)
    scenario = load_scenario(SCENARIO_PATH, catalog)
    adapter = load_modbus_adapter()
    root = build_dataset(scenario, adapter, tmp_path / "ds", name=scenario.name)

    pcap = root / "legit" / "modbus_tcp" / "session.pcap"
    assert pcap.exists()
    packets = rdpcap(str(pcap))
    assert len(packets) >= 2
    # 请求与响应方向相反：响应由服务端发回客户端
    assert packets[0][IP].src == packets[1][IP].dst
    assert packets[0][IP].dst == packets[1][IP].src


def test_session_pairs_requests_with_responses(tmp_path):
    """一次操作在会话里是连续的请求与响应两包，响应帧也单独落盘。"""
    catalog = load_catalog(CATALOG_PATH)
    scenario = load_scenario(SCENARIO_PATH, catalog)
    adapter = load_modbus_adapter()
    root = build_dataset(scenario, adapter, tmp_path / "ds", name=scenario.name)

    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    # 示例场景里没有畸形帧，每条操作都有响应
    for entry in manifest["artifacts"]:
        assert entry["pcap_resp_index"] == entry["pcap_index"] + 1
        assert entry["resp_len"] > 0
        frames = root / entry["tier"] / f"{entry['protocol']}_{entry['transport']}" / "frames"
        assert (frames / f"{entry['id']}.resp.bin").exists()


def test_operation_type_count_meets_floor():
    """覆盖条目数不得低于下限（CI 防退化）。"""
    catalog = load_catalog(CATALOG_PATH)
    assert catalog.coverage_count() >= 90, f"覆盖条目数 {catalog.coverage_count()} 低于下限 90"
