"""分层数据集组装与 manifest。"""

import json

from icsgen.emit.dataset import Artifact, DatasetBuilder, write_dataset
from icsgen.transport.link import encapsulate
from icsgen.transport.spec import TransportSpec


def _artifact(op="modbus.read_holding_registers", tier="legit", payload=b"\x01\x02"):
    return Artifact(
        id=f"{op}#001",
        protocol="modbus",
        transport="tcp",
        op=op,
        variant="normal",
        tier=tier,
        payload=payload,
        metadata={"fc": 3},
    )


def test_write_dataset_creates_tier_directories(tmp_path):
    root = tmp_path / "ds"
    write_dataset("demo", root, [_artifact()], {})
    assert (root / "legit" / "modbus_tcp" / "frames" / "modbus.read_holding_registers#001.bin").exists()


def test_write_dataset_writes_manifest(tmp_path):
    root = tmp_path / "ds"
    write_dataset("demo", root, [_artifact()], {})
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["dataset"] == "demo"
    assert manifest["counts"]["legit"] == 1
    assert manifest["protocols"] == ["modbus"]
    assert manifest["artifacts"][0]["op"] == "modbus.read_holding_registers"
    assert manifest["artifacts"][0]["sha256"]
    assert manifest["artifacts"][0]["len"] == 2


def test_write_dataset_separates_tiers(tmp_path):
    root = tmp_path / "ds"
    write_dataset(
        "demo",
        root,
        [_artifact(tier="legit"), _artifact(op="modbus.write_coil", tier="abnormal")],
        {},
    )
    assert (root / "legit" / "modbus_tcp").is_dir()
    assert (root / "abnormal" / "modbus_tcp").is_dir()


def test_pcap_is_grouped_by_tier_and_transport(tmp_path):
    root = tmp_path / "ds"
    packet = encapsulate(b"\x01", TransportSpec())
    write_dataset(
        "demo",
        root,
        [_artifact(tier="legit"), _artifact(op="x.y", tier="abnormal")],
        {"legit/modbus_tcp": [packet], "abnormal/modbus_tcp": [packet]},
    )
    assert (root / "legit" / "modbus_tcp" / "session.pcap").exists()
    assert (root / "abnormal" / "modbus_tcp" / "session.pcap").exists()


def test_manifest_records_pcap_position(tmp_path):
    """manifest 记录产物所在的 pcap 文件与包序号。"""
    builder = DatasetBuilder("demo", tmp_path / "ds")
    builder.add(_artifact())
    builder.add_linked_packets(
        "modbus.read_holding_registers#001",
        [encapsulate(b"\x01", TransportSpec())],
    )
    root = builder.write()
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    entry = manifest["artifacts"][0]
    assert entry["pcap_file"] == "legit/modbus_tcp/session.pcap"
    assert entry["pcap_index"] == 0


def test_pcap_index_differs_within_one_session(tmp_path):
    """同一会话中的多条产物应有各自的包序号。"""
    builder = DatasetBuilder("demo", tmp_path / "ds")
    for index, op in enumerate(["modbus.read_coils", "modbus.write_coil", "modbus.read_hold"]):
        artifact_id = f"{op}#{index + 1:03d}"
        builder.add(
            Artifact(
                id=artifact_id,
                protocol="modbus",
                transport="tcp",
                op=op,
                variant="normal",
                tier="legit",
                payload=bytes([index]),
            )
        )
        builder.add_linked_packets(artifact_id, [encapsulate(b"\x01", TransportSpec())])
    root = builder.write()
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    indexes = [entry["pcap_index"] for entry in manifest["artifacts"]]
    assert indexes == [0, 1, 2]


def test_response_frame_is_written_and_indexed(tmp_path):
    """响应帧另存为 <id>.resp.bin，并在 manifest 里记录它在会话中的位置。"""
    builder = DatasetBuilder("demo", tmp_path / "ds")
    builder.add(
        Artifact(
            id="modbus.read_holding_registers#001",
            protocol="modbus",
            transport="tcp",
            op="modbus.read_holding_registers",
            variant="normal",
            tier="legit",
            payload=b"\x01\x03",
            response=b"\x01\x03\x06\x00",
        )
    )
    builder.add_linked_packets(
        "modbus.read_holding_registers#001",
        [encapsulate(b"\x01\x03", TransportSpec()), encapsulate(b"\x01\x03\x06\x00", TransportSpec().reversed())],
    )
    root = builder.write()
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    entry = manifest["artifacts"][0]
    assert entry["resp_len"] == 4
    assert entry["resp_sha256"]
    assert entry["pcap_index"] == 0
    assert entry["pcap_resp_index"] == 1
    frames = root / "legit" / "modbus_tcp" / "frames"
    assert (frames / "modbus.read_holding_registers#001.resp.bin").read_bytes() == b"\x01\x03\x06\x00"


def test_builder_collects_artifacts(tmp_path):
    builder = DatasetBuilder("demo", tmp_path / "ds")
    builder.add(_artifact())
    builder.add_linked_packets("modbus.read_holding_registers#001", [encapsulate(b"\x01", TransportSpec())])
    path = builder.write()
    assert (path / "manifest.json").exists()
