"""Modbus 适配器与生成流水线。"""

import json
from pathlib import Path

from icsgen.generator import build_dataset
from icsgen.protocols.modbus.adapter import load_modbus_adapter
from icsgen.spec.catalog import load_catalog
from icsgen.spec.loader import load_scenario
from icsgen.spec.model import Scenario, Tier, Variant

CATALOG_PATH = Path(__file__).resolve().parents[1] / "icsgen" / "protocols" / "modbus" / "catalog.yaml"


def _catalog():
    return load_catalog(CATALOG_PATH)


def test_adapter_exposes_catalog_entries():
    adapter = load_modbus_adapter()
    catalog = _catalog()
    assert adapter.name == "modbus"
    assert set(adapter.operations) == set(catalog.operations)


def test_build_request_frame_starts_with_mbap():
    from icsgen.protocols.base import BuildContext
    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    op = Operation(op="modbus.read_holding_registers", params={"start_addr": 0, "quantity": 3})
    frame = adapter.build(op, BuildContext(transaction_id=1, unit_id=0xFF))
    assert frame.payload[:7] == b"\x00\x01\x00\x00\x00\x06\xff"
    assert frame.payload[7] == 0x03
    assert frame.metadata["fc"] == 3


def test_build_exception_variant_marks_metadata():
    from icsgen.protocols.base import BuildContext
    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    op = Operation(
        op="modbus.read_holding_registers",
        params={"quantity": 3},
        variant=Variant.EXCEPTION,
    )
    frame = adapter.build(op, BuildContext())
    assert frame.metadata["is_exception"] is True
    assert frame.metadata["exception_code"] == 2


def test_build_rtu_variant_produces_crc():
    from icsgen.protocols.base import BuildContext
    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    op = Operation(op="modbus.read_holding_registers", params={"quantity": 3})
    frame = adapter.build(op, BuildContext(transport="rtu"))
    assert frame.metadata["transport"] == "rtu"
    from icsgen.protocols.modbus.framing import parse_rtu

    parsed = parse_rtu(frame.payload)
    assert parsed["pdu"][0] == 0x03


def test_build_dataset_writes_manifest_and_frames(tmp_path):
    adapter = load_modbus_adapter()
    scenario = Scenario(
        name="demo",
        transport={"kind": "tcp"},
        operations=(),
    )
    from icsgen.spec.model import Operation

    scenario = Scenario(
        name="demo",
        transport={"kind": "tcp"},
        operations=(
            Operation(op="modbus.read_holding_registers", params={"quantity": 3}),
            Operation(op="modbus.write_multiple_registers", params={"quantity": 2}),
        ),
    )
    root = build_dataset(scenario, adapter, tmp_path / "ds", name="demo")
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["counts"]["legit"] == 2
    assert len(manifest["artifacts"]) == 2
    assert (root / "legit" / "modbus_tcp" / "frames").is_dir()


def test_build_dataset_separates_abnormal_tier(tmp_path):
    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    scenario = Scenario(
        name="demo",
        transport={"kind": "tcp"},
        operations=(
            Operation(op="modbus.read_holding_registers", params={"quantity": 3}),
            Operation(
                op="modbus.read_holding_registers",
                params={"quantity": 3},
                variant=Variant.EXCEPTION,
            ),
        ),
    )
    root = build_dataset(scenario, adapter, tmp_path / "ds", name="demo")
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["counts"]["legit"] == 1
    assert manifest["counts"]["abnormal"] == 1
    assert (root / "abnormal" / "modbus_tcp" / "frames").is_dir()


def test_build_response_returns_normal_response():
    """正常变体的响应是 FC03 的正常响应：byte_count + 寄存器数据。"""
    from icsgen.protocols.base import BuildContext
    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    op = Operation(op="modbus.read_holding_registers", params={"start_addr": 0, "quantity": 3})
    frame = adapter.build_response(op, BuildContext(transaction_id=1, unit_id=0xFF))
    assert frame is not None
    assert frame.payload[:7] == b"\x00\x01\x00\x00\x00\x09\xff"
    assert frame.payload[7] == 0x03
    assert frame.payload[8] == 6


def test_build_response_returns_exception_response():
    """异常变体的响应是 FC|0x80 + 异常码。"""
    from icsgen.protocols.base import BuildContext
    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    op = Operation(
        op="modbus.read_holding_registers",
        params={"quantity": 3},
        variant=Variant.EXCEPTION,
    )
    frame = adapter.build_response(op, BuildContext(transaction_id=1, unit_id=0xFF))
    assert frame is not None
    assert frame.payload[7] == 0x83
    assert frame.payload[8] == 0x02


def test_malformed_variant_has_no_response():
    """畸形帧没有可解析的响应。"""
    from icsgen.protocols.base import BuildContext
    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    op = Operation(
        op="modbus.read_holding_registers",
        params={"quantity": 3},
        variant=Variant.MALFORMED,
    )
    assert adapter.build_response(op, BuildContext()) is None


def test_dataset_pairs_request_and_response(tmp_path):
    """一次操作在 pcap 里是连续的请求与响应两包。"""
    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    scenario = Scenario(
        name="demo",
        transport={"kind": "tcp"},
        operations=(Operation(op="modbus.read_holding_registers", params={"quantity": 3}),),
    )
    root = build_dataset(scenario, adapter, tmp_path / "ds", name="demo")
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    entry = manifest["artifacts"][0]
    assert entry["pcap_index"] == 3
    assert entry["pcap_resp_index"] == 4
    assert entry["resp_len"] > 0
    frames = root / "legit" / "modbus_tcp" / "frames"
    assert (frames / f"{entry['id']}.resp.bin").exists()


def test_progress_callback_reports_every_interaction(tmp_path):
    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    scenario = Scenario(
        name="demo",
        transport={"kind": "tcp"},
        operations=(
            Operation(op="modbus.read_holding_registers", params={"quantity": 3}),
            Operation(op="modbus.write_multiple_registers", params={"quantity": 2}),
        ),
    )
    seen = []
    build_dataset(
        scenario, adapter, tmp_path / "ds", name="demo",
        on_progress=lambda done, total: seen.append((done, total)),
    )
    assert seen == [(1, 2), (2, 2)]


def test_transaction_id_wraps_after_65536(tmp_path, monkeypatch):
    """交互数量放开后事务 id 会越过 2 字节，必须取模而不是崩掉。

    走真实 modbus 适配器：事务 id 越界会在 MBAP 头
    （transaction_id.to_bytes(2, "big")）抛 OverflowError，
    这正是本用例要守住的那条崩溃路径。

    链路封装与写盘与被测契约无关，打桩避免 65538 次 Scapy 封装
    与 13 万次文件写入把单测拖到分钟级。
    """
    from icsgen.spec.model import Operation

    captured: list[int] = []
    inner = load_modbus_adapter()

    class CapturingAdapter:
        """包住真实适配器：既走真实帧构建，又记录事务 id。"""

        name = inner.name

        def build(self, op, ctx):
            captured.append(ctx.transaction_id)
            return inner.build(op, ctx)

        def build_response(self, op, ctx):
            return inner.build_response(op, ctx)

    # 这几处打桩依赖被测模块以「模块级 from ... import ...」绑定这些名字：
    # icsgen/generator.py 的 encapsulate、icsgen/transport/session.py 的
    # encapsulate、icsgen/emit/dataset.py 的 write_raw/write_pcap。
    # 若它们改成函数内局部 import，模块属性上的桩会被局部绑定遮蔽而**静默失效** ——
    # 用例照样通过，只是跑回真实的封装与写盘，测试从秒级掉回分钟级。
    # 这是该用例的隐式契约，改那几个模块的导入形式时必须同步改这里。
    #
    # TCP 路径的封装现在发生在 icsgen.transport.session 里（由 TcpSession
    # 调用），两个模块的 encapsulate 桩都要打，否则 13 万次真实 Scapy 封装
    # 会把该用例从秒级拖到分钟级。
    monkeypatch.setattr(
        "icsgen.transport.session.encapsulate",
        lambda payload, spec, seq=0, ack=0, flags="PA": b"\x00",
    )
    monkeypatch.setattr(
        "icsgen.generator.encapsulate",
        lambda payload, spec, seq=0, ack=0, flags="PA": b"\x00",
    )
    monkeypatch.setattr("icsgen.emit.dataset.write_raw", lambda *a, **k: None)
    monkeypatch.setattr("icsgen.emit.dataset.write_pcap", lambda *a, **k: None)

    scenario = Scenario(
        name="demo",
        transport={"kind": "tcp"},
        operations=tuple(
            Operation(op="modbus.read_holding_registers", params={"quantity": 1})
            for _ in range(65538)
        ),
    )
    root = build_dataset(scenario, CapturingAdapter(), tmp_path / "ds", name="demo")
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert len(manifest["artifacts"]) == 65538
    assert len(captured) == 65538
    assert captured[65536] == 0
    assert captured[65537] == 1
    assert max(captured) <= 0xFFFF


def test_tcp_session_starts_with_handshake_and_ends_with_teardown(tmp_path):
    """TCP 会话文件是一次完整的连接：握手 → 数据 → 挥手。"""
    from scapy.all import IP, TCP, rdpcap

    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    scenario = Scenario(
        name="demo",
        transport={"kind": "tcp"},
        operations=(Operation(op="modbus.read_holding_registers", params={"quantity": 3}),),
    )
    root = build_dataset(scenario, adapter, tmp_path / "ds", name="demo")
    packets = rdpcap(str(root / "legit" / "modbus_tcp" / "session.pcap"))
    flags = [p[TCP].flags for p in packets]
    assert flags[:3] == ["S", "SA", "A"]
    assert flags[-4:] == ["FA", "A", "FA", "A"]
    assert all(flag == "PA" for flag in flags[3:-4])
    # 规格 §7 指标 1：包数 == 3 + 数据帧数 + 4。pcap_frame_count 只数
    # 产物自己的帧，所以这里不用再减握手与挥手。
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    data_frames = sum(entry["pcap_frame_count"] for entry in manifest["artifacts"])
    assert len(packets) == 3 + data_frames + 4


def test_data_session_mode_emits_only_data_segments(tmp_path):
    """`session: data` 只发数据段：没有握手与挥手。

    没有握手，服务端就还没发过任何段 —— 客户端首个数据段的 ack 必须是 0
    （TCP 规定：未收到任何段的确认号为 0）。
    """
    from scapy.all import IP, TCP, rdpcap

    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    scenario = Scenario(
        name="demo",
        transport={"kind": "tcp", "session": "data"},
        operations=(Operation(op="modbus.read_holding_registers", params={"quantity": 3}),),
    )
    root = build_dataset(scenario, adapter, tmp_path / "ds", name="demo")
    packets = rdpcap(str(root / "legit" / "modbus_tcp" / "session.pcap"))
    flags = [p[TCP].flags for p in packets]
    # 全是数据段：没有 S / SA / A 的握手，也没有 FA / A / FA / A 的挥手
    assert all(flag == "PA" for flag in flags), flags
    # 一次操作 = 请求 + 应答两包
    assert len(packets) == 2
    # 客户端方向的首包：ack 为 0（对端还没发过任何段）
    client = [p[TCP] for p in packets if p[IP].src == "192.168.1.10"]
    assert client[0].ack == 0


def test_tcp_session_sequence_numbers_are_coherent(tmp_path):
    """同方向相邻两包的 seq 差 == 前包消耗的序号数；ack 是对端当前序号。"""
    from scapy.all import IP, TCP, rdpcap

    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    scenario = Scenario(
        name="demo",
        transport={"kind": "tcp"},
        operations=(
            Operation(op="modbus.read_holding_registers", params={"quantity": 3}),
            Operation(op="modbus.write_multiple_registers", params={"quantity": 2}),
        ),
    )
    root = build_dataset(scenario, adapter, tmp_path / "ds", name="demo")
    packets = rdpcap(str(root / "legit" / "modbus_tcp" / "session.pcap"))
    # 按 IP 判定方向：客户端源端口比目的端口大，不能用端口大小判
    client = [p[TCP] for p in packets if p[IP].src == "192.168.1.10"]
    server = [p[TCP] for p in packets if p[IP].src == "192.168.1.20"]
    # 握手 3 包（客户端 S/A、服务端 SA）+ 数据 4 包（2 请求 2 应答）
    # + 挥手 4 包（客户端 FA/A、服务端 A/FA）= 客户端 6 包、服务端 5 包
    assert len(client) == 6
    assert len(server) == 5
    # 同方向相邻两包的 seq 差 == 前包消耗的序号数：数据段按载荷长度，
    # SYN 与 FIN 各占 1，纯 ACK 不消耗序号（因此相邻两包 seq 可以相同）
    for direction in (client, server):
        entries = [(t.seq, len(bytes(t.payload)), str(t.flags)) for t in direction]
        for (seq, length, flags), (next_seq, _, _) in zip(entries, entries[1:]):
            if length:
                step = length
            elif "S" in flags or "F" in flags:
                step = 1
            else:
                step = 0
            assert next_seq == seq + step
    # SYN 占掉客户端一个序号：第一个数据段的 seq 是 ISN+1
    data_client = [t for t in client if t.flags == "PA"]
    assert data_client[0].seq == 0x1001
    assert data_client[0].ack == 0x2001
    assert data_client[1].seq == 0x1001 + len(bytes(data_client[0].payload))
    # FIN 之前的所有数据都算进了序号
    fin = [t for t in client if t.flags == "FA"]
    assert len(fin) == 1
    assert fin[0].seq == 0x1001 + sum(len(bytes(t.payload)) for t in data_client)
