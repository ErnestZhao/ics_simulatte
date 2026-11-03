# TCP 完整会话（握手 + 数据 + 挥手）实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 TCP 层的 `session.pcap` 呈现一次完整的 TCP 交互流程 —— 三次握手 → 请求/应答 → 四次挥手，且序号严格自洽。

**Architecture:** 新增 `icsgen/transport/session.py` 承载 TCP 序号状态机（握手 / 数据 / 挥手三段记账）；会话形态作为**声明式字段**挂在 `TransportSpec.session`（`full` / `data`）上，随 manifest 传递，变异层据此重建同样形态。生成器与变异命令各自按「会话键 = tier/协议_传输」维护一个会话对象。

**Tech Stack:** Python 3.11、Scapy（链路封装）、pydantic（Web 层）、pytest。

**Spec:** `docs/superpowers/specs/2026-11-03-tcp-session-flow-design.md`（设计规格，实现以它为准）

## Global Constraints

- 纯 Python 依赖，不新增任何第三方依赖；不引入 npm / 前端构建链 / SPA 框架。
- **生成必须可复现**：同一场景必得同一份字节 —— 初始序号（ISN）固定，不引入随机源。
- 库层不得依赖 Web 层；Web 层不得复制库层业务逻辑。
- 新增依赖只能进 `[project.optional-dependencies]` 的可选组（本计划不新增依赖）。
- 会话形态是**传输配置的数据**（`TransportSpec.session`），不写死分支；取值集合只在传输层声明一处。
- 测试命令一律从仓库根目录执行：`python3 -m pytest -q -W error`。
- 提交前必须跑通全套测试；提交信息用中文，说明「为什么」。

---

### Task 1: TCP 会话序号状态机 + 传输配置的会话形态字段

**Files:**
- Create: `icsgen/transport/session.py`
- Create: `tests/test_transport_session.py`
- Modify: `icsgen/transport/spec.py`（新增 `session` 字段与校验）

**Interfaces:**
- Consumes: `icsgen.transport.spec.TransportSpec`（既有）、`icsgen.transport.link.encapsulate(payload, transport, *, seq=0, ack=0, flags="PA")`（既有，不改）
- Produces:
  - `icsgen.transport.session.TcpSession(spec, *, client_isn=CLIENT_ISN, server_isn=SERVER_ISN)`
    - `.handshake() -> list[bytes]` —— 3 个包：S / SA / A
    - `.data(payload: bytes, *, outgoing: bool) -> bytes` —— 1 个数据段
    - `.teardown() -> list[bytes]` —— 4 个包：FA / A / FA / A
    - `.client_seq -> int`、`.server_seq -> int` —— 只读当前序号
  - `icsgen.transport.session.CLIENT_ISN = 0x1000`、`SERVER_ISN = 0x2000`
  - `icsgen.transport.spec.SESSION_MODES = ("full", "data")`
  - `TransportSpec.session: str = "full"` —— 非法取值在构造时抛 `ValueError`

- [ ] **Step 1: 写失败的测试**

创建 `tests/test_transport_session.py`：

```python
"""TCP 会话序号状态机：握手、数据、挥手。"""

from scapy.all import Ether, TCP

from icsgen.transport.session import CLIENT_ISN, SERVER_ISN, TcpSession
from icsgen.transport.spec import TransportSpec


def _tcp(raw: bytes) -> TCP:
    return Ether(raw)[TCP]


def test_handshake_is_syn_synack_ack():
    session = TcpSession(TransportSpec())
    packets = session.handshake()
    assert len(packets) == 3
    assert [_tcp(p).flags for p in packets] == ["S", "SA", "A"]


def test_handshake_sequence_numbers():
    session = TcpSession(TransportSpec())
    packets = session.handshake()
    syn, syn_ack, ack = (_tcp(p) for p in packets)
    assert syn.seq == CLIENT_ISN
    assert syn.ack == 0
    assert syn_ack.seq == SERVER_ISN
    assert syn_ack.ack == CLIENT_ISN + 1
    assert ack.seq == CLIENT_ISN + 1
    assert ack.ack == SERVER_ISN + 1


def test_data_advances_sequence_by_payload_length():
    session = TcpSession(TransportSpec())
    session.handshake()
    payload = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x03"
    packet = _tcp(session.data(payload, outgoing=True))
    assert packet.seq == CLIENT_ISN + 1
    assert packet.ack == SERVER_ISN + 1
    assert session.client_seq == CLIENT_ISN + 1 + len(payload)


def test_server_data_acknowledges_client_sequence():
    session = TcpSession(TransportSpec())
    session.handshake()
    request = b"\x00\x01"
    session.data(request, outgoing=True)
    response = b"\x00\x01\x00\x00\x00\x03\x01\x03\x02\x00\x2a"
    packet = _tcp(session.data(response, outgoing=False))
    assert packet.seq == SERVER_ISN + 1
    assert packet.ack == CLIENT_ISN + 1 + len(request)


def test_teardown_is_four_packets():
    session = TcpSession(TransportSpec())
    session.handshake()
    packets = session.teardown()
    assert len(packets) == 4
    assert [_tcp(p).flags for p in packets] == ["FA", "A", "FA", "A"]


def test_teardown_sequence_numbers():
    session = TcpSession(TransportSpec())
    session.handshake()
    client_fin, server_ack, server_fin, client_ack = (
        _tcp(p) for p in session.teardown()
    )
    assert client_fin.seq == CLIENT_ISN + 1
    assert client_fin.ack == SERVER_ISN + 1
    assert server_ack.seq == SERVER_ISN + 1
    assert server_ack.ack == CLIENT_ISN + 2
    assert server_fin.seq == SERVER_ISN + 1
    assert server_fin.ack == CLIENT_ISN + 2
    assert client_ack.seq == CLIENT_ISN + 2
    assert client_ack.ack == SERVER_ISN + 2


def test_sequence_numbers_are_coherent_across_a_whole_session():
    """任一方向相邻两包的 seq 差 == 前包载荷长度（数据段）或 1（SYN/FIN）。"""
    session = TcpSession(TransportSpec())
    packets = session.handshake()
    packets.append(session.data(b"\x01\x02\x03", outgoing=True))
    packets.append(session.data(b"\x04\x05", outgoing=False))
    packets.extend(session.teardown())

    client_seqs: list[int] = []
    server_seqs: list[int] = []
    for raw in packets:
        tcp = _tcp(raw)
        if tcp.sport < tcp.dport:  # 客户端发出
            client_seqs.append(tcp.seq)
        else:
            server_seqs.append(tcp.seq)
    assert client_seqs == sorted(client_seqs)
    assert server_seqs == sorted(server_seqs)


def test_transport_spec_rejects_unknown_session_mode():
    try:
        TransportSpec(session="bogus")
    except ValueError as exc:
        assert "bogus" in str(exc)
    else:
        raise AssertionError("非法会话形态应当报错")


def test_transport_spec_defaults_to_full_session():
    assert TransportSpec().session == "full"
    assert TransportSpec().to_dict()["session"] == "full"
```

- [ ] **Step 2: 跑测试确认失败**

Run: `python3 -m pytest tests/test_transport_session.py -q -W error`
Expected: FAIL —— `ModuleNotFoundError: No module named 'icsgen.transport.session'`

- [ ] **Step 3: 写传输层的会话形态字段**

修改 `icsgen/transport/spec.py`，在 `DEFAULT_SOURCE_PORT` 之后加入：

```python
#: 会话形态：full = 握手 + 数据 + 挥手；data = 只发数据段
SESSION_MODES = ("full", "data")
```

在 `TransportSpec` 的字段列表末尾（`vlan_id` 之后）加入：

```python
    session: str = "full"
```

并在 `TransportSpec` 类体里（`reversed` 方法之前）加入：

```python
    def __post_init__(self) -> None:
        """会话形态取值必须合法 —— 取值集合只在传输层声明一处。"""
        if self.session not in SESSION_MODES:
            raise ValueError(
                f"未知的会话形态 {self.session!r}，可用：{list(SESSION_MODES)}"
            )
```

- [ ] **Step 4: 跑测试确认传输层部分通过、状态机部分仍失败**

Run: `python3 -m pytest tests/test_transport_session.py -q -W error`
Expected: 2 passed（会话形态字段的用例）, 8 failed（`No module named 'icsgen.transport.session'`）

- [ ] **Step 5: 写状态机模块**

创建 `icsgen/transport/session.py`：

```python
"""TCP 会话：三次握手、数据交换、四次挥手。

一条 TCP 连接的序号是连续推进的：SYN 与 FIN 各占一个序号，数据段按载荷
长度推进。序号状态机收在这里，生成器与变异命令共用同一套记账。

初始序号固定 —— 生成必须可复现，同一场景必得同一份字节。
"""

from __future__ import annotations

from .link import encapsulate
from .spec import TransportSpec

#: 客户端初始序号
CLIENT_ISN = 0x1000
#: 服务端初始序号
SERVER_ISN = 0x2000

#: TCP 序列号占 4 字节，越界要回绕而不是崩掉
_SEQUENCE_MODULO = 2**32


class TcpSession:
    """一条 TCP 连接的序号状态机。

    客户端与服务端各维护一个「下一个要发的序号」；每包的 ack 是对端当前
    序号，也就是对端下一个期望收到的字节。
    """

    def __init__(
        self,
        spec: TransportSpec,
        *,
        client_isn: int = CLIENT_ISN,
        server_isn: int = SERVER_ISN,
    ) -> None:
        self.spec = spec
        self._client_seq = client_isn
        self._server_seq = server_isn
        self._server_spoke = False

    @property
    def client_seq(self) -> int:
        """客户端下一个要发的序号。"""
        return self._client_seq

    @property
    def server_seq(self) -> int:
        """服务端下一个要发的序号。"""
        return self._server_seq

    def handshake(self) -> list[bytes]:
        """三次握手：SYN、SYN-ACK、ACK。"""
        packets: list[bytes] = []
        # SYN 占用客户端一个序号；服务端此时还没发过东西，ack 为 0
        packets.append(
            encapsulate(b"", self.spec, seq=self._client_seq, ack=self._ack_to_server(), flags="S")
        )
        self._client_seq += 1
        # SYN-ACK 同样占用服务端一个序号
        packets.append(
            encapsulate(
                b"",
                self.spec.reversed(),
                seq=self._server_seq,
                ack=self._client_seq,
                flags="SA",
            )
        )
        self._server_seq += 1
        self._server_spoke = True
        # ACK 确认服务端的序号
        packets.append(
            encapsulate(b"", self.spec, seq=self._client_seq, ack=self._server_seq, flags="A")
        )
        return packets

    def data(self, payload: bytes, *, outgoing: bool) -> bytes:
        """一个数据段。outgoing 为 True 表示客户端发出。"""
        if outgoing:
            packet = encapsulate(
                payload, self.spec, seq=self._client_seq, ack=self._ack_to_server(), flags="PA"
            )
            self._client_seq = (self._client_seq + len(payload)) % _SEQUENCE_MODULO
            return packet
        packet = encapsulate(
            payload, self.spec.reversed(), seq=self._server_seq, ack=self._client_seq, flags="PA"
        )
        self._server_seq = (self._server_seq + len(payload)) % _SEQUENCE_MODULO
        self._server_spoke = True
        return packet

    def teardown(self) -> list[bytes]:
        """四次挥手：客户端 FIN、服务端 ACK、服务端 FIN、客户端 ACK。"""
        packets: list[bytes] = []
        # 客户端 FIN 占用一个序号
        packets.append(
            encapsulate(b"", self.spec, seq=self._client_seq, ack=self._server_seq, flags="FA")
        )
        self._client_seq += 1
        packets.append(
            encapsulate(b"", self.spec.reversed(), seq=self._server_seq, ack=self._client_seq, flags="A")
        )
        # 服务端 FIN 同样占用一个序号
        packets.append(
            encapsulate(b"", self.spec.reversed(), seq=self._server_seq, ack=self._client_seq, flags="FA")
        )
        self._server_seq += 1
        packets.append(
            encapsulate(b"", self.spec, seq=self._client_seq, ack=self._server_seq, flags="A")
        )
        return packets

    def _ack_to_server(self) -> int:
        """客户端数据段的 ack：服务端还没发过东西时是 0。"""
        return self._server_seq if self._server_spoke else 0
```

- [ ] **Step 6: 跑测试确认通过**

Run: `python3 -m pytest tests/test_transport_session.py -q -W error`
Expected: 10 passed

- [ ] **Step 7: 跑传输层与全量测试**

Run: `python3 -m pytest tests/test_transport_link.py tests/test_pcap.py -q -W error`
Expected: PASS（既有测试不受影响）

Run: `python3 -m pytest -q -W error`
Expected: 全部通过（`TransportSpec` 新增字段不影响既有构造）

- [ ] **Step 8: 提交**

```bash
git add icsgen/transport/session.py icsgen/transport/spec.py tests/test_transport_session.py
git commit -m "feat: TCP 会话序号状态机与声明式会话形态"
```

---

### Task 2: 生成器与数据集组装接入握手/挥手

**Files:**
- Modify: `icsgen/generator.py`
- Modify: `icsgen/emit/dataset.py`
- Modify: `tests/test_generator.py`
- Modify: `tests/test_emit_dataset.py`

**Interfaces:**
- Consumes: Task 1 的 `TcpSession`；既有 `Artifact`、`DatasetBuilder.add_linked_packets`
- Produces:
  - `icsgen.emit.dataset.session_key(artifact: Artifact) -> str` —— 会话键 `tier/协议_传输`（由既有的私有 `_session_key` 改名导出）
  - `DatasetBuilder.begin_session(key: str, packets: list[bytes]) -> None` —— 会话前导包（握手）；该会话已有包时抛 `ValueError`
  - `DatasetBuilder.end_session(key: str, packets: list[bytes]) -> None` —— 会话收尾包（挥手）

- [ ] **Step 1: 写失败的测试**

在 `tests/test_emit_dataset.py` 末尾追加（并把文件顶部的 import 补成
`from scapy.all import rdpcap` 与 `from icsgen.emit.dataset import Artifact, DatasetBuilder, session_key, write_dataset`）：

```python
def test_begin_session_shifts_artifact_index(tmp_path):
    """握手占住前三个包序号，产物的 pcap_index 随之偏移。"""
    builder = DatasetBuilder("demo", tmp_path / "ds")
    artifact = _artifact(payload=b"\x01")
    builder.add(artifact)
    builder.begin_session(session_key(artifact), [b"\x00", b"\x01", b"\x02"])
    builder.add_linked_packets(artifact.id, [b"\x10", b"\x11"])
    root = builder.write()
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    entry = manifest["artifacts"][0]
    assert entry["pcap_index"] == 3
    assert entry["pcap_resp_index"] == 4
    packets = rdpcap(str(root / "legit" / "modbus_tcp" / "session.pcap"))
    assert len(packets) == 5


def test_end_session_appends_teardown(tmp_path):
    builder = DatasetBuilder("demo", tmp_path / "ds")
    artifact = _artifact(payload=b"\x01")
    builder.add(artifact)
    builder.begin_session(session_key(artifact), [b"\x00", b"\x01", b"\x02"])
    builder.add_linked_packets(artifact.id, [b"\x10", b"\x11"])
    builder.end_session(session_key(artifact), [b"\x20", b"\x21", b"\x22", b"\x23"])
    root = builder.write()
    packets = rdpcap(str(root / "legit" / "modbus_tcp" / "session.pcap"))
    assert len(packets) == 9


def test_begin_session_rejects_a_started_session(tmp_path):
    builder = DatasetBuilder("demo", tmp_path / "ds")
    builder.begin_session("legit/modbus_tcp", [b"\x00"])
    try:
        builder.begin_session("legit/modbus_tcp", [b"\x01"])
    except ValueError:
        pass
    else:
        raise AssertionError("已经起头的会话不应再插入前导包")
```

（`_artifact` 是该文件里既有的辅助函数，签名
`_artifact(op=..., tier=..., payload=..., transport=..., response=...)`。）

在 `tests/test_generator.py` 末尾追加：

```python
def test_tcp_session_starts_with_handshake_and_ends_with_teardown(tmp_path):
    """TCP 会话文件是一次完整的连接：握手 → 数据 → 挥手。"""
    from scapy.all import TCP, rdpcap

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
    assert len(packets) == 3 + 2 + 4


def test_tcp_session_sequence_numbers_are_coherent(tmp_path):
    """双方序号各自严格递增；数据段按载荷长度推进，ack 是对端当前序号。"""
    from scapy.all import TCP, rdpcap

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
    packets = [
        p[TCP] for p in rdpcap(str(root / "legit" / "modbus_tcp" / "session.pcap"))
    ]
    client = [t for t in packets if t.sport < t.dport]
    server = [t for t in packets if t.sport > t.dport]
    assert [t.seq for t in client] == sorted(t.seq for t in client)
    assert [t.seq for t in server] == sorted(t.seq for t in server)
    # SYN 占掉客户端一个序号：第一个数据段的 seq 是 ISN+1
    data_client = [t for t in client if t.flags == "PA"]
    assert data_client[0].seq == 0x1001
    assert data_client[0].ack == 0x2001
    assert data_client[1].seq == 0x1001 + len(bytes(data_client[0].payload))
    # FIN 之前的所有数据都算进了序号
    fin = [t for t in client if t.flags == "FA"]
    assert len(fin) == 1
    assert fin[0].seq == 0x1001 + sum(len(bytes(t.payload)) for t in data_client)
```

- [ ] **Step 2: 跑测试确认失败**

Run: `python3 -m pytest tests/test_generator.py tests/test_emit_dataset.py -q -W error`
Expected: FAIL —— `ImportError: cannot import name 'session_key'`（或 `begin_session` 不存在）

- [ ] **Step 3: 数据集组装支持会话前导与收尾**

修改 `icsgen/emit/dataset.py`：

把 `def _session_key(artifact: Artifact) -> str:` 改名为 `def session_key(artifact: Artifact) -> str:`，
并更新它的两处调用（`add_linked_packets` 与 `write_dataset` 里的 `_session_key(artifact)`）。

在 `DatasetBuilder` 类里（`add_linked_packets` 之后）加入：

```python
    def begin_session(self, key: str, packets: list[bytes]) -> None:
        """会话的前导包（TCP 握手）。

        必须在该会话的任何产物挂进来之前调用 —— 前导包要占住包序号，
        产物的 pcap_index 由此偏移。
        """
        session = self._packets.setdefault(key, [])
        if session:
            raise ValueError(f"会话 {key!r} 已经有包了，不能再插入前导包")
        session.extend(packets)

    def end_session(self, key: str, packets: list[bytes]) -> None:
        """会话的收尾包（TCP 挥手）。"""
        self._packets.setdefault(key, []).extend(packets)
```

- [ ] **Step 4: 生成器接入会话**

修改 `icsgen/generator.py`：

导入改为：

```python
from .emit.dataset import Artifact, DatasetBuilder, session_key
from .protocols.base import BuildContext, ProtocolAdapter
from .spec.model import Scenario
from .transport.link import encapsulate
from .transport.session import TcpSession
from .transport.spec import TransportSpec
```

删除 `_SEQUENCE_MODULO` 常量（序号推进交给状态机）。

在 `build_dataset` 里，`builder = DatasetBuilder(...)` 之后加入：

```python
    sessions: dict[str, TcpSession] = {}
```

把原来构造 `packets` 的那一段（`seq = (index * 10) % _SEQUENCE_MODULO` 起始）替换为：

```python
        if spec.kind == "tcp":
            key = session_key(artifact)
            session = sessions.get(key)
            if session is None:
                session = TcpSession(spec)
                sessions[key] = session
                if spec.session == "full":
                    builder.begin_session(key, session.handshake())
            packets = [session.data(frame.payload, outgoing=True)]
            if response_frame is not None:
                packets.append(session.data(response_frame.payload, outgoing=False))
        else:
            packets = [encapsulate(frame.payload, spec)]
            if response_frame is not None:
                packets.append(encapsulate(response_frame.payload, spec.reversed()))
```

在 `return builder.write()` 之前加入：

```python
    for key, session in sessions.items():
        if spec.session == "full":
            builder.end_session(key, session.teardown())
```

- [ ] **Step 5: 修正既有断言**

`tests/test_generator.py` 里断言 `entry["pcap_index"] == 0` 与 `entry["pcap_resp_index"] == 1`
的两处，改成握手偏移后的值：

```python
    assert entry["pcap_index"] == 3
    assert entry["pcap_resp_index"] == 4
```

`tests/test_emit_dataset.py` 里直接用 `DatasetBuilder` 而没有握手的用例，索引不变；
只有经 `build_dataset` 生成的用例才需要偏移 —— 逐个核对后再改。

- [ ] **Step 6: 跑测试确认通过**

Run: `python3 -m pytest tests/test_generator.py tests/test_emit_dataset.py -q -W error`
Expected: PASS

Run: `python3 -m pytest -q -W error`
Expected: 全部通过

- [ ] **Step 7: 提交**

```bash
git add icsgen/generator.py icsgen/emit/dataset.py tests/test_generator.py tests/test_emit_dataset.py
git commit -m "feat: 生成的 TCP 会话补齐握手与挥手"
```

---

### Task 3: 变异层按 manifest 重建会话 + 保存时校验会话形态 + 文档

**Files:**
- Modify: `icsgen/cli.py`（`mutate_cmd`）
- Modify: `icsgen/web/service.py`（`save_config` 在写账本前校验传输配置）
- Modify: `tests/test_cli.py`
- Modify: `tests/test_web_service.py`
- Modify: `README.md`

**Interfaces:**
- Consumes: Task 1 的 `TcpSession`、`TransportSpec.session`；Task 2 的 `session_key`、`begin_session`、`end_session`
- Produces: `mutated` 层的 `session.pcap` 与源层同样带握手与挥手；Web 层保存配置时校验传输配置可被 `TransportSpec` 接受

- [ ] **Step 1: 写失败的测试**

在 `tests/test_cli.py` 末尾追加（该文件已有 `runner = CliRunner()` 与 `from icsgen.cli import app`）：

```python
def test_mutate_command_writes_full_tcp_session(tmp_path):
    """变异层同样是一次完整的 TCP 连接：握手 → 数据 → 挥手。"""
    from scapy.all import TCP, rdpcap

    from icsgen.generator import build_dataset
    from icsgen.protocols.modbus.adapter import load_modbus_adapter
    from icsgen.spec.model import Operation, Scenario

    source = tmp_path / "src"
    build_dataset(
        Scenario(
            name="demo",
            transport={"kind": "tcp"},
            operations=(
                Operation(op="modbus.read_holding_registers", params={"quantity": 3}),
            ),
        ),
        load_modbus_adapter(),
        source,
        name="demo",
    )
    output = tmp_path / "fuzz"
    result = runner.invoke(
        app, ["mutate", str(source), "-o", str(output), "--rules", "bit_flip"]
    )
    assert result.exit_code == 0, result.output
    packets = rdpcap(str(output / "mutated" / "modbus_tcp" / "session.pcap"))
    flags = [p[TCP].flags for p in packets]
    assert flags[:3] == ["S", "SA", "A"]
    assert flags[-4:] == ["FA", "A", "FA", "A"]
```

在 `tests/test_web_service.py` 末尾追加：

```python
def test_save_config_rejects_invalid_session_mode(tmp_path):
    """非法会话形态要在写账本之前报错 —— 记录落盘就删不掉了。"""
    store = WebStore(tmp_path)
    payload = ConfigPayload(
        name="非法形态",
        transport={"kind": "tcp", "session": "bogus"},
        operations=[OperationInput(op="modbus.read_holding_registers", count=1)],
    )
    with pytest.raises(WebError) as excinfo:
        save_config(store, payload)
    assert "bogus" in str(excinfo.value)
    assert store.list_configs() == []
```

- [ ] **Step 2: 跑测试确认失败**

Run: `python3 -m pytest tests/test_cli.py tests/test_web_service.py -q -W error`
Expected: FAIL（变异层没有握手；Web 层没有校验）

- [ ] **Step 3: 变异层按 manifest 重建会话**

修改 `icsgen/cli.py` 的 `mutate_cmd`：

导入处加入：

```python
from .transport.session import TcpSession
```

把 `seq = 0` 换成：

```python
    sessions: dict[str, TcpSession] = {}
```

把构造 `packets` 的那一段：

```python
            packets = []
            for frame, outgoing in zip(frames, frame_roles(artifact)):
                direction = spec if outgoing else spec.reversed()
                packets.append(encapsulate(frame, direction, seq=seq, ack=seq))
                seq += len(frame)
            builder.add_linked_packets(artifact.id, packets)
```

替换为：

```python
            if spec.kind == "tcp":
                key = session_key(artifact)
                session = sessions.get(key)
                if session is None:
                    session = TcpSession(spec)
                    sessions[key] = session
                    if spec.session == "full":
                        builder.begin_session(key, session.handshake())
                packets = [
                    session.data(frame, outgoing=outgoing)
                    for frame, outgoing in zip(frames, frame_roles(artifact))
                ]
            else:
                packets = [
                    encapsulate(frame, spec if outgoing else spec.reversed())
                    for frame, outgoing in zip(frames, frame_roles(artifact))
                ]
            builder.add_linked_packets(artifact.id, packets)
```

在 `root = builder.write()` 之前加入：

```python
    for key, session in sessions.items():
        if spec.session == "full":
            builder.end_session(key, session.teardown())
```

并把 `mutate_cmd` 里的 `from .emit.dataset import ...` 导入补上 `session_key`
（与 `generator.py` 同一处来源）。

- [ ] **Step 4: Web 层在保存时校验传输配置**

修改 `icsgen/web/service.py` 的 `save_config`，在「未知字段」检查之后加入：

```python
    # 传输配置要能被 TransportSpec 接受：非法取值在写账本之前就得拦住 ——
    # 配置记录一旦落进只追加的账本就删不掉了。
    try:
        raw = dict(payload.transport)
        kind = raw.pop("kind", "tcp")
        TransportSpec(kind=kind, **raw)
    except (TypeError, ValueError) as exc:
        raise WebError(f"传输配置不合法：{exc}") from exc
```

- [ ] **Step 5: 跑测试确认通过**

Run: `python3 -m pytest tests/test_cli.py tests/test_web_service.py -q -W error`
Expected: PASS

- [ ] **Step 6: 文档**

修改 `README.md`：

在「产物布局」小节的说明列表里，`- **`.pcap` 是完整链路帧**…` 那一条之后加入：

```markdown
- **TCP 会话是完整的一次连接**：pcap 里含三次握手（`S` / `SA` / `A`）与四次挥手
  （`FA` / `A` / `FA` / `A`），序号严格自洽 —— SYN 与 FIN 各占一个序号，数据段按
  载荷长度推进。串口与 UDP 没有握手。
```

在「变异引擎」小节里，`变异结果按源数据集 manifest 里记录的链路参数重新封装…`
那一条之后加入：

```markdown
- 变异层同样是完整的 TCP 连接：会话形态（握手 / 挥手）随源 manifest 的
  `transport.session` 传递，变异层按同样的形态重建。
```

在「Web 交互界面」小节的命令示例之后补一句：

```markdown
传输配置里的 `session` 字段控制会话形态：`full`（默认，握手 + 数据 + 挥手）或
`data`（只发数据段）。
```

- [ ] **Step 7: 跑全量测试**

Run: `python3 -m pytest -q -W error`
Expected: 全部通过

- [ ] **Step 8: 提交**

```bash
git add icsgen/cli.py icsgen/web/service.py tests/test_cli.py tests/test_web_service.py README.md
git commit -m "feat: 变异层重建完整会话并在保存时校验会话形态"
```

---

## 验收（全部可自动判定）

| # | 指标 | 判定 |
|---|---|---|
| 1 | TCP 会话包数 == 3 + 数据帧数 + 4 | 测试断言 |
| 2 | flags 序列 == `[S, SA, A] + [PA…] + [FA, A, FA, A]` | 测试逐包断言 |
| 3 | 客户端 / 服务端 seq 严格递增 | 测试断言 |
| 4 | 每包 ack == 对端当前序号 | 测试断言 |
| 5 | SYN seq == 客户端 ISN；SYN-ACK ack == ISN+1 | 测试断言 |
| 6 | 串口与 UDP 会话不变 | 既有测试保持通过 |
| 7 | `mutated` 层同样满足 1–5 | 测试断言 |
| 8 | `pcap_resp_index == pcap_index + 1` | 既有测试保持通过 |
| 9 | 全套测试通过 | `python3 -m pytest -q -W error` |
