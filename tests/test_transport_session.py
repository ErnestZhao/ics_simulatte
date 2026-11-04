"""TCP 会话序号状态机：握手、数据、挥手。"""

import pytest
from scapy.all import Ether, IP, TCP

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
    """任一方向相邻两包的 seq 差 == 前包消耗的序号数。"""
    spec = TransportSpec()
    session = TcpSession(spec)
    packets = session.handshake()
    packets.append(session.data(b"\x01\x02\x03", outgoing=True))
    packets.append(session.data(b"\x04\x05", outgoing=False))
    packets.extend(session.teardown())

    by_direction: dict[str, list[tuple[int, int, str]]] = {"client": [], "server": []}
    for raw in packets:
        parsed = Ether(raw)
        tcp = parsed[TCP]
        direction = "client" if parsed[IP].src == spec.src_ip else "server"
        by_direction[direction].append(
            (tcp.seq, len(bytes(tcp.payload)), str(tcp.flags))
        )

    for direction, entries in by_direction.items():
        for (seq, length, flags), (next_seq, _, _) in zip(entries, entries[1:]):
            if length:
                step = length
            elif "S" in flags or "F" in flags:
                step = 1
            else:
                step = 0
            assert next_seq == (seq + step) % 2**32, direction


def test_sequence_number_wraps_instead_of_crashing():
    """序号到顶后回绕，不因 Scapy 打包越界而崩溃。"""
    session = TcpSession(
        TransportSpec(), client_isn=2**32 - 1, server_isn=2**32 - 1
    )
    packets = session.handshake()
    assert len(packets) == 3
    # ISN 取 2**32-1，握手各消耗一个序号后回绕到 0
    assert session.client_seq == 0
    assert session.server_seq == 0


def test_handshake_cannot_be_repeated():
    session = TcpSession(TransportSpec())
    session.handshake()
    with pytest.raises(RuntimeError):
        session.handshake()


def test_transport_spec_rejects_unknown_session_mode():
    with pytest.raises(ValueError) as info:
        TransportSpec(session="bogus")
    assert "bogus" in str(info.value)


def test_transport_spec_rejects_unknown_kind():
    """传输种类也在传输层校验 —— 别等封装层才炸。"""
    with pytest.raises(ValueError) as info:
        TransportSpec(kind="carrier-pigeon")
    assert "carrier-pigeon" in str(info.value)


def test_transport_spec_defaults_to_full_session():
    assert TransportSpec().session == "full"
    assert TransportSpec().to_dict()["session"] == "full"


@pytest.mark.parametrize("bad_isn", [-1, 2**32, 2**33])
def test_initial_sequence_number_must_fit_in_32_bits(bad_isn):
    """初始序号越界要在构造时就被拦下，而不是拖到 Scapy 打包才炸。"""
    with pytest.raises(ValueError) as info:
        TcpSession(TransportSpec(), client_isn=bad_isn)
    assert "client_isn" in str(info.value)


def test_initial_sequence_number_must_be_an_integer():
    with pytest.raises(TypeError) as info:
        TcpSession(TransportSpec(), server_isn="0x2000")
    assert "server_isn" in str(info.value)


def test_initial_sequence_number_rejects_bool():
    """True 是 int 的子类，但当序号用是错的 —— 不能被静默接受成 1。"""
    with pytest.raises(TypeError):
        TcpSession(TransportSpec(), client_isn=True)
