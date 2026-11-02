"""传输封装层：Ethernet / IP / TCP / UDP。"""

from scapy.all import Ether, IP, TCP, UDP

from icsgen.transport.link import encapsulate
from icsgen.transport.spec import TransportSpec


def _parse(raw: bytes):
    return Ether(raw)


def test_tcp_frame_structure():
    raw = encapsulate(b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x03", TransportSpec())
    pkt = _parse(raw)
    assert pkt[IP].src == "192.168.1.10"
    assert pkt[IP].dst == "192.168.1.20"
    assert pkt[TCP].dport == 502
    assert bytes(pkt[TCP].payload) == b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x03"


def test_tcp_checksum_is_computed():
    raw = encapsulate(b"\xaa" * 6, TransportSpec())
    pkt = _parse(raw)
    assert pkt[TCP].chksum is not None
    assert pkt[IP].chksum is not None


def test_udp_frame_structure():
    raw = encapsulate(b"\x01\x02", TransportSpec(kind="udp", dport=502))
    pkt = _parse(raw)
    assert pkt[UDP].dport == 502
    assert bytes(pkt[UDP].payload) == b"\x01\x02"


def test_serial_kind_returns_raw_payload():
    """串口传输不封装链路层。"""
    raw = encapsulate(b"\x11\x03\x00\x00", TransportSpec(kind="serial"))
    assert raw == b"\x11\x03\x00\x00"


def test_vlan_tag_is_applied():
    raw = encapsulate(b"\x01", TransportSpec(vlan_id=100))
    pkt = _parse(raw)
    assert pkt[Ether].type == 0x8100


def test_custom_ports_are_used():
    raw = encapsulate(b"\x01", TransportSpec(dport=1502, sport=40001))
    pkt = _parse(raw)
    assert pkt[TCP].dport == 1502
    assert pkt[TCP].sport == 40001


def test_reversed_spec_swaps_endpoints():
    """反向配置把源/目的对调：响应当由服务端发往客户端。"""
    spec = TransportSpec(dport=502, sport=40001)
    rev = spec.reversed()
    assert rev.src_ip == spec.dst_ip
    assert rev.dst_ip == spec.src_ip
    assert rev.mac_src == spec.mac_dst
    assert rev.mac_dst == spec.mac_src
    assert rev.sport == spec.dport
    assert rev.dport == 40001


def test_reversed_spec_yields_opposite_direction_on_the_wire():
    spec = TransportSpec()
    request = _parse(encapsulate(b"\x01", spec))
    response = _parse(encapsulate(b"\x02", spec.reversed()))
    assert request[IP].src == response[IP].dst
    assert request[IP].dst == response[IP].src
    assert request[TCP].sport == response[TCP].dport
    assert request[TCP].dport == response[TCP].sport
