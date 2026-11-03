"""传输封装层：Ethernet / IP / TCP / UDP。"""

import struct

from scapy.all import Ether, IP, TCP, UDP

from icsgen.transport.link import encapsulate, sll_header
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


def test_sll_header_is_sixteen_bytes():
    """串口帧按 Linux cooked capture 记录，头部固定 16 字节。"""
    header = sll_header(outgoing=True)
    assert len(header) == 16


def test_sll_header_marks_direction():
    """SLL 头区分本机发出与本机接收。"""
    outgoing = struct.unpack(">H", sll_header(outgoing=True)[:2])[0]
    incoming = struct.unpack(">H", sll_header(outgoing=False)[:2])[0]
    assert outgoing == 4
    assert incoming == 0


def test_sll_header_leaves_protocol_unknown():
    """串口没有上层协议字段可用，协议号留 0。"""
    protocol = struct.unpack(">H", sll_header(outgoing=True)[14:16])[0]
    assert protocol == 0


def test_transport_spec_round_trips_through_dict():
    """传输层参数写进 manifest 后要能原样还原，供派生数据集重建封装。"""
    spec = TransportSpec(kind="serial", dport=9600, src_ip="10.0.0.1")
    assert TransportSpec.from_dict(spec.to_dict()) == spec
