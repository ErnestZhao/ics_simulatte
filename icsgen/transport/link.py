"""链路封装：把协议帧包装成 Ethernet / IP / TCP / UDP 字节。

序列化时由 Scapy 填充 IP 与 TCP/UDP 的校验和。
"""

from __future__ import annotations

from scapy.all import Dot1Q, Ether, IP, TCP, UDP

from .spec import DEFAULT_SOURCE_PORT, TransportSpec


def encapsulate(
    payload: bytes,
    transport: TransportSpec,
    *,
    seq: int = 0,
    ack: int = 0,
    flags: str = "PA",
) -> bytes:
    """把协议帧封装为链路字节。

    kind 为 serial 时直接返回原始字节（串口链路无 IP/TCP 封装）。
    """
    if transport.kind == "serial":
        return payload

    ether = Ether(src=transport.mac_src, dst=transport.mac_dst)
    ip = IP(src=transport.src_ip, dst=transport.dst_ip)
    sport = transport.sport if transport.sport is not None else DEFAULT_SOURCE_PORT

    if transport.kind == "tcp":
        layer = TCP(sport=sport, dport=transport.dport, seq=seq, ack=ack, flags=flags)
    elif transport.kind == "udp":
        layer = UDP(sport=sport, dport=transport.dport)
    else:
        raise ValueError(f"不支持的传输类型 {transport.kind!r}")

    if transport.vlan_id is not None:
        ether = Ether(src=transport.mac_src, dst=transport.mac_dst, type=0x8100)
        ip = Dot1Q(vlan=transport.vlan_id) / ip

    return bytes(ether / ip / layer / payload)
