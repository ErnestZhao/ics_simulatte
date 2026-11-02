"""标准 libpcap 文件写出。

自己写文件头与包记录，不依赖 Scapy 的 pcap 写出，以便精确控制字节；
产物可被 Scapy 的 rdpcap 与 Wireshark 正常读取。
"""

from __future__ import annotations

import struct
from pathlib import Path

#: libpcap 文件头的 magic（小端）
PCAP_MAGIC = 0xA1B2C3D4
#: 链路类型：1 = Ethernet
LINKTYPE_ETHERNET = 1
#: 单包最大长度
SNAPLEN = 65535


def write_pcap(path: Path, packets: list[bytes], *, link_type: int = LINKTYPE_ETHERNET) -> None:
    """把若干链路字节写成 pcap 文件。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        fh.write(
            struct.pack(
                "<IHHiIII",
                PCAP_MAGIC,
                2,
                4,
                0,
                0,
                SNAPLEN,
                link_type,
            )
        )
        for packet in packets:
            fh.write(struct.pack("<IIII", 0, 0, len(packet), len(packet)))
            fh.write(packet)
