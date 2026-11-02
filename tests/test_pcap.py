"""pcap 写出与原始字节导出。"""

from scapy.all import Ether, IP, TCP, rdpcap

from icsgen.emit.raw import write_raw
from icsgen.transport.link import encapsulate
from icsgen.transport.pcap import write_pcap
from icsgen.transport.spec import TransportSpec


def test_write_pcap_creates_readable_file(tmp_path):
    path = tmp_path / "out.pcap"
    packets = [encapsulate(b"\x01\x02\x03", TransportSpec()), encapsulate(b"\x04\x05", TransportSpec())]
    write_pcap(path, packets)
    assert path.exists()
    read = rdpcap(str(path))
    assert len(read) == 2
    assert bytes(read[0][TCP].payload) == b"\x01\x02\x03"


def test_pcap_global_header_is_little_endian(tmp_path):
    path = tmp_path / "out.pcap"
    write_pcap(path, [])
    header = path.read_bytes()[:24]
    assert header[:4] == b"\xd4\xc3\xb2\xa1"
    assert int.from_bytes(header[20:24], "little") == 1


def test_write_raw_creates_bin_and_hex(tmp_path):
    bin_path, hex_path = write_raw(tmp_path, "sample", b"\x01\x02\xff")
    assert bin_path.read_bytes() == b"\x01\x02\xff"
    assert hex_path.read_text(encoding="utf-8").strip() == "01 02 ff"


def test_write_raw_hex_is_readable_back(tmp_path):
    bin_path, hex_path = write_raw(tmp_path, "sample", b"\xde\xad\xbe\xef")
    text = hex_path.read_text(encoding="utf-8")
    assert bytes.fromhex(text.replace(" ", "")) == bin_path.read_bytes()
