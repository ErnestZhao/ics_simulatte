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
