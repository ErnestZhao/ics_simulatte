"""传输层配置。"""

from __future__ import annotations

from dataclasses import dataclass, replace

#: 未指定源端口时的起始端口，后续按会话递增
DEFAULT_SOURCE_PORT = 40001


@dataclass(frozen=True)
class TransportSpec:
    """一次流量会话的传输层参数。"""

    kind: str = "tcp"
    dport: int = 502
    sport: int | None = None
    src_ip: str = "192.168.1.10"
    dst_ip: str = "192.168.1.20"
    mac_src: str = "02:00:00:00:00:01"
    mac_dst: str = "02:00:00:00:00:02"
    vlan_id: int | None = None

    def reversed(self) -> "TransportSpec":
        """返回方向相反的传输配置。

        一次操作会产出请求与响应两帧，响应由服务端发往客户端，因此源/目的
        的 IP、MAC 与端口都要对调。
        """
        return replace(
            self,
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            mac_src=self.mac_dst,
            mac_dst=self.mac_src,
            sport=self.dport,
            dport=self.sport if self.sport is not None else DEFAULT_SOURCE_PORT,
        )
