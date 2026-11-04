"""传输层配置。"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from typing import Any, Mapping

#: 未指定源端口时的起始端口，后续按会话递增
DEFAULT_SOURCE_PORT = 40001

#: 传输种类：tcp / udp / serial
TRANSPORT_KINDS = ("tcp", "udp", "serial")

#: 会话形态：full = 握手 + 数据 + 挥手；data = 只发数据段
SESSION_MODES = ("full", "data")


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
    session: str = "full"

    def __post_init__(self) -> None:
        """取值必须合法 —— 取值集合只在传输层声明一处。

        传输种类与会话形态都在这里校验：构造器是唯一的事实源，早失败
        总比拖到封装层才炸好 —— 那里的报错看不出是哪个字段写错了。
        """
        if self.kind not in TRANSPORT_KINDS:
            raise ValueError(
                f"未知的传输种类 {self.kind!r}，可用：{list(TRANSPORT_KINDS)}"
            )
        if self.session not in SESSION_MODES:
            raise ValueError(
                f"未知的会话形态 {self.session!r}，可用：{list(SESSION_MODES)}"
            )

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

    def to_dict(self) -> dict[str, Any]:
        """序列化为普通字典，供 manifest 记录。"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TransportSpec":
        """从 manifest 里记录的字典还原传输配置。"""
        return cls(**dict(data))
