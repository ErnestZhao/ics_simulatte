"""PLC 服务端模拟的公共契约。"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class PlcServer(Protocol):
    """模拟一台现场设备的最小契约。"""

    def start(self) -> None:
        """启动服务。"""
        ...

    def stop(self) -> None:
        """停止服务。"""
        ...

    @property
    def address(self) -> str:
        """服务监听地址，形如 tcp://127.0.0.1:5020。"""
        ...
