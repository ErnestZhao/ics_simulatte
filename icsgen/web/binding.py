"""监听套接字的构造：让 Web 界面同时接 IPv4 与 IPv6。

asyncio 建监听套接字时会显式关掉双栈（`IPV6_V6ONLY=True`），于是
`uvicorn --host ::` 只接 IPv6、`--host 0.0.0.0` 只接 IPv4。双栈主机上
客户端从哪一族进来并不由我们决定 —— 套接字自己造，两族都交给 uvicorn。

套接字在这里只 bind，listen 与 accept 由 uvicorn 接管。
"""

from __future__ import annotations

import socket

#: IPv4 全地址
_IPV4_WILDCARD = "0.0.0.0"
#: IPv6 全地址
_IPV6_WILDCARD = "::"


def _make(family: int, address: str, port: int, *, v6only: bool = True) -> socket.socket:
    """造一个已 bind 的监听套接字。"""
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, v6only)
    sock.bind((address, port))
    return sock


def build_listeners(host: str, port: int) -> list[socket.socket]:
    """按监听地址造出监听套接字。

    - ``0.0.0.0``：同时监听 IPv4 全地址与 IPv6 全地址。IPv6 那只设
      ``IPV6_V6ONLY=1``，两只互不抢占端口。
    - ``::``：只造一只双栈套接字（``IPV6_V6ONLY=0``），IPv4 客户端以
      ``::ffff:`` 映射地址进来。
    - 其它地址：只监听该地址。

    ``port`` 传 0 时由内核分配端口；多只套接字共用同一个分配到的端口。
    """
    specs = _plan(host, port)
    listeners: list[socket.socket] = []
    try:
        for family, address, v6only in specs:
            bind_port = port
            if bind_port == 0 and listeners:
                # 端口由内核分配：后续套接字必须跟上第一只，否则
                # 同一族里会出现两个不同的监听点。
                bind_port = listeners[0].getsockname()[1]
            listeners.append(_make(family, address, bind_port, v6only=v6only))
    except OSError:
        for listener in listeners:
            listener.close()
        raise
    return listeners


def _plan(host: str, port: int) -> list[tuple[int, str, bool]]:
    """列出要监听的（地址族，地址，是否双栈）。"""
    if host in ("", _IPV4_WILDCARD):
        return [
            (socket.AF_INET, _IPV4_WILDCARD, False),
            (socket.AF_INET6, _IPV6_WILDCARD, True),
        ]
    if host == _IPV6_WILDCARD:
        return [(socket.AF_INET6, _IPV6_WILDCARD, False)]
    plans: list[tuple[int, str, bool]] = []
    seen: set[int] = set()
    for family, _socktype, _proto, _canon, sockaddr in socket.getaddrinfo(
        host, port, type=socket.SOCK_STREAM
    ):
        if family in seen:
            continue
        seen.add(family)
        plans.append((family, sockaddr[0], True))
    if not plans:
        raise OSError(f"无法解析监听地址 {host!r}")
    return plans
