"""监听套接字的构造：IPv4 与 IPv6 都要接得住。"""

import socket

import pytest

from icsgen.web.binding import build_listeners


def _free_port() -> int:
    """拿一个当前空闲的端口。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _close_all(listeners: list[socket.socket]) -> None:
    for listener in listeners:
        listener.close()


def test_ipv4_wildcard_also_listens_ipv6():
    """`0.0.0.0` 要同时覆盖 IPv4 与 IPv6 —— 双栈主机上客户端从哪族来都行。"""
    port = _free_port()
    listeners = build_listeners("0.0.0.0", port)
    try:
        assert len(listeners) == 2
        families = {listener.family for listener in listeners}
        assert families == {socket.AF_INET, socket.AF_INET6}
        for listener in listeners:
            assert listener.getsockname()[1] == port
    finally:
        _close_all(listeners)


def test_ipv4_and_ipv6_wildcards_do_not_collide():
    """两只套接字抢同一个端口不冲突 —— IPv6 那只必须是 v6-only。"""
    port = _free_port()
    listeners = build_listeners("0.0.0.0", port)
    try:
        v6 = next(listener for listener in listeners if listener.family == socket.AF_INET6)
        v6only = v6.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY)
        assert v6only == 1
    finally:
        _close_all(listeners)


def test_ipv6_wildcard_is_dual_stack():
    """`::` 造出的是一只双栈套接字：IPv4 客户端以映射地址进来。"""
    port = _free_port()
    listeners = build_listeners("::", port)
    try:
        assert len(listeners) == 1
        listener = listeners[0]
        assert listener.family == socket.AF_INET6
        assert listener.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY) == 0
        listener.listen(8)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
            assert client.family == socket.AF_INET
            connected, _ = listener.accept()
            connected.close()
    finally:
        _close_all(listeners)


def test_specific_address_binds_only_that_family():
    """具体地址只监听该地址，不牵扯另一族。"""
    port = _free_port()
    listeners = build_listeners("127.0.0.1", port)
    try:
        assert len(listeners) == 1
        assert listeners[0].family == socket.AF_INET
        assert listeners[0].getsockname()[0] == "127.0.0.1"
    finally:
        _close_all(listeners)


def test_unknown_address_is_rejected():
    with pytest.raises(OSError):
        build_listeners("no-such-host.invalid", 8080)


def test_port_zero_shares_one_assigned_port():
    """端口为 0 时由内核分配 —— 两只套接字必须共用同一个端口。"""
    listeners = build_listeners("0.0.0.0", 0)
    try:
        ports = {listener.getsockname()[1] for listener in listeners}
        assert len(ports) == 1
        assert ports != {0}
    finally:
        _close_all(listeners)
