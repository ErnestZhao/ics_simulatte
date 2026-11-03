"""协议注册表：协议名 → catalog 与适配器工厂的唯一映射。

CLI 与 Web 层共用这张表。新增协议只需在这里登记一行，
框架代码与页面都不需要改动。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..spec.catalog import Catalog, load_catalog
from .base import ProtocolAdapter

#: catalog 里的传输名 → TransportSpec.kind
_TRANSPORT_KINDS = {"tcp": "tcp", "rtu": "serial"}


@dataclass(frozen=True)
class ProtocolInfo:
    """一个协议的注册信息。"""

    name: str
    summary: str
    transports: tuple[str, ...]
    catalog_path: Path
    adapter_factory: Callable[[], ProtocolAdapter]


def _modbus_info() -> ProtocolInfo:
    """Modbus 的注册信息。传输名取自 catalog，避免第二事实源。"""
    from .modbus.adapter import CATALOG_PATH, load_modbus_adapter

    catalog = load_catalog(CATALOG_PATH)
    return ProtocolInfo(
        name=catalog.protocol,
        summary="Modbus TCP / RTU",
        transports=catalog.transports,
        catalog_path=CATALOG_PATH,
        adapter_factory=load_modbus_adapter,
    )


#: 已注册协议。新增协议在此登记一行即可。
_REGISTRY: dict[str, ProtocolInfo] = {
    "modbus": _modbus_info(),
}


def available_protocols() -> list[ProtocolInfo]:
    """全部已注册协议，按名称排序。"""
    return [_REGISTRY[name] for name in sorted(_REGISTRY)]


def get_protocol(name: str) -> ProtocolInfo:
    """按名字取协议信息，未注册时抛 KeyError。"""
    try:
        return _REGISTRY[name]
    except KeyError as exc:
        raise KeyError(f"未注册协议 {name!r}，已注册：{sorted(_REGISTRY)}") from exc


def get_catalog(name: str) -> Catalog:
    """取协议的操作目录。"""
    return load_catalog(get_protocol(name).catalog_path)


def get_adapter(name: str) -> ProtocolAdapter:
    """取协议的适配器实例。"""
    return get_protocol(name).adapter_factory()


def transport_kind(catalog_transport: str) -> str:
    """catalog 里的传输名 → TransportSpec.kind。"""
    try:
        return _TRANSPORT_KINDS[catalog_transport]
    except KeyError as exc:
        raise KeyError(
            f"传输名 {catalog_transport!r} 无对应的链路类型，已知：{sorted(_TRANSPORT_KINDS)}"
        ) from exc
