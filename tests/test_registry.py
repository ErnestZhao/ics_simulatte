"""协议注册表：协议枚举与传输名映射。"""

import pytest
from typer.testing import CliRunner

from icsgen.cli import app
from icsgen.protocols.registry import (
    available_protocols,
    get_adapter,
    get_catalog,
    get_protocol,
    transport_kind,
)


def test_registry_lists_modbus():
    assert [info.name for info in available_protocols()] == ["modbus"]


def test_registry_entry_exposes_catalog_stats():
    info = get_protocol("modbus")
    catalog = get_catalog("modbus")
    assert info.transports == catalog.transports
    assert catalog.count() == 41
    assert catalog.coverage_count() == 192


def test_registry_unknown_protocol_raises():
    with pytest.raises(KeyError, match="未注册协议"):
        get_protocol("cip")


def test_registry_adapter_is_usable():
    adapter = get_adapter("modbus")
    assert adapter.name == "modbus"
    assert len(adapter.operations) == 41


def test_transport_kind_maps_catalog_names():
    assert transport_kind("tcp") == "tcp"
    assert transport_kind("rtu") == "serial"


def test_transport_kind_unknown_raises():
    with pytest.raises(KeyError, match="无对应的链路类型"):
        transport_kind("bluetooth")


def test_cli_reports_unknown_protocol():
    result = CliRunner().invoke(app, ["catalog", "--protocol", "cip"])
    assert result.exit_code != 0
    assert "未注册协议" in result.output
