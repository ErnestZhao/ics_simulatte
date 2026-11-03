"""PLC 服务端模拟。"""

import pytest
from pymodbus.client import ModbusTcpClient

from icsgen.server.base import PlcServer
from icsgen.server.modbus_server import ModbusPlcServer


def test_plc_server_contract():
    assert hasattr(PlcServer, "start")
    assert hasattr(PlcServer, "stop")
    assert hasattr(PlcServer, "address")


def test_plc_server_answers_read_request():
    """PLC 角色应能响应保持寄存器读取请求。"""
    server = ModbusPlcServer(host="127.0.0.1", port=15020, role="plc")
    server.start()
    try:
        client = ModbusTcpClient("127.0.0.1", port=15020, timeout=3)
        client.connect()
        assert client.connected
        result = client.read_holding_registers(0, count=4, device_id=1)
        assert not result.isError()
        assert len(result.registers) == 4
        client.close()
    finally:
        server.stop()


def test_plc_server_address_is_reported():
    server = ModbusPlcServer(host="127.0.0.1", port=15021, role="plc")
    assert "15021" in server.address
