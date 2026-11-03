"""基于 pymodbus 的 Modbus PLC 服务端模拟。

plc 角色被动应答，模拟被读取的现场设备；
client 角色主动发起请求并接收响应，产出成对的请求/响应会话。

pymodbus 3.16 的服务端是 asyncio 原生的：构造服务端需要一个正在运行的事件
循环，``serve_forever`` / ``shutdown`` 都是协程。因此这里在独立线程里跑一个
事件循环，把同步的 start / stop 契约包在它外面。
"""

from __future__ import annotations

import asyncio
import threading
import time

from pymodbus.client import ModbusTcpClient
from pymodbus.server import ModbusTcpServer
from pymodbus.simulator import DataType, SimData, SimDevice

#: 模拟寄存器区的初始值
INITIAL_REGISTER_VALUE = 0

#: 保持寄存器数量
HOLDING_REGISTER_COUNT = 1000

#: 线圈与离散输入的数量
BIT_COUNT = 1000

#: 等待服务端开始监听的超时时间（秒）
STARTUP_TIMEOUT = 5.0


def _build_device(unit_id: int) -> SimDevice:
    """构造被模拟的设备。

    线圈、离散输入、保持寄存器、输入寄存器是四块独立区域，各自从地址 0
    开始编号。
    """
    coils = SimData(address=0, count=BIT_COUNT, values=False, datatype=DataType.BITS)
    discrete_inputs = SimData(
        address=0, count=BIT_COUNT, values=False, datatype=DataType.BITS
    )
    holding_registers = SimData(
        address=0,
        count=HOLDING_REGISTER_COUNT,
        values=INITIAL_REGISTER_VALUE,
        datatype=DataType.REGISTERS,
    )
    input_registers = SimData(
        address=0,
        count=HOLDING_REGISTER_COUNT,
        values=INITIAL_REGISTER_VALUE,
        datatype=DataType.REGISTERS,
    )
    return SimDevice(
        id=unit_id,
        simdata=(
            [coils],
            [discrete_inputs],
            [holding_registers],
            [input_registers],
        ),
    )


class ModbusPlcServer:
    """Modbus PLC 服务端。"""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 5020,
        role: str = "plc",
        unit_id: int = 1,
    ) -> None:
        if role not in {"plc", "client"}:
            raise ValueError(f"不支持的角色 {role!r}，可选 plc / client")
        self.host = host
        self.port = port
        self.role = role
        self.unit_id = unit_id
        self._server: ModbusTcpServer | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._ready = threading.Event()
        self._error: BaseException | None = None

    @property
    def address(self) -> str:
        """服务监听地址。"""
        return f"tcp://{self.host}:{self.port}"

    def start(self) -> None:
        """启动服务。"""
        if self.role == "client":
            self._thread = threading.Thread(target=self._run_client, daemon=True)
            self._thread.start()
            return
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        # 监听就绪前不返回：调用方拿到服务后就应当能连上
        if not self._ready.wait(timeout=STARTUP_TIMEOUT):
            raise RuntimeError(f"Modbus 服务端未能在 {self.address} 上开始监听")
        if self._error is not None:
            raise self._error

    def stop(self) -> None:
        """停止服务。"""
        self._stop_event.set()
        if self._loop is not None and self._server is not None:
            future = asyncio.run_coroutine_threadsafe(self._server.shutdown(), self._loop)
            try:
                future.result(timeout=STARTUP_TIMEOUT)
            except Exception:  # noqa: BLE001 —— 关停失败不应掩盖原始异常
                pass
        if self._thread is not None:
            self._thread.join(timeout=STARTUP_TIMEOUT)
            self._thread = None
        self._server = None
        self._loop = None

    def _serve(self) -> None:
        """在独立线程里跑事件循环。"""
        assert self._loop is not None
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._serve_async())
        except BaseException as exc:  # noqa: BLE001 —— 启动失败要传回调用方
            self._error = exc
            self._ready.set()

    async def _serve_async(self) -> None:
        """监听并应答，直到被关闭。"""
        server = ModbusTcpServer(
            context=_build_device(self.unit_id),
            address=(self.host, self.port),
        )
        self._server = server
        # background=True：只负责开始监听，后续由 serving 事件控制生命周期
        await server.serve_forever(background=True)
        self._ready.set()
        await server.serving

    def _run_client(self) -> None:
        """主动请求模式：发起一组读写操作并接收响应。"""
        client = ModbusTcpClient(self.host, port=self.port, timeout=3)
        try:
            client.connect()
        except OSError:
            return
        try:
            while not self._stop_event.is_set():
                self._exchange(client)
        finally:
            client.close()

    def _exchange(self, client: ModbusTcpClient) -> None:
        """执行一轮读写交互。"""
        try:
            client.read_holding_registers(0, count=8, device_id=self.unit_id)
            client.write_register(0, value=0x1234, device_id=self.unit_id)
            client.read_input_registers(0, count=8, device_id=self.unit_id)
        except OSError:
            time.sleep(0.2)


def run_modbus_server(transport: str, host: str, port: int, role: str) -> None:
    """阻塞运行 Modbus 服务端，直到进程被中断。"""
    if transport not in {"tcp", "serial"}:
        raise ValueError(f"不支持的传输类型 {transport!r}")
    server = ModbusPlcServer(host=host, port=port, role=role)
    server.start()
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
