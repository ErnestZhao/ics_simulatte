# P1 Modbus 流量生成器 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 交付 P1 —— 基于自研字段表驱动编解码内核的 Modbus TCP/RTU 工控协议流量生成器，可离线产出 pcap / bin / hex / manifest 分层数据集，并提供 PLC 服务端模拟与确定性变异引擎。

**Architecture:** 五层单向依赖：场景描述层（YAML）→ 协议适配层（catalog 驱动编解码）→ 传输封装层（Ethernet/IP/TCP）→ 产出层（pcap/bin/hex/manifest）。编解码内核（`icsgen/codec/`）是自研的字段表驱动实现，catalog 中的字段布局声明直接驱动编码与解码；Scapy 仅用于链路封装与作为独立第三方解析器交叉验证自研内核的正确性。

**Tech Stack:** Python 3.11 · Scapy ≥2.6（链路封装 + 交叉验证解析器）· pymodbus ≥3.8（PLC 服务端模拟）· pydantic ≥2.0 + jsonschema ≥4.20（catalog 与场景校验）· Typer ≥0.9（CLI）· PyYAML ≥6.0 · pytest ≥8.0

**Spec:** `docs/superpowers/specs/2026-10-30-ics-traffic-generator-design.md`

## Global Constraints

以下约束适用于本计划中的每一个任务：

- Python 版本：`>=3.11`
- 包名：`icsgen`，命令行入口：`icsgen = "icsgen.cli:app"`，位于 `icsgen/cli.py`
- 全部代码注释与 docstring 使用简体中文
- 类型注解齐全，使用 `from __future__ import annotations`
- **不使用** `construct` 等二进制 DSL 库；编解码内核自研
- Scapy **仅**用于链路封装与测试中的第三方交叉验证，不得作为 Modbus PDU 的编解码后端
- catalog 是操作类型的唯一事实源；新增操作类型不得修改框架代码
- 变体 → 语义层映射固定为：`normal`/`boundary` → `legit`，`exception`/`illegal_fc`/`malformed` → `abnormal`；`mutated` 仅由变异引擎产生
- 所有随机性必须来自显式传入的 `seed`，同 seed + 同输入必得同输出
- 每个任务结束前必须提交，提交信息末尾附 `Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>`
- 不得提交 `datasets/` 目录内容（已在 `.gitignore` 中）
- 测试命令统一为 `python3 -m pytest tests/<path> -v`，在项目根目录 `/home/szhao/ics` 执行

---

## File Structure

```
ics/
├── pyproject.toml                      # 依赖、入口、pytest 配置
├── README.md                           # 用法说明
├── .gitignore                          # 已存在：忽略 datasets/、__pycache__
├── icsgen/
│   ├── __init__.py                     # 包标记，导出 __version__
│   ├── paths.py                        # 默认路径常量
│   ├── cli.py                          # Typer 命令面
│   ├── codec/
│   │   ├── __init__.py
│   │   ├── fields.py                   # Field / Layout / 字段尺寸表
│   │   ├── encoder.py                  # encode(fields, values) -> bytes
│   │   └── decoder.py                  # decode(fields, data, offset) -> dict
│   ├── spec/
│   │   ├── __init__.py
│   │   ├── model.py                    # Tier / Variant / Operation / Scenario
│   │   ├── catalog.py                  # catalog.yaml 加载与查询
│   │   └── loader.py                   # 场景 YAML 加载与参数校验
│   ├── protocols/
│   │   ├── __init__.py
│   │   ├── base.py                     # OperationSpec / ProtocolFrame / BuildContext
│   │   └── modbus/
│   │       ├── __init__.py
│   │       ├── layouts.py              # 字段布局表
│   │       ├── crc.py                  # CRC16
│   │       ├── framing.py              # MBAP 组帧 / RTU 组帧
│   │       ├── variants.py             # 变体取值策略
│   │       ├── adapter.py              # ModbusAdapter
│   │       └── catalog.yaml            # 41 个操作类型
│   ├── transport/
│   │   ├── __init__.py
│   │   ├── spec.py                     # TransportSpec
│   │   ├── link.py                     # Ethernet/IP/TCP/UDP 封装
│   │   └── pcap.py                     # pcap 文件写出
│   ├── emit/
│   │   ├── __init__.py
│   │   ├── raw.py                      # .bin / .hex 导出
│   │   └── dataset.py                  # Artifact / DatasetBuilder / manifest
│   ├── mutate/
│   │   ├── __init__.py
│   │   ├── rules.py                    # 12 条变异规则
│   │   └── engine.py                   # 变异引擎
│   └── server/
│       ├── __init__.py
│       ├── base.py                     # PlcServer 契约
│       └── modbus_server.py            # 基于 pymodbus
├── scenarios/
│   └── modbus_demo.yaml                # 示例场景
└── tests/
    ├── test_codec.py
    ├── test_spec_model.py
    ├── test_catalog.py
    ├── test_modbus_layouts.py
    ├── test_modbus_framing.py
    ├── test_modbus_variants.py
    ├── test_transport_link.py
    ├── test_pcap.py
    ├── test_emit_dataset.py
    ├── test_mutate.py
    ├── test_cli.py
    ├── test_server.py
    └── test_e2e.py
```

**模块职责边界**：`codec/` 是纯字节转换，无协议知识；`protocols/modbus/` 只产出协议帧，不涉及 IP/TCP/以太；`transport/` 只做链路封装，不了解协议语义；`emit/` 只负责写盘，不理解协议。

---

## Task 1: 项目骨架与核心数据模型

**Files:**
- Create: `pyproject.toml`
- Create: `icsgen/__init__.py`
- Create: `icsgen/paths.py`
- Create: `icsgen/spec/__init__.py`
- Create: `icsgen/spec/model.py`
- Create: `tests/test_spec_model.py`

**Interfaces:**
- Consumes: 无（首个任务）
- Produces:
  - `icsgen.spec.model.Tier(str, Enum)`：`LEGIT="legit"` / `ABNORMAL="abnormal"` / `MUTATED="mutated"`
  - `icsgen.spec.model.Variant(str, Enum)`：`NORMAL="normal"` / `BOUNDARY="boundary"` / `EXCEPTION="exception"` / `ILLEGAL_FC="illegal_fc"` / `MALFORMED="malformed"`
  - `icsgen.spec.model.VARIANT_TIER: dict[Variant, Tier]`
  - `icsgen.spec.model.Operation`：`frozen dataclass`，字段 `op: str`、`params: dict[str, Any] = {}`、`variant: Variant = NORMAL`、`tier: Tier | None = None`、`expect_response: bool = True`
  - `icsgen.spec.model.Scenario`：`frozen dataclass`，字段 `name: str`、`description: str = ""`、`transport: dict[str, Any] = {}`、`operations: tuple[Operation, ...] = ()`

- [ ] **Step 1: 写失败的测试**

创建 `tests/test_spec_model.py`：

```python
"""核心数据模型的语义层与变体映射规则。"""

import pytest

from icsgen.spec.model import VARIANT_TIER, Operation, Scenario, Tier, Variant


def test_variant_tier_mapping_is_complete():
    """每个变体都必须有确定的语义层归属。"""
    assert set(VARIANT_TIER) == set(Variant)
    assert VARIANT_TIER[Variant.NORMAL] is Tier.LEGIT
    assert VARIANT_TIER[Variant.BOUNDARY] is Tier.LEGIT
    assert VARIANT_TIER[Variant.EXCEPTION] is Tier.ABNORMAL
    assert VARIANT_TIER[Variant.ILLEGAL_FC] is Tier.ABNORMAL
    assert VARIANT_TIER[Variant.MALFORMED] is Tier.ABNORMAL


def test_tier_defaults_to_variant_mapping():
    """未显式声明 tier 时，tier 由 variant 推导。"""
    op = Operation(op="modbus.read_coils", variant=Variant.EXCEPTION)
    assert op.tier is Tier.ABNORMAL


def test_conflicting_tier_is_rejected():
    """显式 tier 与 variant 冲突时报错。"""
    with pytest.raises(ValueError, match="冲突"):
        Operation(op="modbus.read_coils", variant=Variant.NORMAL, tier=Tier.ABNORMAL)


def test_operation_defaults():
    op = Operation(op="modbus.read_coils")
    assert op.params == {}
    assert op.variant is Variant.NORMAL
    assert op.tier is Tier.LEGIT
    assert op.expect_response is True


def test_scenario_is_immutable_container():
    scenario = Scenario(name="demo", operations=(Operation(op="modbus.read_coils"),))
    assert scenario.operations[0].op == "modbus.read_coils"
    with pytest.raises(Exception):
        scenario.name = "other"  # type: ignore[misc]
```

- [ ] **Step 2: 运行测试确认失败**

Run: `python3 -m pytest tests/test_spec_model.py -v`
Expected: FAIL —— `ModuleNotFoundError: No module named 'icsgen'`

- [ ] **Step 3: 写最小实现**

创建 `pyproject.toml`：

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "icsgen"
version = "0.1.0"
description = "ICS 工控协议流量生成器"
requires-python = ">=3.11"
dependencies = [
    "scapy>=2.6",
    "pymodbus>=3.8",
    "pydantic>=2.0",
    "jsonschema>=4.20",
    "typer>=0.9",
    "pyyaml>=6.0",
]

[project.optional-dependencies]
dev = ["pytest>=8.0"]

[project.scripts]
icsgen = "icsgen.cli:app"

[tool.setuptools.packages.find]
include = ["icsgen*"]

[tool.setuptools.package-data]
"icsgen.protocols.modbus" = ["catalog.yaml"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

创建 `icsgen/__init__.py`：

```python
"""ICS 工控协议流量生成器。"""

__version__ = "0.1.0"
```

创建 `icsgen/paths.py`：

```python
"""项目内默认路径常量。"""

from pathlib import Path

#: 项目根目录（icsgen 包的父目录）
PROJECT_ROOT = Path(__file__).resolve().parent.parent

#: 内置场景目录
SCENARIOS_DIR = PROJECT_ROOT / "scenarios"

#: 数据集默认输出目录
DATASETS_DIR = PROJECT_ROOT / "datasets"
```

创建 `icsgen/spec/__init__.py`（空文件）。

创建 `icsgen/spec/model.py`：

```python
"""核心数据模型：语义层、变体、操作与场景。

语义层（Tier）描述产物在数据集中的归属，变体（Variant）描述同一操作的
语义形态。两者是固定映射关系，场景中显式声明 tier 时必须与变体一致。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Tier(str, Enum):
    """数据集语义分层。"""

    LEGIT = "legit"
    ABNORMAL = "abnormal"
    MUTATED = "mutated"


class Variant(str, Enum):
    """同一操作的语义形态。"""

    NORMAL = "normal"
    BOUNDARY = "boundary"
    EXCEPTION = "exception"
    ILLEGAL_FC = "illegal_fc"
    MALFORMED = "malformed"


#: 变体到语义层的固定映射
VARIANT_TIER: dict[Variant, Tier] = {
    Variant.NORMAL: Tier.LEGIT,
    Variant.BOUNDARY: Tier.LEGIT,
    Variant.EXCEPTION: Tier.ABNORMAL,
    Variant.ILLEGAL_FC: Tier.ABNORMAL,
    Variant.MALFORMED: Tier.ABNORMAL,
}


@dataclass(frozen=True)
class Operation:
    """一次协议操作。

    tier 省略时由 variant 推导；显式声明且与 variant 冲突时构造即报错。
    """

    op: str
    params: dict[str, Any] = field(default_factory=dict)
    variant: Variant = Variant.NORMAL
    tier: Tier | None = None
    expect_response: bool = True

    def __post_init__(self) -> None:
        expected = VARIANT_TIER[self.variant]
        if self.tier is None:
            object.__setattr__(self, "tier", expected)
        elif self.tier != expected:
            raise ValueError(
                f"操作 {self.op!r} 的 variant={self.variant.value} 隐含 tier="
                f"{expected.value}，与显式声明的 {self.tier.value} 冲突"
            )


@dataclass(frozen=True)
class Scenario:
    """一个场景：一次有序的协议操作序列 + 传输层配置。"""

    name: str
    description: str = ""
    transport: dict[str, Any] = field(default_factory=dict)
    operations: tuple[Operation, ...] = ()
```

- [ ] **Step 4: 运行测试确认通过**

Run: `python3 -m pytest tests/test_spec_model.py -v`
Expected: PASS —— 5 passed

- [ ] **Step 5: 提交**

```bash
git add pyproject.toml icsgen/__init__.py icsgen/paths.py icsgen/spec/ tests/test_spec_model.py
git commit -m "$(cat <<'EOF'
feat: 项目骨架与核心数据模型

建立 Tier/Variant 语义层映射、Operation 与 Scenario 模型，
变体与语义层的冲突在构造时即报错。

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: 字段表驱动的二进制编解码内核

**Files:**
- Create: `icsgen/codec/__init__.py`
- Create: `icsgen/codec/fields.py`
- Create: `icsgen/codec/encoder.py`
- Create: `icsgen/codec/decoder.py`
- Create: `tests/test_codec.py`

**Interfaces:**
- Consumes: 无
- Produces:
  - `icsgen.codec.fields.FIELD_SIZES: dict[str, int]` —— `{"uint8":1,"int8":1,"uint16":2,"int16":2,"uint32":4,"int32":4,"bytes":1}`
  - `icsgen.codec.fields.Field`：`frozen dataclass`，字段 `name: str`、`type: str`、`count_of: str | None = None`、`count_from: str | None = None`、`len_from_request: str | None = None`、`adjust: Callable[[int], int] | None = None`、`default: Any = None`
  - `icsgen.codec.fields.Layout`：`frozen dataclass`，字段 `request: tuple[Field, ...] = ()`、`response: tuple[Field, ...] = ()`
  - `icsgen.codec.encoder.CodecError(ValueError)`
  - `icsgen.codec.encoder.encode(fields: tuple[Field, ...], values: Mapping[str, Any]) -> bytes`
  - `icsgen.codec.decoder.decode(fields: tuple[Field, ...], data: bytes, offset: int = 0) -> dict[str, Any]`

字段修饰符语义（编码视角与解码视角各用其一）：

- `count_of`：编码时本字段的值 = 被引用字段的元素个数，经 `adjust` 换算后写入
- `count_from`：解码时本字段是变长数组，元素个数 = 被引用字段的值 ÷ 本字段类型宽度
- `len_from_request`：构造时本数组的元素个数 = 该参数的值。响应数组的参数在请求里（如 FC03 响应的寄存器数等于请求的 quantity）；请求数组的参数在同一请求里（如 FC10 的 values 元素数等于同帧的 quantity）。仅用于构造，不影响编解码
- `adjust`：写入长度字段前的换算函数，如 Modbus 的 `byte_count = len(values) * 2`

- [ ] **Step 1: 写失败的测试**

创建 `tests/test_codec.py`：

```python
"""字段表驱动的编解码内核。"""

import pytest

from icsgen.codec.decoder import DecodeError, decode
from icsgen.codec.encoder import CodecError, encode
from icsgen.codec.fields import Field, Layout


def test_encode_fixed_width_fields():
    fields = (Field("start_addr", "uint16"), Field("quantity", "uint16"))
    assert encode(fields, {"start_addr": 0x0001, "quantity": 0x0003}) == b"\x00\x01\x00\x03"


def test_encode_signed_field():
    fields = (Field("value", "int16"),)
    assert encode(fields, {"value": -2}) == b"\xff\xfe"


def test_encode_count_of_with_adjust():
    """byte_count 由 values 长度乘 2 得出。"""
    fields = (
        Field("byte_count", "uint8", count_of="values", adjust=lambda n: n * 2),
        Field("values", "uint16", count_from="byte_count"),
    )
    out = encode(fields, {"values": [0xDEAD, 0xBEEF]})
    assert out == b"\x04\xde\xad\xbe\xef"


def test_encode_bytes_array():
    fields = (Field("length", "uint8", count_of="data"), Field("data", "bytes", count_from="length"))
    assert encode(fields, {"data": b"\x01\x02"}) == b"\x02\x01\x02"


def test_encode_uses_default_when_value_missing():
    fields = (Field("unit_id", "uint8", default=0xFF),)
    assert encode(fields, {}) == b"\xff"


def test_encode_missing_required_field_raises():
    fields = (Field("start_addr", "uint16"),)
    with pytest.raises(CodecError, match="缺少字段"):
        encode(fields, {})


def test_encode_unknown_type_raises():
    fields = (Field("weird", "uint64"),)
    with pytest.raises(CodecError, match="未知字段类型"):
        encode(fields, {"weird": 1})


def test_decode_round_trip():
    fields = (
        Field("byte_count", "uint8", count_of="values", adjust=lambda n: n * 2),
        Field("values", "uint16", count_from="byte_count"),
    )
    raw = b"\x04\xde\xad\xbe\xef"
    assert decode(fields, raw) == {"byte_count": 4, "values": [0xDEAD, 0xBEEF]}


def test_decode_from_offset():
    fields = (Field("quantity", "uint16"),)
    assert decode(fields, b"\xff\xff\x00\x07", offset=2) == {"quantity": 7}


def test_decode_insufficient_data_raises():
    fields = (Field("start_addr", "uint16"),)
    with pytest.raises(Exception, match="数据不足"):
        decode(fields, b"\x00")


def test_layout_holds_request_and_response():
    layout = Layout(request=(Field("a", "uint8"),), response=(Field("b", "uint16"),))
    assert len(layout.request) == 1
    assert len(layout.response) == 1


def test_bytes_field_round_trips():
    """bytes 型变长字段编码后能原样解码回来（编解码器对称）。"""
    fields = (Field("length", "uint8", count_of="data"), Field("data", "bytes", count_from="length"))
    encoded = encode(fields, {"data": b"\x01\x02"})
    assert encoded == b"\x02\x01\x02"
    assert decode(fields, encoded) == {"length": 2, "data": b"\x01\x02"}


def test_encode_bytes_value_out_of_range_raises():
    """bytes 类型的值域错误收敛为 CodecError，而不是裸 ValueError。"""
    fields = (Field("length", "uint8", count_of="data"), Field("data", "bytes", count_from="length"))
    with pytest.raises(CodecError, match="无法编码为 bytes"):
        encode(fields, {"data": [256]})


def test_decode_unknown_type_raises():
    """未知字段类型解码时报 DecodeError，而不是裸 KeyError。"""
    fields = (Field("n", "uint8"), Field("weird", "uint64", count_from="n"))
    with pytest.raises(DecodeError, match="未知字段类型"):
        decode(fields, b"\x02\x00")
```

- [ ] **Step 2: 运行测试确认失败**

Run: `python3 -m pytest tests/test_codec.py -v`
Expected: FAIL —— `ModuleNotFoundError: No module named 'icsgen.codec'`

- [ ] **Step 3: 写最小实现**

创建 `icsgen/codec/__init__.py`（空文件）。

创建 `icsgen/codec/fields.py`：

```python
"""字段表驱动的编解码内核：字段声明与布局定义。

内核本身不含任何协议知识 —— 协议方通过声明 Field 序列描述报文的字节结构，
由 encoder / decoder 按声明完成转换。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

#: 各字段类型的字节宽度。bytes 视作 1 字节元素组成的数组。
FIELD_SIZES: dict[str, int] = {
    "uint8": 1,
    "int8": 1,
    "uint16": 2,
    "int16": 2,
    "uint32": 4,
    "int32": 4,
    "bytes": 1,
}


@dataclass(frozen=True)
class Field:
    """一个协议字段的声明。

    count_of:  编码时本字段的值由被引用字段的元素个数决定（被引用字段是数组时取其长度）
    count_from: 解码时本字段是变长数组，元素个数由被引用字段的值除以本字段类型宽度得出
    len_from_request: 本数组的元素个数取自该参数的值，仅用于构造：响应数组的
                参数在请求里（FC03 响应的寄存器数等于请求的 quantity），请求
                数组的参数在同一请求里（FC10 的 values 元素数等于同帧的 quantity）
    adjust:    写入长度字段前的换算函数，例如 Modbus 的 byte_count = len(values) * 2
    default:   缺省值，编码时 values 中缺少该字段则使用
    """

    name: str
    type: str
    count_of: str | None = None
    count_from: str | None = None
    len_from_request: str | None = None
    adjust: Callable[[int], int] | None = None
    default: Any = None


@dataclass(frozen=True)
class Layout:
    """一组字段的布局，描述某个操作类型的请求与响应结构。"""

    request: tuple[Field, ...] = ()
    response: tuple[Field, ...] = ()
```

创建 `icsgen/codec/encoder.py`：

```python
"""按字段布局把取值字典编码成字节。"""

from __future__ import annotations

from typing import Any, Mapping

from .fields import FIELD_SIZES, Field


class CodecError(ValueError):
    """字段值无法按布局编码。"""


def _pack_value(ftype: str, value: Any) -> bytes:
    """把单个标量值按类型打包为大端字节。"""
    size = FIELD_SIZES.get(ftype)
    if size is None:
        raise CodecError(f"未知字段类型 {ftype!r}")
    try:
        if ftype == "bytes":
            # bytes 类型视作 1 字节元素：整数按单字节写出，字节串按原样写出
            if isinstance(value, int):
                return bytes([value])
            return bytes(value)
        return int(value).to_bytes(size, "big", signed=ftype.startswith("int"))
    except (TypeError, ValueError) as exc:
        raise CodecError(f"值 {value!r} 无法编码为 {ftype}") from exc


def encode(fields: tuple[Field, ...], values: Mapping[str, Any]) -> bytes:
    """按 fields 声明把 values 编码成字节。

    count_of 字段写入被引用数组的长度（经 adjust 换算）；
    count_from 字段直接写入 values 中对应数组的各元素。
    """
    out = bytearray()
    for f in fields:
        if f.count_of is not None:
            referenced = values.get(f.count_of)
            if referenced is None:
                raise CodecError(f"字段 {f.name!r} 依赖的 {f.count_of!r} 缺失")
            if isinstance(referenced, (list, tuple, bytes, bytearray)):
                count = len(referenced)
            else:
                count = int(referenced)
            if f.adjust is not None:
                count = f.adjust(count)
            out += _pack_value(f.type, count)
            continue
        if f.count_from is not None:
            items = values.get(f.name)
            if items is None:
                raise CodecError(f"缺少数组字段 {f.name!r}")
            # bytes 类型的变长字段，其元素是 1 字节整数或 1 字节字节串，
            # 两种形态都由 _pack_value 统一处理，编码结果与解码器对称。
            for item in items:
                out += _pack_value(f.type, item)
            continue
        if f.name not in values:
            if f.default is None:
                raise CodecError(f"缺少字段 {f.name!r} 的值")
            out += _pack_value(f.type, f.default)
            continue
        out += _pack_value(f.type, values[f.name])
    return bytes(out)
```

创建 `icsgen/codec/decoder.py`：

```python
"""按字段布局把字节解码成取值字典。"""

from __future__ import annotations

from typing import Any

from .fields import FIELD_SIZES, Field


class DecodeError(ValueError):
    """字节数据无法按布局解码。"""


def _unpack_value(ftype: str, data: bytes, offset: int) -> Any:
    """从 data 的 offset 处读出一个标量值。"""
    size = FIELD_SIZES.get(ftype)
    if size is None:
        raise DecodeError(f"未知字段类型 {ftype!r}")
    if offset + size > len(data):
        remaining = len(data) - offset
        raise DecodeError(f"数据不足：偏移 {offset} 需要 {size} 字节，实际剩余 {remaining} 字节")
    chunk = data[offset : offset + size]
    if ftype == "bytes":
        return chunk
    return int.from_bytes(chunk, "big", signed=ftype.startswith("int"))


def decode(fields: tuple[Field, ...], data: bytes, offset: int = 0) -> dict[str, Any]:
    """按 fields 声明把 data 解码成取值字典。

    count_from 字段的元素个数 = 被引用字段的值 ÷ 本字段类型宽度；
    count_of 字段在解码时按普通定长字段处理。
    bytes 类型的变长字段解码为连续的 bytes 对象，与编码器对称。
    """
    values: dict[str, Any] = {}
    for f in fields:
        if f.count_from is not None:
            referenced = values.get(f.count_from)
            if referenced is None:
                raise DecodeError(f"字段 {f.name!r} 依赖的 {f.count_from!r} 尚未解码")
            width = FIELD_SIZES.get(f.type)
            if width is None:
                raise DecodeError(f"未知字段类型 {f.type!r}")
            count = int(referenced) // width
            if f.type == "bytes":
                # bytes 类型宽度为 1，长度即字节数，直接切片返回连续字节串
                if offset + count > len(data):
                    remaining = len(data) - offset
                    raise DecodeError(
                        f"数据不足：偏移 {offset} 需要 {count} 字节，实际剩余 {remaining} 字节"
                    )
                values[f.name] = data[offset : offset + count]
                offset += count
                continue
            items: list[Any] = []
            for _ in range(count):
                items.append(_unpack_value(f.type, data, offset))
                offset += width
            values[f.name] = items
            continue
        values[f.name] = _unpack_value(f.type, data, offset)
        offset += FIELD_SIZES[f.type]
    return values
```

- [ ] **Step 4: 运行测试确认通过**

Run: `python3 -m pytest tests/test_codec.py -v`
Expected: PASS —— 14 passed

- [ ] **Step 5: 提交**

```bash
git add icsgen/codec/ tests/test_codec.py
git commit -m "$(cat <<'EOF'
feat: 字段表驱动的二进制编解码内核

Field/Layout 描述报文字节结构，encode/decode 按声明完成转换。
支持 count_of/count_from/adjust 三个修饰符，覆盖 Modbus 的
byteCount 与变长数组语义。

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: catalog 加载与场景校验

**Files:**
- Create: `icsgen/spec/catalog.py`
- Create: `icsgen/spec/loader.py`
- Create: `tests/test_catalog.py`

**Interfaces:**
- Consumes: `icsgen.spec.model.Operation`、`icsgen.spec.model.Scenario`、`icsgen.spec.model.Tier`、`icsgen.spec.model.Variant`（Task 1）
- Produces:
  - `icsgen.spec.catalog.OperationEntry(pydantic.BaseModel)`：字段 `name: str`、`summary: str = ""`、`layout: str`、`tier: str = "legit"`、`variants: list[str] = ["normal"]`、`params: dict[str, Any] = {}`、`func_code: int | None = None`（**Task 4 移除 `tier` 字段**，语义层改由变体推导，见 Task 4 的「为什么移除 `OperationEntry.tier`」）
  - `icsgen.spec.catalog.Catalog`：`frozen dataclass`，字段 `protocol: str`、`operations: dict[str, OperationEntry]`；方法 `get(name) -> OperationEntry`（不存在时抛 `KeyError`）、`count() -> int`
  - `icsgen.spec.catalog.load_catalog(path: Path) -> Catalog`
  - `icsgen.spec.loader.ScenarioError(ValueError)`
  - `icsgen.spec.loader.load_scenario(path: Path, catalog: Catalog) -> Scenario`

- [ ] **Step 1: 写失败的测试**

创建 `tests/test_catalog.py`：

```python
"""catalog 加载与场景校验。"""

import pytest
import yaml

from icsgen.spec.catalog import Catalog, load_catalog
from icsgen.spec.loader import ScenarioError, load_scenario
from icsgen.spec.model import Tier, Variant


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(yaml.safe_dump(content, allow_unicode=True), encoding="utf-8")
    return p


CATALOG = {
    "protocol": "demo",
    "operations": [
        {
            "name": "demo.read_holding",
            "summary": "读保持寄存器",
            "layout": "fc03",
            "variants": ["normal", "boundary"],
            "params": {
                "quantity": {"type": "integer", "minimum": 1, "maximum": 125, "default": 1}
            },
        }
    ],
}


def test_load_catalog(tmp_path):
    path = _write(tmp_path, "catalog.yaml", CATALOG)
    catalog = load_catalog(path)
    assert catalog.protocol == "demo"
    assert catalog.count() == 1
    entry = catalog.get("demo.read_holding")
    assert entry.layout == "fc03"
    assert entry.params["quantity"]["maximum"] == 125


def test_catalog_unknown_operation_raises(tmp_path):
    path = _write(tmp_path, "catalog.yaml", CATALOG)
    catalog = load_catalog(path)
    with pytest.raises(KeyError, match="不存在操作"):
        catalog.get("demo.nope")


def test_duplicate_operation_name_rejected(tmp_path):
    bad = {
        "protocol": "demo",
        "operations": [CATALOG["operations"][0], CATALOG["operations"][0]],
    }
    path = _write(tmp_path, "catalog.yaml", bad)
    with pytest.raises(ValueError, match="重复"):
        load_catalog(path)


def test_load_scenario_validates_params(tmp_path):
    cat_path = _write(tmp_path, "catalog.yaml", CATALOG)
    catalog = load_catalog(cat_path)
    scn_path = _write(
        tmp_path,
        "scenario.yaml",
        {
            "name": "s1",
            "operations": [{"op": "demo.read_holding", "params": {"quantity": 3}}],
        },
    )
    scenario = load_scenario(scn_path, catalog)
    assert scenario.name == "s1"
    assert scenario.operations[0].params == {"quantity": 3}
    assert scenario.operations[0].tier is Tier.LEGIT


def test_load_scenario_rejects_unknown_op(tmp_path):
    cat_path = _write(tmp_path, "catalog.yaml", CATALOG)
    catalog = load_catalog(cat_path)
    scn_path = _write(
        tmp_path,
        "scenario.yaml",
        {"name": "s1", "operations": [{"op": "demo.unknown"}]},
    )
    with pytest.raises(ScenarioError, match="不存在操作"):
        load_scenario(scn_path, catalog)


def test_load_scenario_rejects_out_of_range_param(tmp_path):
    cat_path = _write(tmp_path, "catalog.yaml", CATALOG)
    catalog = load_catalog(cat_path)
    scn_path = _write(
        tmp_path,
        "scenario.yaml",
        {"name": "s1", "operations": [{"op": "demo.read_holding", "params": {"quantity": 500}}]},
    )
    with pytest.raises(ScenarioError, match="参数校验失败"):
        load_scenario(scn_path, catalog)


def test_load_scenario_rejects_unsupported_variant(tmp_path):
    cat_path = _write(tmp_path, "catalog.yaml", CATALOG)
    catalog = load_catalog(cat_path)
    scn_path = _write(
        tmp_path,
        "scenario.yaml",
        {"name": "s1", "operations": [{"op": "demo.read_holding", "variant": "exception"}]},
    )
    with pytest.raises(ScenarioError, match="不支持的变体"):
        load_scenario(scn_path, catalog)


def test_load_scenario_rejects_unknown_param(tmp_path):
    """catalog 未声明的参数一律拒绝 —— catalog 是操作参数的唯一事实源。"""
    cat_path = _write(tmp_path, "catalog.yaml", CATALOG)
    catalog = load_catalog(cat_path)
    scn_path = _write(
        tmp_path,
        "scenario.yaml",
        {"name": "s1", "operations": [{"op": "demo.read_holding", "params": {"bogus": 1}}]},
    )
    with pytest.raises(ScenarioError, match="参数校验失败"):
        load_scenario(scn_path, catalog)


def test_load_scenario_rejects_tier_variant_conflict(tmp_path):
    """显式 tier 与 variant 冲突时按场景错误报告，而不是逃逸裸 ValueError。"""
    cat_path = _write(tmp_path, "catalog.yaml", CATALOG)
    catalog = load_catalog(cat_path)
    scn_path = _write(
        tmp_path,
        "scenario.yaml",
        {
            "name": "s1",
            "operations": [
                {"op": "demo.read_holding", "variant": "boundary", "tier": "abnormal"}
            ],
        },
    )
    with pytest.raises(ScenarioError, match="冲突"):
        load_scenario(scn_path, catalog)


def test_load_catalog_rejects_unknown_param_type(tmp_path):
    """catalog 里的参数 schema 引用未知类型时报错，而不是逃逸第三方异常。"""
    bad = {
        "protocol": "demo",
        "operations": [
            {
                "name": "demo.read_holding",
                "layout": "fc03",
                "params": {"quantity": {"type": "not-a-real-type"}},
            }
        ],
    }
    path = _write(tmp_path, "catalog.yaml", bad)
    with pytest.raises(ValueError, match="schema 非法"):
        load_catalog(path)


def test_load_catalog_rejects_non_object_param_schema(tmp_path):
    """catalog 里的参数 schema 不是对象时报错。"""
    bad = {
        "protocol": "demo",
        "operations": [
            {
                "name": "demo.read_holding",
                "layout": "fc03",
                "params": {"quantity": "integer"},
            }
        ],
    }
    path = _write(tmp_path, "catalog.yaml", bad)
    with pytest.raises(ValueError, match="必须是对象"):
        load_catalog(path)
```

- [ ] **Step 2: 运行测试确认失败**

Run: `python3 -m pytest tests/test_catalog.py -v`
Expected: FAIL —— `ModuleNotFoundError: No module named 'icsgen.spec.catalog'`

- [ ] **Step 3: 写最小实现**

创建 `icsgen/spec/catalog.py`：

```python
"""操作目录（catalog）的加载与查询。

catalog 是操作类型的唯一事实源：每个条目声明操作名、所用布局、可用变体
与参数 schema。框架代码不感知任何具体操作。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from pydantic import BaseModel, Field


class OperationEntry(BaseModel):
    """catalog 中的一个操作类型条目。

    params 是「参数名 -> 该参数的 JSON Schema 片段」的映射；其中的 default
    键仅作文档说明，参数缺省值由字段布局的 Field.default 决定，加载时不会
    自动填充。
    """

    name: str
    summary: str = ""
    layout: str
    tier: str = "legit"
    variants: list[str] = Field(default_factory=lambda: ["normal"])
    params: dict[str, Any] = Field(default_factory=dict)
    func_code: int | None = None


class CatalogModel(BaseModel):
    """catalog.yaml 的结构。"""

    protocol: str
    operations: list[OperationEntry]


@dataclass(frozen=True)
class Catalog:
    """已加载的操作目录。"""

    protocol: str
    operations: dict[str, OperationEntry]

    def get(self, name: str) -> OperationEntry:
        """按操作名取条目，不存在时抛 KeyError。"""
        try:
            return self.operations[name]
        except KeyError as exc:
            raise KeyError(f"catalog {self.protocol!r} 中不存在操作 {name!r}") from exc

    def count(self) -> int:
        """操作类型数量。"""
        return len(self.operations)


def _check_params_schema(entry: OperationEntry, path: Path) -> None:
    """自检 catalog 声明的参数 schema，把手写 YAML 的错误挡在加载期。

    params 是「参数名 -> 该参数的 JSON Schema 片段」的映射：片段不是对象，
    或引用了未知的类型关键字，交给 jsonschema 会抛出第三方异常甚至
    AttributeError，调用方难以判断是自己写错了 catalog。
    """
    for param, schema in entry.params.items():
        if not isinstance(schema, dict):
            raise ValueError(
                f"catalog {path} 中操作 {entry.name!r} 的参数 {param!r} 的 schema 必须是对象"
            )
        try:
            Draft202012Validator.check_schema(schema)
        except SchemaError as exc:
            raise ValueError(
                f"catalog {path} 中操作 {entry.name!r} 的参数 {param!r} 的 schema 非法：{exc.message}"
            ) from exc


def load_catalog(path: Path) -> Catalog:
    """从 YAML 文件加载 catalog。"""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    model = CatalogModel.model_validate(raw)
    for entry in model.operations:
        _check_params_schema(entry, path)
    operations = {entry.name: entry for entry in model.operations}
    if len(operations) != len(model.operations):
        raise ValueError(f"catalog {path} 中存在重复的操作名")
    return Catalog(protocol=model.protocol, operations=operations)
```

创建 `icsgen/spec/loader.py`：

```python
"""场景 YAML 的加载与校验。

加载链路：YAML → pydantic 校验结构 → 逐个操作查 catalog → 用 catalog 声明的
参数 schema 校验参数 → 构造 Operation 列表。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError

from .catalog import Catalog, OperationEntry
from .model import Operation, Scenario, Tier, Variant


class ScenarioError(ValueError):
    """场景文件不合法。"""


class ScenarioOperationModel(BaseModel):
    """场景中的一条操作声明。"""

    op: str
    params: dict[str, Any] = {}
    variant: Variant = Variant.NORMAL
    tier: Tier | None = None
    expect_response: bool = True


class ScenarioModel(BaseModel):
    """scenario.yaml 的结构。"""

    name: str
    description: str = ""
    transport: dict[str, Any] = {}
    operations: list[ScenarioOperationModel]


def _object_schema(entry: OperationEntry) -> dict[str, Any]:
    """把 catalog 的逐参数 schema 映射拼成对象级 JSON Schema。

    catalog 的 params 形如 {"quantity": {"type": "integer", ...}}，是
    「参数名 -> 该参数的 schema」的映射。直接交给 jsonschema 会被当成一份
    无约束的空 schema（关键字 quantity 不被识别），任何参数都能通过校验，
    因此必须显式包成对象级 schema。
    """
    return {
        "type": "object",
        "properties": entry.params,
        "additionalProperties": False,
    }


def _validate_params(entry: OperationEntry, params: dict[str, Any], path: Path, index: int) -> None:
    """用 catalog 声明的参数 schema 校验操作参数。"""
    if not entry.params:
        if params:
            raise ScenarioError(
                f"场景 {path} 第 {index} 条操作 {entry.name!r} 不接受参数，但给出了 {params}"
            )
        return
    validator = Draft202012Validator(_object_schema(entry))
    errors = sorted(validator.iter_errors(params), key=lambda e: list(e.path))
    if errors:
        details = "; ".join(f"{list(e.path) or '<根>'}: {e.message}" for e in errors)
        raise ScenarioError(
            f"场景 {path} 第 {index} 条操作 {entry.name!r} 参数校验失败：{details}"
        )


def load_scenario(path: Path, catalog: Catalog) -> Scenario:
    """加载并校验场景文件，返回 Scenario。"""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    try:
        model = ScenarioModel.model_validate(raw)
    except ValidationError as exc:
        raise ScenarioError(f"场景 {path} 结构不合法：{exc}") from exc

    operations: list[Operation] = []
    for index, item in enumerate(model.operations):
        try:
            entry = catalog.get(item.op)
        except KeyError as exc:
            raise ScenarioError(
                f"场景 {path} 第 {index} 条操作 {item.op!r}：catalog {catalog.protocol!r} 中不存在操作"
            ) from exc
        if item.variant.value not in entry.variants:
            raise ScenarioError(
                f"场景 {path} 第 {index} 条操作 {entry.name!r} 不支持的变体 {item.variant.value!r}，"
                f"可用变体：{entry.variants}"
            )
        _validate_params(entry, item.params, path, index)
        try:
            operation = Operation(
                op=item.op,
                params=item.params,
                variant=item.variant,
                tier=item.tier,
                expect_response=item.expect_response,
            )
        except ValueError as exc:
            # tier 与 variant 冲突由 Operation 构造时发现，这里统一转成场景错误，
            # 保证 load_scenario 对外只有 ScenarioError 一种失败形态。
            raise ScenarioError(
                f"场景 {path} 第 {index} 条操作 {item.op!r} 的语义层与变体冲突：{exc}"
            ) from exc
        operations.append(operation)

    return Scenario(
        name=model.name,
        description=model.description,
        transport=model.transport,
        operations=tuple(operations),
    )
```

- [ ] **Step 4: 运行测试确认通过**

Run: `python3 -m pytest tests/test_catalog.py -v`
Expected: PASS —— 11 passed

- [ ] **Step 5: 提交**

```bash
git add icsgen/spec/catalog.py icsgen/spec/loader.py tests/test_catalog.py
git commit -m "$(cat <<'EOF'
feat: catalog 加载与场景校验

catalog 声明操作元数据与参数 schema，场景加载时逐条查表并用
jsonschema 校验参数，同时校验变体是否被该操作支持。

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Modbus 字段布局与操作目录

**Files:**
- Create: `icsgen/protocols/__init__.py`
- Create: `icsgen/protocols/modbus/__init__.py`
- Create: `icsgen/protocols/modbus/layouts.py`
- Create: `icsgen/protocols/modbus/catalog.yaml`
- Create: `tests/test_modbus_layouts.py`
- Modify: `icsgen/codec/fields.py`（新增 `len_adjust`、`count_is_elements` 与 `count_adjust` 三个长度换算开关）
- Modify: `icsgen/codec/decoder.py`（按新开关解释 `count_from` 的元素个数）
- Modify: `icsgen/codec/encoder.py`（`count_of` / `count_from` 缺值时回退到字段缺省值）
- Modify: `icsgen/spec/catalog.py`（移除 `OperationEntry.tier`，catalog 模型拒绝未知键）
- Modify: `tests/test_codec.py`（新增 4 个用例）

**Interfaces:**
- Consumes: `icsgen.codec.fields.Field`、`icsgen.codec.fields.Layout`（Task 2）、`icsgen.spec.catalog.load_catalog`（Task 3）
- Produces:
  - `icsgen.codec.fields.Field.len_adjust: Callable[[int], int] | None = None` —— **构造**响应时元素个数的线性修正（只作用于 `len_from_request` 路径，不影响解码）
  - `icsgen.codec.fields.Field.count_is_elements: bool = False` —— 被引用字段给出的是**元素个数**而非字节数时置真，解码不再除以元素宽度
  - `icsgen.codec.fields.Field.count_adjust: Callable[[int], int] | None = None` —— 解码时元素个数换算后的线性修正
  - `icsgen.protocols.modbus.layouts.LAYOUTS: dict[str, Layout]` —— 布局名 → 布局，共 19 个
  - `icsgen.protocols.modbus.layouts.get_layout(name: str) -> Layout`（不存在时抛 `KeyError`）
  - `icsgen.protocols.modbus.layouts.DIAGNOSTIC_SUBFUNCTIONS: dict[int, str]` —— 诊断子功能码 → 名称，共 21 项
  - `icsgen.protocols.modbus.catalog.yaml` —— 41 个操作类型，协议名 `modbus`，顶层声明传输 `tcp` 与 `rtu`
  - `icsgen.spec.catalog.Catalog.transports: tuple[str, ...]` —— catalog 声明的传输方式，缺省 `("tcp",)`
  - `icsgen.spec.catalog.Catalog.coverage_count() -> int` —— 覆盖条目数 = Σ(每个操作类型的变体数) × 传输数

**为什么需要三个新的长度换算开关**：Modbus 的长度字段有两种形态 —— **字节计数**（`byte_count`，值 = 数据字节数）与**元素计数**（FC0x18 的 `fifo_count`，值 = 元素个数）。原内核只有「元素个数 = 引用值 ÷ 元素宽度」一条规则，遇到元素计数字段会把个数算少一半。`count_is_elements` 声明引用值本身就是元素个数；`count_adjust` 在**解码**换算后对个数做一次修正（如 FC0x15 的 `record_length` 是寄存器数，字节数是它的两倍）；`len_adjust` 是**构造**路径上的对应物（如 FC0x01 的响应数据按位打包，字节数 = 线圈数 ÷ 8 向上取整），两者作用在不同路径上，不可互相替代。

**为什么移除 `OperationEntry.tier`**：语义层由变体唯一决定（`icsgen.spec.model.VARIANT_TIER`）。catalog 再声明一个 tier 就成了第二事实源，而且对「同一操作类型既有合法变体（normal）又有异常变体（exception）」的情况必然自相矛盾 —— 例如 `modbus.read_coils` 声明 `tier: legit` 却同时声明 `variants: [normal, boundary, exception]`。catalog 因此只声明变体，tier 一律由变体推导。相应地，catalog 模型开启 `extra="forbid"`，YAML 里残留的 `tier:` 键会在加载期直接报错，而不是被静默忽略。

**布局清单**（请求/响应均不含功能码字节，功能码由适配器单独拼装）：

| 布局名 | 功能码 | 请求字段 | 响应字段 |
|---|---|---|---|
| `fc01` / `fc02` | 0x01–0x02 | start_addr u16, quantity u16 | byte_count u8(count_of values), values bytes(count_from byte_count, len_from_request quantity, len_adjust ÷8 向上取整) |
| `fc03` / `fc04` | 0x03–0x04 | start_addr u16, quantity u16 | byte_count u8(count_of values, adjust×2), values u16(count_from byte_count, len_from_request quantity) |
| `fc05` / `fc06` | 0x05–0x06 | start_addr u16, value u16 | 同请求 |
| `fc07` | 0x07 | 无 | status u8 |
| `fc08` | 0x08 | sub_function u16, data u16 | 同请求 |
| `fc0b` | 0x0B | 无 | status u16, event_count u16 |
| `fc0c` | 0x0C | 无 | byte_count u8(count_of events, adjust+6), status u16, event_count u16, message_count u16, events bytes(count_from byte_count, count_adjust−6) |
| `fc0f` | 0x0F | start_addr u16, quantity u16, byte_count u8(count_of values), values bytes(count_from byte_count, len_from_request quantity, len_adjust ÷8 向上取整) | start_addr u16, quantity u16 |
| `fc10` | 0x10 | start_addr u16, quantity u16, byte_count u8(count_of values, adjust×2), values u16(count_from byte_count, len_from_request quantity) | start_addr u16, quantity u16 |
| `fc11` | 0x11 | 无 | byte_count u8(count_of slave_id, adjust+1), slave_id bytes(count_from byte_count, count_adjust−1), run_indicator_status u8 |
| `fc14` | 0x14 | byte_count u8, reference_type u8, file_number u16, record_number u16, record_length u16 | byte_count u8(count_of record_data, adjust+2), file_response_length u8(count_of record_data, adjust+1), reference_type u8, record_data bytes(count_from file_response_length, count_adjust−1) |
| `fc15` | 0x15 | byte_count u8(count_of record_data, adjust+7), reference_type u8, file_number u16, record_number u16, record_length u16(count_of record_data, adjust÷2), record_data bytes(count_from record_length, count_is_elements, count_adjust×2) | 同请求 |
| `fc16` | 0x16 | start_addr u16, and_mask u16, or_mask u16 | 同请求 |
| `fc17` | 0x17 | read_addr u16, read_quantity u16, write_addr u16, write_quantity u16, write_byte_count u8(count_of write_values, adjust×2), write_values u16(count_from write_byte_count, len_from_request write_quantity) | byte_count u8(count_of values, adjust×2), values u16(count_from byte_count, len_from_request read_quantity) |
| `fc18` | 0x18 | fifo_pointer_address u16 | byte_count u16(count_of fifo_values, adjust×2+2), fifo_count u16(count_of fifo_values), fifo_values u16(count_from fifo_count, count_is_elements) |
| `fc2b` | 0x2B | mei_type u8, read_device_id_code u8, object_id u8 | mei_type u8, read_device_id_code u8, conformity_level u8, more_follows u8, next_object_id u8, number_of_objects u8, object_id u8, object_size u8(count_of object_value), object_value bytes(count_from object_size) |

> 规范说明：`0x12` 是保留空档（`0x11` 与 `0x14` 之间），不存在「读文件记录」功能码 —— 读文件记录是 `0x14`，写文件记录是 `0x15`。FC0x01 / FC0x02 的响应数据**按位打包**（每 8 个线圈 1 字节），FC0x03 / FC0x04 是每寄存器 2 字节，两者布局不共用。FC0x0C 的响应是 `byte_count(6 + 事件字节数) + status + event_count + message_count + 事件字节`（每条事件 1 字节）。FC0x16 是掩码写寄存器（start_addr + and_mask + or_mask），FC0x17 的响应与 FC0x03 同构（byte_count + 寄存器数组），FC0x18 的响应是 byte_count + fifo_count + FIFO 数据。

**操作类型构成**（41 个 = 规范功能码 17 + MEI 2 + 诊断子功能 21 + 协议级异常 1）：

| 类别 | 数量 | 变体 |
|---|---|---|
| 读取类（FC01–FC04） | 4 | normal, boundary, exception |
| 写入类（FC05、FC06、FC0F、FC10、FC16） | 5 | normal, boundary, exception |
| 状态与诊断类（FC07、FC0B、FC0C、FC11、FC18） | 5 | normal, exception |
| 文件与读写类（FC14、FC15、FC17） | 3 | normal, boundary, exception |
| 设备标识 MEI（basic / specific 两种访问方式） | 2 | normal, boundary, exception |
| 诊断子功能（FC0x08） | 21 | normal, exception |
| 协议级异常（非法功能码） | 1 | illegal_fc, exception |

合计：(操作类型, 变体) 组合 = 14×3 + 5×2 + 21×2 + 1×2 = 96，覆盖条目数 = 96 × 2（tcp + rtu）= 192。

- [ ] **Step 1: 写失败的测试**

创建 `tests/test_modbus_layouts.py`：

```python
"""Modbus 字段布局与操作目录。"""

from pathlib import Path

import pytest

from icsgen.codec.decoder import decode
from icsgen.codec.encoder import encode
from icsgen.protocols.modbus.layouts import (
    DIAGNOSTIC_SUBFUNCTIONS,
    LAYOUTS,
    get_layout,
)
from icsgen.spec.catalog import load_catalog

CATALOG_PATH = Path(__file__).resolve().parents[1] / "icsgen" / "protocols" / "modbus" / "catalog.yaml"

#: catalog 中允许出现的全部变体
KNOWN_VARIANTS = {"normal", "boundary", "exception", "illegal_fc", "malformed"}


def test_all_layouts_have_request_and_response():
    for name, layout in LAYOUTS.items():
        assert isinstance(layout.request, tuple), name
        assert isinstance(layout.response, tuple), name


def test_get_layout_unknown_raises():
    with pytest.raises(KeyError, match="fc99"):
        get_layout("fc99")


def test_fc03_round_trip():
    layout = get_layout("fc03")
    raw = encode(layout.request, {"start_addr": 0, "quantity": 3})
    assert raw == b"\x00\x00\x00\x03"
    assert decode(layout.request, raw) == {"start_addr": 0, "quantity": 3}


def test_fc10_byte_count_is_two_times_value_count():
    """FC10 的 byte_count 等于寄存器数量的两倍。"""
    layout = get_layout("fc10")
    raw = encode(
        layout.request,
        {"start_addr": 100, "quantity": 2, "values": [0xDEAD, 0xBEEF]},
    )
    assert raw == b"\x00\x64\x00\x02\x04\xde\xad\xbe\xef"


def test_fc0f_values_are_bytes():
    layout = get_layout("fc0f")
    raw = encode(
        layout.request,
        {"start_addr": 0, "quantity": 8, "values": b"\xff"},
    )
    assert raw == b"\x00\x00\x00\x08\x01\xff"


def test_fc08_carries_sub_function():
    layout = get_layout("fc08")
    raw = encode(layout.request, {"sub_function": 0x0004, "data": 0x0000})
    assert raw == b"\x00\x04\x00\x00"


def test_fc16_mask_write_carries_three_fields():
    """FC16 掩码写寄存器 = 起始地址 + 与掩码 + 或掩码。"""
    layout = get_layout("fc16")
    raw = encode(layout.request, {"start_addr": 1, "and_mask": 0xFF00, "or_mask": 0x00FF})
    assert raw == b"\x00\x01\xff\x00\x00\xff"
    assert decode(layout.request, raw) == {
        "start_addr": 1,
        "and_mask": 0xFF00,
        "or_mask": 0x00FF,
    }


def test_fc18_response_matches_spec():
    """FC18 响应 = byte_count(2 + 2×元素数) + fifo_count(元素数) + FIFO 数据。"""
    layout = get_layout("fc18")
    raw = encode(layout.response, {"fifo_values": [1, 2, 3]})
    assert raw == b"\x00\x08\x00\x03\x00\x01\x00\x02\x00\x03"
    assert decode(layout.response, raw) == {
        "byte_count": 8,
        "fifo_count": 3,
        "fifo_values": [1, 2, 3],
    }


def test_fc14_request_matches_spec():
    """FC14 读文件记录请求 = byte_count(7) + 引用类型 + 文件号 + 记录号 + 记录长度。"""
    layout = get_layout("fc14")
    raw = encode(
        layout.request,
        {"reference_type": 6, "file_number": 4, "record_number": 0, "record_length": 1},
    )
    assert raw == b"\x07\x06\x00\x04\x00\x00\x00\x01"


def test_fc14_response_length_fields():
    """FC14 响应的 byte_count = 数据长度 + 2，file_response_length = 数据长度 + 1。"""
    layout = get_layout("fc14")
    raw = encode(layout.response, {"record_data": b"\x00\x01\x00\x02"})
    assert raw == b"\x06\x05\x06\x00\x01\x00\x02"
    assert decode(layout.response, raw) == {
        "byte_count": 6,
        "file_response_length": 5,
        "reference_type": 6,
        "record_data": b"\x00\x01\x00\x02",
    }


def test_fc15_request_length_fields():
    """FC15 写文件记录：byte_count = 数据长度 + 7，record_length = 寄存器数。"""
    layout = get_layout("fc15")
    raw = encode(layout.request, {"record_data": b"\x00\x01\x00\x02"})
    assert raw == b"\x0b\x06\x00\x00\x00\x00\x00\x02\x00\x01\x00\x02"


def test_fc15_decodes_record_data():
    """FC15 记录长度以寄存器计，字节数是它的两倍。"""
    layout = get_layout("fc15")
    raw = b"\x0b\x06\x00\x00\x00\x00\x00\x02\x00\x01\x00\x02"
    assert decode(layout.request, raw) == {
        "byte_count": 11,
        "reference_type": 6,
        "file_number": 0,
        "record_number": 0,
        "record_length": 2,
        "record_data": b"\x00\x01\x00\x02",
    }


def test_fc11_report_slave_id_length():
    """FC11 响应 = byte_count(标识长度 + 1) + 标识 + 运行指示状态。"""
    layout = get_layout("fc11")
    raw = encode(layout.response, {"slave_id": b"PLC-1"})
    assert raw == b"\x06PLC-1\xff"
    assert decode(layout.response, raw) == {
        "byte_count": 6,
        "slave_id": b"PLC-1",
        "run_indicator_status": 0xFF,
    }


def test_fc0c_response_matches_spec():
    """FC0C 响应 = byte_count(6 + 事件字节数) + status + event_count + message_count + 事件字节。"""
    layout = get_layout("fc0c")
    raw = encode(layout.response, {"events": b"\x21\x20"})
    assert raw == b"\x08\x00\x00\x00\x00\x00\x00\x21\x20"
    assert decode(layout.response, raw) == {
        "byte_count": 8,
        "status": 0,
        "event_count": 0,
        "message_count": 0,
        "events": b"\x21\x20",
    }


def test_fc01_response_is_bit_packed():
    """FC01 响应数据按位打包：8 个线圈 = 1 字节，不是每线圈 2 字节。"""
    layout = get_layout("fc01")
    raw = encode(layout.response, {"values": b"\x05"})
    assert raw == b"\x01\x05"
    assert decode(layout.response, raw) == {
        "byte_count": 1,
        "values": b"\x05",
    }


def test_fc17_request_layout():
    """FC17 请求的 write_byte_count = 写入寄存器数 × 2。"""
    layout = get_layout("fc17")
    raw = encode(
        layout.request,
        {
            "read_addr": 0,
            "read_quantity": 2,
            "write_addr": 10,
            "write_quantity": 1,
            "write_values": [0x1234],
        },
    )
    assert raw == b"\x00\x00\x00\x02\x00\x0a\x00\x01\x02\x12\x34"


def test_fc17_response_layout():
    """FC17 响应与 FC03 同构：byte_count + 寄存器数组。"""
    layout = get_layout("fc17")
    raw = encode(layout.response, {"values": [1, 2]})
    assert raw == b"\x04\x00\x01\x00\x02"


def test_fc2b_response_carries_single_object():
    """FC2B 响应带一个对象：对象长度 + 对象值。"""
    layout = get_layout("fc2b")
    raw = encode(layout.response, {"object_value": b"\x01\x02"})
    assert raw == b"\x0e\x01\x83\x00\x00\x01\x00\x02\x01\x02"
    assert decode(layout.response, raw)["object_value"] == b"\x01\x02"


def test_diagnostic_subfunction_table_has_twenty_one_entries():
    assert len(DIAGNOSTIC_SUBFUNCTIONS) == 21
    assert DIAGNOSTIC_SUBFUNCTIONS[0x0004] == "Force Listen Only Mode"
    assert DIAGNOSTIC_SUBFUNCTIONS[0x0015] == "Get Clear Modbus Plus Request"


def test_catalog_declares_operation_types_and_transports():
    catalog = load_catalog(CATALOG_PATH)
    assert catalog.protocol == "modbus"
    assert catalog.count() == 41
    assert catalog.transports == ("tcp", "rtu")


def test_catalog_declares_ninety_six_variants():
    """catalog 声明的 (操作类型, 变体) 组合共 96 个。"""
    catalog = load_catalog(CATALOG_PATH)
    total = sum(len(entry.variants) for entry in catalog.operations.values())
    assert total == 96


def test_catalog_coverage_count_meets_floor():
    """覆盖条目数 = Σ(每个操作类型的变体数) × 传输数，是 §15 丰富度指标的度量口径。"""
    catalog = load_catalog(CATALOG_PATH)
    assert catalog.coverage_count() >= 90, f"覆盖条目数 {catalog.coverage_count()} 低于下限 90"


def test_every_catalog_entry_references_existing_layout():
    catalog = load_catalog(CATALOG_PATH)
    for name in catalog.operations:
        entry = catalog.get(name)
        assert entry.layout in LAYOUTS, f"{name} 引用了不存在的布局 {entry.layout}"


def test_diagnostic_operations_cover_all_subfunctions():
    """21 个诊断子功能各自是一个操作类型，且子功能码与诊断表一致。"""
    catalog = load_catalog(CATALOG_PATH)
    diag = [n for n in catalog.operations if n.startswith("modbus.diagnostics.")]
    assert len(diag) == 21
    declared = {
        catalog.get(name).params["sub_function"]["default"] for name in diag
    }
    assert declared == set(DIAGNOSTIC_SUBFUNCTIONS)


def test_every_catalog_entry_declares_known_variants():
    catalog = load_catalog(CATALOG_PATH)
    for name, entry in catalog.operations.items():
        assert entry.variants, f"{name} 未声明任何变体"
        for variant in entry.variants:
            assert variant in KNOWN_VARIANTS, f"{name} 声明了未知变体 {variant!r}"


def test_catalog_covers_all_variant_kinds():
    """normal/boundary/exception/illegal_fc 都由 catalog 声明；malformed 只由变异引擎产生。"""
    catalog = load_catalog(CATALOG_PATH)
    kinds = {v for entry in catalog.operations.values() for v in entry.variants}
    assert kinds == {"normal", "boundary", "exception", "illegal_fc"}


def test_illegal_function_code_entry_declares_abnormal_variants():
    """非法功能码是协议级异常，只能用 abnormal 层的变体。"""
    catalog = load_catalog(CATALOG_PATH)
    entry = catalog.get("modbus.illegal_function_code")
    assert entry.func_code == 99
    assert set(entry.variants) == {"illegal_fc", "exception"}
```

在 `tests/test_codec.py` 末尾追加 4 个用例：

```python
def test_decode_count_is_elements_keeps_count():
    """被引用字段给出的是元素个数时不再除以元素宽度。"""
    fields = (
        Field("fifo_count", "uint16"),
        Field("fifo_values", "uint16", count_from="fifo_count", count_is_elements=True),
    )
    assert decode(fields, b"\x00\x03\x00\x01\x00\x02\x00\x03") == {
        "fifo_count": 3,
        "fifo_values": [1, 2, 3],
    }


def test_decode_count_adjust_transforms_element_count():
    """count_adjust 在换算后对元素个数做一次修正。"""
    fields = (
        Field("record_length", "uint16"),
        Field("record_data", "bytes", count_from="record_length", count_adjust=lambda n: n * 2),
    )
    assert decode(fields, b"\x00\x02\x00\x01\x00\x02") == {
        "record_length": 2,
        "record_data": b"\x00\x01\x00\x02",
    }


def test_encode_count_of_falls_back_to_referenced_default():
    """被引用数组没有取值时，长度字段按被引用字段的缺省值计算。"""
    fields = (
        Field("byte_count", "uint8", count_of="data", adjust=lambda n: n + 1),
        Field("data", "bytes", count_from="byte_count", default=b"\x01\x02"),
    )
    assert encode(fields, {}) == b"\x03\x01\x02"


def test_encode_count_from_falls_back_to_field_default():
    """数组字段没有取值时用字段缺省值。"""
    fields = (
        Field("byte_count", "uint8", count_of="data"),
        Field("data", "bytes", count_from="byte_count", default=b"\x01\x02"),
    )
    assert encode(fields, {}) == b"\x02\x01\x02"
```

- [ ] **Step 2: 运行测试确认失败**

Run: `python3 -m pytest tests/test_modbus_layouts.py tests/test_codec.py -v`
Expected: FAIL —— `ModuleNotFoundError: No module named 'icsgen.protocols'`

- [ ] **Step 3: 写最小实现**

创建 `icsgen/protocols/__init__.py` 与 `icsgen/protocols/modbus/__init__.py`（空文件）。

**（1）扩展 `icsgen/codec/fields.py` 的 `Field`**，新增三个长度换算开关：

```python
@dataclass(frozen=True)
class Field:
    """一个协议字段的声明。

    count_of:  编码时本字段的值由被引用字段的元素个数决定（被引用字段是数组时取其长度）
    count_from: 解码时本字段是变长数组，元素个数由被引用字段的值除以本字段类型宽度得出
    len_from_request: 本数组的元素个数取自该参数的值，仅用于构造：响应数组的
                参数在请求里（FC03 响应的寄存器数等于请求的 quantity），请求
                数组的参数在同一请求里（FC10 的 values 元素数等于同帧的 quantity）
    len_adjust: 构造响应时元素个数的线性修正，例如 Modbus FC0x01 的响应数据按位打包，
                字节数是线圈数向上取整除以 8
    count_is_elements: 被引用字段给出的是元素个数而非字节数时置真，解码不再除以元素宽度
    count_adjust: 元素个数换算后的线性修正，例如 Modbus FC0x15 的记录长度以寄存器计，
                  字节数是它的两倍
    adjust:    写入长度字段前的换算函数，例如 Modbus 的 byte_count = len(values) * 2
    default:   缺省值，编码时 values 中缺少该字段则使用
    """

    name: str
    type: str
    count_of: str | None = None
    count_from: str | None = None
    len_from_request: str | None = None
    len_adjust: Callable[[int], int] | None = None
    count_is_elements: bool = False
    count_adjust: Callable[[int], int] | None = None
    adjust: Callable[[int], int] | None = None
    default: Any = None
```

**（2）修改 `icsgen/codec/decoder.py` 的 `count_from` 分支**，按新开关解释元素个数：

```python
        if f.count_from is not None:
            referenced = values.get(f.count_from)
            if referenced is None:
                raise DecodeError(f"字段 {f.name!r} 依赖的 {f.count_from!r} 尚未解码")
            width = FIELD_SIZES.get(f.type)
            if width is None:
                raise DecodeError(f"未知字段类型 {f.type!r}")
            count = int(referenced)
            if not f.count_is_elements:
                # 引用值是字节计数时换算成元素个数
                count = count // width
            if f.count_adjust is not None:
                count = f.count_adjust(count)
            if f.type == "bytes":
                # bytes 类型宽度为 1，长度即字节数，直接切片返回连续字节串
                if offset + count > len(data):
                    remaining = len(data) - offset
                    raise DecodeError(
                        f"数据不足：偏移 {offset} 需要 {count} 字节，实际剩余 {remaining} 字节"
                    )
                values[f.name] = data[offset : offset + count]
                offset += count
                continue
            items: list[Any] = []
            for _ in range(count):
                items.append(_unpack_value(f.type, data, offset))
                offset += width
            values[f.name] = items
            continue
```

**（3）修改 `icsgen/codec/encoder.py`**，`count_of` 与 `count_from` 缺值时回退到字段缺省值：

```python
def _field_default(fields: tuple[Field, ...], name: str) -> Any:
    """取同名字段的缺省值。"""
    for other in fields:
        if other.name == name:
            return other.default
    return None


def encode(fields: tuple[Field, ...], values: Mapping[str, Any]) -> bytes:
    """按 fields 声明把 values 编码成字节。

    count_of 字段写入被引用数组的长度（经 adjust 换算）；
    count_from 字段直接写入 values 中对应数组的各元素。
    数组与被引用字段都没有取值时，退回字段声明的缺省值。
    """
    out = bytearray()
    for f in fields:
        if f.count_of is not None:
            referenced = values.get(f.count_of)
            if referenced is None:
                referenced = _field_default(fields, f.count_of)
            if referenced is None:
                raise CodecError(f"字段 {f.name!r} 依赖的 {f.count_of!r} 缺失")
            if isinstance(referenced, (list, tuple, bytes, bytearray)):
                count = len(referenced)
            else:
                count = int(referenced)
            if f.adjust is not None:
                count = f.adjust(count)
            out += _pack_value(f.type, count)
            continue
        if f.count_from is not None:
            items = values.get(f.name)
            if items is None:
                items = f.default
            if items is None:
                raise CodecError(f"缺少数组字段 {f.name!r}")
            # bytes 类型的变长字段，其元素是 1 字节整数或 1 字节字节串，
            # 两种形态都由 _pack_value 统一处理，编码结果与解码器对称。
            for item in items:
                out += _pack_value(f.type, item)
            continue
        if f.name not in values:
            if f.default is None:
                raise CodecError(f"缺少字段 {f.name!r} 的值")
            out += _pack_value(f.type, f.default)
            continue
        out += _pack_value(f.type, values[f.name])
    return bytes(out)
```

**（4）修改 `icsgen/spec/catalog.py`**（Task 3 的文件）：移除 `OperationEntry.tier`，并让 catalog 模型拒绝未知键。

```python
from pydantic import BaseModel, ConfigDict, Field


class OperationEntry(BaseModel):
    """catalog 中的一个操作类型条目。

    params 是「参数名 -> 该参数的 JSON Schema 片段」的映射；其中的 default
    键仅作文档说明，参数缺省值由字段布局的 Field.default 决定，加载时不会
    自动填充。

    本条目不声明 tier：语义层由变体唯一决定（icsgen.spec.model.VARIANT_TIER），
    catalog 再声明一个 tier 会成为第二事实源，且对同时含合法变体与异常变体的
    操作类型必然自相矛盾。
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    summary: str = ""
    layout: str
    variants: list[str] = Field(default_factory=lambda: ["normal"])
    params: dict[str, Any] = Field(default_factory=dict)
    func_code: int | None = None


class CatalogModel(BaseModel):
    """catalog.yaml 的结构。"""

    model_config = ConfigDict(extra="forbid")

    protocol: str
    transports: list[str] = Field(default_factory=lambda: ["tcp"])
    operations: list[OperationEntry]
```

`Catalog` 的 `transports` 字段与 `coverage_count()` 方法按 Task 3 已有实现保留：

```python
@dataclass(frozen=True)
class Catalog:
    """已加载的操作目录。"""

    protocol: str
    operations: dict[str, OperationEntry]
    transports: tuple[str, ...] = ("tcp",)

    def get(self, name: str) -> OperationEntry:
        """按操作名取条目，不存在时抛 KeyError。"""
        try:
            return self.operations[name]
        except KeyError as exc:
            raise KeyError(f"catalog {self.protocol!r} 中不存在操作 {name!r}") from exc

    def count(self) -> int:
        """操作类型数量。"""
        return len(self.operations)

    def coverage_count(self) -> int:
        """覆盖条目数 = Σ(每个操作类型的变体数) × 传输数。

        这是 §15 丰富度指标的度量口径：一条覆盖条目对应一个
        (操作类型, 变体, 传输) 组合，即一条可生成的流量样本。
        """
        variants = sum(len(entry.variants) for entry in self.operations.values())
        return variants * len(self.transports)
```

**（5）创建 `icsgen/protocols/modbus/layouts.py`**：

```python
"""Modbus 功能码的字段布局。

布局描述请求与响应 PDU 的字节结构（不含功能码字节本身，功能码由适配器
单独拼装）。字段结构对照 Modbus Application Protocol Specification V1.1b3；
长度字段的换算关系由 Field 的 count_of / count_from / adjust /
count_is_elements / count_adjust 声明。

诊断子功能的 21 个子功能各自是一个操作类型，共享 fc08 布局，仅子功能码
默认值不同。
"""

from __future__ import annotations

from icsgen.codec.fields import Field, Layout

#: FC0x08 诊断子功能全集（Modbus Application Protocol 规范）
DIAGNOSTIC_SUBFUNCTIONS: dict[int, str] = {
    0x0000: "Return Query Data",
    0x0001: "Restart Communications Option",
    0x0002: "Return Diagnostic Register",
    0x0003: "Change ASCII Input Delimiter",
    0x0004: "Force Listen Only Mode",
    0x0005: "Change Byte Count",
    0x0006: "Change Word Count",
    0x0008: "Get/Modify Modbus Plus Parameters",
    0x000A: "Clear Counters and Diagnostic Register",
    0x000B: "Return Bus Message Count",
    0x000C: "Return Bus Communication Error Count",
    0x000D: "Return Bus Exception Error Count",
    0x000E: "Return Slave Message Count",
    0x000F: "Return Slave No Response Count",
    0x0010: "Return Slave NAK Count",
    0x0011: "Return Slave Busy Count",
    0x0012: "Return Bus Character Overrun Count",
    0x0014: "Clear Overrun Counter and Flag",
    0x0015: "Get Clear Modbus Plus Request",
    0x0017: "Return I/O Overrun Count",
    0x0018: "Clear I/O Overrun Counter and Flag",
}

#: FC0x01 / FC0x02 读位：响应数据按位打包，每 8 个线圈 1 字节
_BIT_READ_LAYOUT = Layout(
    request=(Field("start_addr", "uint16"), Field("quantity", "uint16")),
    response=(
        Field("byte_count", "uint8", count_of="values"),
        Field(
            "values",
            "bytes",
            count_from="byte_count",
            len_from_request="quantity",
            len_adjust=lambda n: (n + 7) // 8,
        ),
    ),
)

#: FC0x03 / FC0x04 读寄存器：响应数据每寄存器 2 字节
_REGISTER_READ_LAYOUT = Layout(
    request=(Field("start_addr", "uint16"), Field("quantity", "uint16")),
    response=(
        Field("byte_count", "uint8", count_of="values", adjust=lambda n: n * 2),
        Field("values", "uint16", count_from="byte_count", len_from_request="quantity"),
    ),
)

_WRITE_SINGLE_LAYOUT = Layout(
    request=(Field("start_addr", "uint16"), Field("value", "uint16")),
    response=(Field("start_addr", "uint16"), Field("value", "uint16")),
)

#: FC0x14 读文件记录请求：byte_count(7) + 引用类型 + 文件号 + 记录号 + 记录长度
_FILE_READ_REQUEST_FIELDS = (
    Field("byte_count", "uint8", default=7),
    Field("reference_type", "uint8", default=0x06),
    Field("file_number", "uint16", default=0),
    Field("record_number", "uint16", default=0),
    Field("record_length", "uint16", default=1),
)

#: FC0x14 读文件记录响应：两个长度字段都由记录数据长度推出
#: 记录数据以寄存器计（请求的 record_length 个寄存器），字节数是它的两倍
_FILE_READ_RESPONSE_FIELDS = (
    Field("byte_count", "uint8", count_of="record_data", adjust=lambda n: n + 2),
    Field("file_response_length", "uint8", count_of="record_data", adjust=lambda n: n + 1),
    Field("reference_type", "uint8", default=0x06),
    Field(
        "record_data",
        "bytes",
        count_from="file_response_length",
        count_adjust=lambda n: n - 1,
        len_from_request="record_length",
        len_adjust=lambda n: n * 2,
        default=b"\x00\x01\x00\x02",
    ),
)

#: FC0x15 写文件记录：请求与响应同构（响应是请求的回显）
_FILE_WRITE_FIELDS = (
    Field("byte_count", "uint8", count_of="record_data", adjust=lambda n: n + 7),
    Field("reference_type", "uint8", default=0x06),
    Field("file_number", "uint16", default=0),
    Field("record_number", "uint16", default=0),
    Field("record_length", "uint16", count_of="record_data", adjust=lambda n: n // 2),
    Field(
        "record_data",
        "bytes",
        count_from="record_length",
        count_is_elements=True,
        count_adjust=lambda n: n * 2,
        default=b"\x00\x01\x00\x02",
    ),
)

LAYOUTS: dict[str, Layout] = {
    "fc01": _BIT_READ_LAYOUT,
    "fc02": _BIT_READ_LAYOUT,
    "fc03": _REGISTER_READ_LAYOUT,
    "fc04": _REGISTER_READ_LAYOUT,
    "fc05": _WRITE_SINGLE_LAYOUT,
    "fc06": _WRITE_SINGLE_LAYOUT,
    "fc07": Layout(request=(), response=(Field("status", "uint8"),)),
    "fc08": Layout(
        request=(Field("sub_function", "uint16"), Field("data", "uint16")),
        response=(Field("sub_function", "uint16"), Field("data", "uint16")),
    ),
    "fc0b": Layout(
        request=(),
        response=(Field("status", "uint16"), Field("event_count", "uint16")),
    ),
    "fc0c": Layout(
        request=(),
        response=(
            Field("byte_count", "uint8", count_of="events", adjust=lambda n: n + 6),
            Field("status", "uint16", default=0),
            Field("event_count", "uint16", default=0),
            Field("message_count", "uint16", default=0),
            Field("events", "bytes", count_from="byte_count", count_adjust=lambda n: n - 6),
        ),
    ),
    "fc0f": Layout(
        request=(
            Field("start_addr", "uint16"),
            # quantity 是线圈数，位图的字节数由它推出（÷8 向上取整）
            Field("quantity", "uint16", default=8),
            Field("byte_count", "uint8", count_of="values"),
            Field(
                "values",
                "bytes",
                count_from="byte_count",
                len_from_request="quantity",
                len_adjust=lambda n: (n + 7) // 8,
            ),
        ),
        response=(Field("start_addr", "uint16"), Field("quantity", "uint16")),
    ),
    "fc10": Layout(
        request=(
            Field("start_addr", "uint16"),
            # quantity 是寄存器数，values 的元素个数与它相同
            Field("quantity", "uint16", default=2),
            Field("byte_count", "uint8", count_of="values", adjust=lambda n: n * 2),
            Field(
                "values",
                "uint16",
                count_from="byte_count",
                len_from_request="quantity",
            ),
        ),
        response=(Field("start_addr", "uint16"), Field("quantity", "uint16")),
    ),
    "fc11": Layout(
        request=(),
        response=(
            Field("byte_count", "uint8", count_of="slave_id", adjust=lambda n: n + 1),
            Field(
                "slave_id",
                "bytes",
                count_from="byte_count",
                count_adjust=lambda n: n - 1,
                default=b"Pymodbus",
            ),
            Field("run_indicator_status", "uint8", default=0xFF),
        ),
    ),
    "fc14": Layout(
        request=_FILE_READ_REQUEST_FIELDS,
        response=_FILE_READ_RESPONSE_FIELDS,
    ),
    "fc15": Layout(
        request=_FILE_WRITE_FIELDS,
        response=_FILE_WRITE_FIELDS,
    ),
    "fc16": Layout(
        request=(
            Field("start_addr", "uint16"),
            Field("and_mask", "uint16"),
            Field("or_mask", "uint16"),
        ),
        response=(
            Field("start_addr", "uint16"),
            Field("and_mask", "uint16"),
            Field("or_mask", "uint16"),
        ),
    ),
    "fc17": Layout(
        request=(
            Field("read_addr", "uint16"),
            Field("read_quantity", "uint16"),
            Field("write_addr", "uint16"),
            # write_quantity 是写入寄存器数，write_values 的元素个数与它相同
            Field("write_quantity", "uint16", default=1),
            Field("write_byte_count", "uint8", count_of="write_values", adjust=lambda n: n * 2),
            Field(
                "write_values",
                "uint16",
                count_from="write_byte_count",
                len_from_request="write_quantity",
            ),
        ),
        response=(
            Field("byte_count", "uint8", count_of="values", adjust=lambda n: n * 2),
            Field("values", "uint16", count_from="byte_count", len_from_request="read_quantity"),
        ),
    ),
    "fc18": Layout(
        request=(Field("fifo_pointer_address", "uint16"),),
        response=(
            Field("byte_count", "uint16", count_of="fifo_values", adjust=lambda n: n * 2 + 2),
            Field("fifo_count", "uint16", count_of="fifo_values"),
            Field("fifo_values", "uint16", count_from="fifo_count", count_is_elements=True, default=(0, 1, 2, 3)),
        ),
    ),
    "fc2b": Layout(
        request=(
            Field("mei_type", "uint8", default=0x0E),
            Field("read_device_id_code", "uint8", default=0x01),
            Field("object_id", "uint8", default=0x00),
        ),
        response=(
            Field("mei_type", "uint8", default=0x0E),
            Field("read_device_id_code", "uint8", default=0x01),
            Field("conformity_level", "uint8", default=0x83),
            Field("more_follows", "uint8", default=0x00),
            Field("next_object_id", "uint8", default=0x00),
            Field("number_of_objects", "uint8", default=0x01),
            Field("object_id", "uint8", default=0x00),
            Field("object_size", "uint8", count_of="object_value"),
            Field("object_value", "bytes", count_from="object_size", default=b"\x01\x02"),
        ),
    ),
}


def get_layout(name: str) -> Layout:
    """按名称取布局，不存在时抛 KeyError。"""
    try:
        return LAYOUTS[name]
    except KeyError as exc:
        raise KeyError(f"不存在布局 {name!r}，可用布局：{sorted(LAYOUTS)}") from exc
```

**（6）创建 `icsgen/protocols/modbus/catalog.yaml`**：

```yaml
protocol: modbus
transports: [tcp, rtu]
operations:
  # ---- 读取类功能码（4 个）----
  - {name: modbus.read_coils, summary: 读线圈状态 (FC01), layout: fc01, func_code: 1, variants: [normal, boundary, exception], params: {start_addr: {type: integer, minimum: 0, maximum: 65535, default: 0}, quantity: {type: integer, minimum: 1, maximum: 2000, default: 8}}}
  - {name: modbus.read_discrete_inputs, summary: 读离散输入 (FC02), layout: fc02, func_code: 2, variants: [normal, boundary, exception], params: {start_addr: {type: integer, minimum: 0, maximum: 65535, default: 0}, quantity: {type: integer, minimum: 1, maximum: 2000, default: 8}}}
  - {name: modbus.read_holding_registers, summary: 读保持寄存器 (FC03), layout: fc03, func_code: 3, variants: [normal, boundary, exception], params: {start_addr: {type: integer, minimum: 0, maximum: 65535, default: 0}, quantity: {type: integer, minimum: 1, maximum: 125, default: 3}}}
  - {name: modbus.read_input_registers, summary: 读输入寄存器 (FC04), layout: fc04, func_code: 4, variants: [normal, boundary, exception], params: {start_addr: {type: integer, minimum: 0, maximum: 65535, default: 0}, quantity: {type: integer, minimum: 1, maximum: 125, default: 3}}}
  # ---- 写入类功能码（5 个）----
  - {name: modbus.write_single_coil, summary: 写单个线圈 (FC05), layout: fc05, func_code: 5, variants: [normal, boundary, exception], params: {start_addr: {type: integer, minimum: 0, maximum: 65535, default: 0}, value: {type: integer, minimum: 0, maximum: 65535, default: 65280}}}
  - {name: modbus.write_single_register, summary: 写单个保持寄存器 (FC06), layout: fc06, func_code: 6, variants: [normal, boundary, exception], params: {start_addr: {type: integer, minimum: 0, maximum: 65535, default: 0}, value: {type: integer, minimum: 0, maximum: 65535, default: 1}}}
  - {name: modbus.write_multiple_coils, summary: 写多个线圈 (FC0F), layout: fc0f, func_code: 15, variants: [normal, boundary, exception], params: {start_addr: {type: integer, minimum: 0, maximum: 65535, default: 0}, quantity: {type: integer, minimum: 1, maximum: 1968, default: 8}, values: {type: array, items: {type: integer, minimum: 0, maximum: 255}, minItems: 1, maxItems: 246, default: [255]}}}
  - {name: modbus.write_multiple_registers, summary: 写多个保持寄存器 (FC10), layout: fc10, func_code: 16, variants: [normal, boundary, exception], params: {start_addr: {type: integer, minimum: 0, maximum: 65535, default: 0}, quantity: {type: integer, minimum: 1, maximum: 123, default: 2}, values: {type: array, items: {type: integer, minimum: 0, maximum: 65535}, minItems: 1, maxItems: 123, default: [1, 1]}}}
  - {name: modbus.mask_write_register, summary: 掩码写寄存器 (FC16), layout: fc16, func_code: 22, variants: [normal, boundary, exception], params: {start_addr: {type: integer, minimum: 0, maximum: 65535, default: 0}, and_mask: {type: integer, minimum: 0, maximum: 65535, default: 65280}, or_mask: {type: integer, minimum: 0, maximum: 65535, default: 0}}}
  # ---- 状态与诊断类功能码（5 个）----
  - {name: modbus.read_exception_status, summary: 读异常状态 (FC07), layout: fc07, func_code: 7, variants: [normal, exception], params: {}}
  - {name: modbus.get_comm_event_counter, summary: 读通信事件计数器 (FC0B), layout: fc0b, func_code: 11, variants: [normal, exception], params: {}}
  - {name: modbus.get_comm_event_log, summary: 读通信事件日志 (FC0C), layout: fc0c, func_code: 12, variants: [normal, exception], params: {}}
  - {name: modbus.report_slave_id, summary: 报告从站 ID (FC11), layout: fc11, func_code: 17, variants: [normal, exception], params: {}}
  - {name: modbus.read_fifo_queue, summary: 读 FIFO 队列 (FC18), layout: fc18, func_code: 24, variants: [normal, exception], params: {fifo_pointer_address: {type: integer, minimum: 0, maximum: 65535, default: 0}}}
  # ---- 文件记录与读写类功能码（3 个）----
  - {name: modbus.read_file_record, summary: 读文件记录 (FC14), layout: fc14, func_code: 20, variants: [normal, boundary, exception], params: {reference_type: {type: integer, minimum: 0, maximum: 255, default: 6}, file_number: {type: integer, minimum: 0, maximum: 65535, default: 4}, record_number: {type: integer, minimum: 0, maximum: 65535, default: 0}, record_length: {type: integer, minimum: 1, maximum: 123, default: 1}}}
  - {name: modbus.write_file_record, summary: 写文件记录 (FC15), layout: fc15, func_code: 21, variants: [normal, boundary, exception], params: {reference_type: {type: integer, minimum: 0, maximum: 255, default: 6}, file_number: {type: integer, minimum: 0, maximum: 65535, default: 4}, record_number: {type: integer, minimum: 0, maximum: 65535, default: 0}, record_data: {type: array, items: {type: integer, minimum: 0, maximum: 255}, minItems: 2, maxItems: 246, default: [0, 1, 0, 2]}}}
  - {name: modbus.read_write_multiple_registers, summary: 读写多个保持寄存器 (FC17), layout: fc17, func_code: 23, variants: [normal, boundary, exception], params: {read_addr: {type: integer, minimum: 0, maximum: 65535, default: 0}, read_quantity: {type: integer, minimum: 1, maximum: 125, default: 1}, write_addr: {type: integer, minimum: 0, maximum: 65535, default: 0}, write_quantity: {type: integer, minimum: 1, maximum: 121, default: 1}, write_values: {type: array, items: {type: integer, minimum: 0, maximum: 65535}, minItems: 1, maxItems: 121, default: [1]}}}
  # ---- 设备标识 MEI（2 个：basic 与 specific 两种访问方式）----
  - {name: modbus.read_device_identification, summary: 读设备标识 MEI-basic (FC2B), layout: fc2b, func_code: 43, variants: [normal, boundary, exception], params: {read_device_id_code: {type: integer, minimum: 1, maximum: 3, default: 1}, object_id: {type: integer, minimum: 0, maximum: 255, default: 0}}}
  - {name: modbus.read_device_identification_specific, summary: 读设备标识 MEI-specific (FC2B), layout: fc2b, func_code: 43, variants: [normal, boundary, exception], params: {read_device_id_code: {type: integer, minimum: 4, maximum: 4, default: 4}, object_id: {type: integer, minimum: 0, maximum: 255, default: 0}}}
  # ---- 诊断子功能：21 个独立操作类型，共享 fc08 布局 ----
  - {name: modbus.diagnostics.return_query_data, summary: 诊断-返回查询数据 (FC08/00), layout: fc08, func_code: 8, variants: [normal, exception], params: {sub_function: {type: integer, minimum: 0, maximum: 65535, default: 0}, data: {type: integer, minimum: 0, maximum: 65535, default: 0}}}
  - {name: modbus.diagnostics.restart_communications_option, summary: 诊断-重启通信选项 (FC08/01), layout: fc08, func_code: 8, variants: [normal, exception], params: {sub_function: {type: integer, minimum: 0, maximum: 65535, default: 1}, data: {type: integer, minimum: 0, maximum: 65535, default: 0}}}
  - {name: modbus.diagnostics.return_diagnostic_register, summary: 诊断-返回诊断寄存器 (FC08/02), layout: fc08, func_code: 8, variants: [normal, exception], params: {sub_function: {type: integer, minimum: 0, maximum: 65535, default: 2}, data: {type: integer, minimum: 0, maximum: 65535, default: 0}}}
  - {name: modbus.diagnostics.change_ascii_input_delimiter, summary: 诊断-更改 ASCII 输入定界符 (FC08/03), layout: fc08, func_code: 8, variants: [normal, exception], params: {sub_function: {type: integer, minimum: 0, maximum: 65535, default: 3}, data: {type: integer, minimum: 0, maximum: 65535, default: 10}}}
  - {name: modbus.diagnostics.force_listen_only_mode, summary: 诊断-强制仅监听模式 (FC08/04), layout: fc08, func_code: 8, variants: [normal, exception], params: {sub_function: {type: integer, minimum: 0, maximum: 65535, default: 4}, data: {type: integer, minimum: 0, maximum: 65535, default: 0}}}
  - {name: modbus.diagnostics.change_byte_count, summary: 诊断-更改字节计数 (FC08/05), layout: fc08, func_code: 8, variants: [normal, exception], params: {sub_function: {type: integer, minimum: 0, maximum: 65535, default: 5}, data: {type: integer, minimum: 0, maximum: 65535, default: 0}}}
  - {name: modbus.diagnostics.change_word_count, summary: 诊断-更改字计数 (FC08/06), layout: fc08, func_code: 8, variants: [normal, exception], params: {sub_function: {type: integer, minimum: 0, maximum: 65535, default: 6}, data: {type: integer, minimum: 0, maximum: 65535, default: 0}}}
  - {name: modbus.diagnostics.get_modify_modbus_plus_parameters, summary: 诊断-获取/修改 Modbus Plus 参数 (FC08/08), layout: fc08, func_code: 8, variants: [normal, exception], params: {sub_function: {type: integer, minimum: 0, maximum: 65535, default: 8}, data: {type: integer, minimum: 0, maximum: 65535, default: 0}}}
  - {name: modbus.diagnostics.clear_counters_and_diagnostic_register, summary: 诊断-清除计数器和诊断寄存器 (FC08/0A), layout: fc08, func_code: 8, variants: [normal, exception], params: {sub_function: {type: integer, minimum: 0, maximum: 65535, default: 10}, data: {type: integer, minimum: 0, maximum: 65535, default: 0}}}
  - {name: modbus.diagnostics.return_bus_message_count, summary: 诊断-返回总线消息计数 (FC08/0B), layout: fc08, func_code: 8, variants: [normal, exception], params: {sub_function: {type: integer, minimum: 0, maximum: 65535, default: 11}, data: {type: integer, minimum: 0, maximum: 65535, default: 0}}}
  - {name: modbus.diagnostics.return_bus_communication_error_count, summary: 诊断-返回总线通信错误计数 (FC08/0C), layout: fc08, func_code: 8, variants: [normal, exception], params: {sub_function: {type: integer, minimum: 0, maximum: 65535, default: 12}, data: {type: integer, minimum: 0, maximum: 65535, default: 0}}}
  - {name: modbus.diagnostics.return_bus_exception_error_count, summary: 诊断-返回总线异常错误计数 (FC08/0D), layout: fc08, func_code: 8, variants: [normal, exception], params: {sub_function: {type: integer, minimum: 0, maximum: 65535, default: 13}, data: {type: integer, minimum: 0, maximum: 65535, default: 0}}}
  - {name: modbus.diagnostics.return_slave_message_count, summary: 诊断-返回从站消息计数 (FC08/0E), layout: fc08, func_code: 8, variants: [normal, exception], params: {sub_function: {type: integer, minimum: 0, maximum: 65535, default: 14}, data: {type: integer, minimum: 0, maximum: 65535, default: 0}}}
  - {name: modbus.diagnostics.return_slave_no_response_count, summary: 诊断-返回从站无响应计数 (FC08/0F), layout: fc08, func_code: 8, variants: [normal, exception], params: {sub_function: {type: integer, minimum: 0, maximum: 65535, default: 15}, data: {type: integer, minimum: 0, maximum: 65535, default: 0}}}
  - {name: modbus.diagnostics.return_slave_nak_count, summary: 诊断-返回从站 NAK 计数 (FC08/10), layout: fc08, func_code: 8, variants: [normal, exception], params: {sub_function: {type: integer, minimum: 0, maximum: 65535, default: 16}, data: {type: integer, minimum: 0, maximum: 65535, default: 0}}}
  - {name: modbus.diagnostics.return_slave_busy_count, summary: 诊断-返回从站忙计数 (FC08/11), layout: fc08, func_code: 8, variants: [normal, exception], params: {sub_function: {type: integer, minimum: 0, maximum: 65535, default: 17}, data: {type: integer, minimum: 0, maximum: 65535, default: 0}}}
  - {name: modbus.diagnostics.return_bus_character_overrun_count, summary: 诊断-返回总线字符溢出计数 (FC08/12), layout: fc08, func_code: 8, variants: [normal, exception], params: {sub_function: {type: integer, minimum: 0, maximum: 65535, default: 18}, data: {type: integer, minimum: 0, maximum: 65535, default: 0}}}
  - {name: modbus.diagnostics.clear_overrun_counter_and_flag, summary: 诊断-清除溢出计数器与标志 (FC08/14), layout: fc08, func_code: 8, variants: [normal, exception], params: {sub_function: {type: integer, minimum: 0, maximum: 65535, default: 20}, data: {type: integer, minimum: 0, maximum: 65535, default: 0}}}
  - {name: modbus.diagnostics.get_clear_modbus_plus_request, summary: 诊断-获取清除 Modbus Plus 请求 (FC08/15), layout: fc08, func_code: 8, variants: [normal, exception], params: {sub_function: {type: integer, minimum: 0, maximum: 65535, default: 21}, data: {type: integer, minimum: 0, maximum: 65535, default: 0}}}
  - {name: modbus.diagnostics.return_io_overrun_count, summary: 诊断-返回 I/O 溢出计数 (FC08/17), layout: fc08, func_code: 8, variants: [normal, exception], params: {sub_function: {type: integer, minimum: 0, maximum: 65535, default: 23}, data: {type: integer, minimum: 0, maximum: 65535, default: 0}}}
  - {name: modbus.diagnostics.clear_io_overrun_counter_and_flag, summary: 诊断-清除 I/O 溢出计数器与标志 (FC08/18), layout: fc08, func_code: 8, variants: [normal, exception], params: {sub_function: {type: integer, minimum: 0, maximum: 65535, default: 24}, data: {type: integer, minimum: 0, maximum: 65535, default: 0}}}
  # ---- 协议级异常：非法功能码（0x63 是保留值）----
  - {name: modbus.illegal_function_code, summary: 非法/保留功能码, layout: fc01, func_code: 99, variants: [illegal_fc, exception], params: {start_addr: {type: integer, minimum: 0, maximum: 65535, default: 0}, quantity: {type: integer, minimum: 1, maximum: 2000, default: 1}}}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `python3 -m pytest tests/test_modbus_layouts.py tests/test_codec.py -v`
Expected: PASS —— 27 + 18 = 45 passed

- [ ] **Step 5: 提交**

```bash
git add icsgen/protocols/ icsgen/spec/catalog.py icsgen/codec/ tests/test_modbus_layouts.py tests/test_codec.py
git commit -m "$(cat <<'EOF'
fix: 按 Modbus 规范校正字段布局，去掉 catalog 的 tier 第二事实源

八个布局的字段结构与规范不符（fc0c/fc11/fc14/fc15/fc16/fc17/fc18/fc2b），
0x12 是保留空档而非读文件记录 —— 一并按规范重写并补齐对应测试。

编解码内核新增 count_is_elements 与 count_adjust 两个长度换算开关，
支持「元素计数」形态的长度字段；编码缺值时回退到字段缺省值。

catalog 移除 OperationEntry.tier：语义层由变体唯一决定，
catalog 再声明 tier 会与「同一操作类型既有合法变体又有异常变体」自相矛盾。

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Modbus 变体语义

**Files:**
- Create: `icsgen/protocols/modbus/variants.py`
- Create: `tests/test_modbus_variants.py`
- Modify: `icsgen/protocols/modbus/layouts.py`（FC0x14 响应的记录数据长度改由请求的 `record_length` 推出；FC0F/FC10/FC17 的请求数组声明长度来源与计数标量）
- Modify: `icsgen/codec/fields.py`（`Field.len_from_request` 的说明覆盖「请求内计数标量」这一路径）

**Interfaces:**
- Consumes: `icsgen.codec.fields.Layout`、`icsgen.protocols.modbus.layouts.get_layout`（Task 4）、`icsgen.spec.model.Variant`（Task 1）
- 注意：Task 4 给 `Field` 加了 `len_adjust`（构造路径上的元素个数修正），本任务的 `_element_count` 必须区分「来自请求」与「来自长度字段」两条路径 —— 前者用 `len_adjust`，后者用 `count_adjust`。
- Produces:
  - `icsgen.protocols.modbus.variants.VariantPlan`：`frozen dataclass`，字段 `func_code: int`、`request_values: dict[str, Any]`、`response_values: dict[str, Any]`、`is_exception: bool`、`metadata: dict[str, Any]`
  - `icsgen.protocols.modbus.variants.plan_variant(layout: Layout, op_name: str, func_code: int, params: dict[str, Any], variant: Variant, maxima: dict[str, int] | None = None, max_counts: dict[str, int] | None = None) -> VariantPlan`

**变体策略**：

| 变体 | 请求 | 响应 |
|---|---|---|
| `normal` | 按 catalog 参数默认值填充 | 按布局生成合理的默认值 |
| `boundary` | 标量参数取上界（`maxima`）；数组参数取其应有的长度并把每个元素顶到元素上界（`maxima`） | 同 normal |
| `exception` | 请求同 normal | 异常响应：功能码 \| 0x80 + 异常码（默认 0x02 非法数据地址） |
| `illegal_fc` | 功能码就是 catalog 条目声明的非法功能码 | 异常响应：功能码 \| 0x80 + 异常码 0x01 非法功能码 |
| `malformed` | 请求同 normal，但长度字段与实际内容不符 | 无响应 |

> `illegal_fc` 变体的功能码不再由参数携带：catalog 条目 `modbus.illegal_function_code`
> 的 `func_code` 本身就是保留值（99），参数里再放一个功能码会形成第二事实源。

> **边界变体为什么要两个上界**：catalog 对数组参数同时声明了「元素个数上界」（`maxItems`）
> 与「元素值上界」（`items.maximum`）。只顶元素值而不顶元素个数，会让帧自相矛盾 ——
> FC10 写多个寄存器若 `quantity` 顶到 123 而 `values` 只有 2 个元素，从站会直接判为协议错误，
> 而这份流量挂在 `legit` 语义层下。故 `maxima` 传元素值上界，`max_counts` 传元素个数上界，
> 两者都来自 catalog，由适配器（Task 11）读出后传入。

> **数组长度由计数标量决定**：请求里的数组长度不由参数给，而由同帧的计数标量决定 ——
> FC10 的 `values` 元素数 = `quantity`，FC0F 的 `values` 字节数 = ⌈`quantity` ÷ 8⌉，
> FC17 的 `write_values` 元素数 = `write_quantity`。计数标量是权威的一方：数组内容
> 不足时补零、超出时截断。这样场景改写 `quantity` 时帧里的计数标量与实际内容不会脱节。
> 布局上用 `Field.len_from_request` 声明这层关系；边界变体里计数标量被顶到上界，
> 数组长度随之变化。

- [ ] **Step 1: 写失败的测试**

创建 `tests/test_modbus_variants.py`：

```python
"""Modbus 变体语义：同一操作的正常/边界/异常/非法功能码形态。"""

from icsgen.codec.encoder import encode
from icsgen.protocols.modbus.layouts import get_layout
from icsgen.protocols.modbus.variants import plan_variant
from icsgen.spec.model import Variant


def test_normal_plan_uses_given_params():
    layout = get_layout("fc03")
    plan = plan_variant(layout, "modbus.read_holding_registers", 3, {"start_addr": 5, "quantity": 3}, Variant.NORMAL)
    assert plan.func_code == 3
    assert plan.request_values["start_addr"] == 5
    assert plan.request_values["quantity"] == 3
    assert plan.is_exception is False


def test_boundary_plan_uses_upper_bound():
    """边界变体把 quantity 顶到上界 125。"""
    layout = get_layout("fc03")
    plan = plan_variant(
        layout,
        "modbus.read_holding_registers",
        3,
        {"start_addr": 0, "quantity": 3},
        Variant.BOUNDARY,
        maxima={"quantity": 125},
    )
    assert plan.request_values["quantity"] == 125


def test_exception_plan_marks_exception():
    layout = get_layout("fc03")
    plan = plan_variant(layout, "modbus.read_holding_registers", 3, {"quantity": 3}, Variant.EXCEPTION)
    assert plan.is_exception is True
    assert plan.metadata["exception_code"] == 2


def test_illegal_function_code_variant_marks_exception():
    """非法功能码由 catalog 条目的 func_code 决定，响应是异常响应。"""
    layout = get_layout("fc01")
    plan = plan_variant(
        layout,
        "modbus.illegal_function_code",
        99,
        {"quantity": 1},
        Variant.ILLEGAL_FC,
    )
    assert plan.func_code == 99
    assert plan.is_exception is True
    assert plan.metadata["illegal_function_code"] == 99
    assert plan.metadata["exception_code"] == 1


def test_malformed_variant_has_no_response():
    layout = get_layout("fc03")
    plan = plan_variant(layout, "modbus.read_holding_registers", 3, {"quantity": 3}, Variant.MALFORMED)
    assert plan.response_values == {}
    assert plan.metadata["malformed"] is True


def test_response_values_populated_for_normal():
    layout = get_layout("fc03")
    plan = plan_variant(layout, "modbus.read_holding_registers", 3, {"quantity": 3}, Variant.NORMAL)
    assert "values" in plan.response_values
    assert len(plan.response_values["values"]) == 3


def test_response_byte_count_matches_value_count():
    """FC03 响应的 byte_count 应等于寄存器数的两倍。"""
    layout = get_layout("fc03")
    plan = plan_variant(layout, "modbus.read_holding_registers", 3, {"quantity": 3}, Variant.NORMAL)
    assert plan.response_values["byte_count"] == 6
    assert len(plan.response_values["values"]) == 3


def test_bit_read_response_is_packed_to_bytes():
    """FC01 响应数据按位打包：9 个线圈占 2 字节，不是 9 字节。"""
    layout = get_layout("fc01")
    plan = plan_variant(layout, "modbus.read_coils", 1, {"quantity": 9}, Variant.NORMAL)
    assert plan.response_values["byte_count"] == 2
    assert plan.response_values["values"] == b"\x00\x00"


def test_boundary_plan_pushes_array_elements_to_maximum():
    """边界变体把数组参数的每个元素都顶到元素上界。"""
    layout = get_layout("fc10")
    plan = plan_variant(
        layout,
        "modbus.write_multiple_registers",
        16,
        {"quantity": 2, "values": [1, 2]},
        Variant.BOUNDARY,
        maxima={"values": 0xFFFF},
    )
    assert plan.request_values["values"] == [0xFFFF, 0xFFFF]


def test_file_write_response_length_fields_are_consistent():
    """FC15 响应的 byte_count 与 record_length 必须与记录数据自洽。"""
    layout = get_layout("fc15")
    plan = plan_variant(
        layout,
        "modbus.write_file_record",
        21,
        {"record_data": b"\x00\x01\x00\x02"},
        Variant.NORMAL,
    )
    assert plan.request_values["record_length"] == 2
    assert plan.request_values["byte_count"] == 11
    assert plan.response_values["record_length"] == 2
    assert plan.response_values["byte_count"] == 11
    assert len(plan.response_values["record_data"]) == 4


def test_circular_array_is_never_a_scalar():
    """数组的取值必须是序列而不是标量。

    FC17 的 write_values 长度由 write_byte_count 推出，而 write_byte_count 又由
    write_values 推出 —— 环状引用下无法从长度字段反推数组，只能由计数标量
    write_quantity 推出。给标量会让编码器在遍历数组时抛裸 TypeError。
    """
    layout = get_layout("fc17")
    plan = plan_variant(layout, "modbus.read_write_multiple_registers", 23, {}, Variant.NORMAL)
    assert plan.request_values["write_values"] == [0]
    assert encode(layout.request, plan.request_values) == b"\x00\x00\x00\x00\x00\x00\x00\x01\x02\x00\x00"


def test_response_array_without_length_source_is_a_sequence():
    """长度来源不可得的响应数组退回占位值，占位值同样是序列。"""
    layout = get_layout("fc0c")
    plan = plan_variant(layout, "modbus.get_comm_event_log", 12, {}, Variant.NORMAL)
    assert plan.response_values["events"] == b"\x00"
    assert plan.response_values["byte_count"] == 7


def test_fc10_request_array_follows_quantity():
    """FC10 的寄存器数组长度跟随 quantity：计数标量与实际内容必须一致。"""
    layout = get_layout("fc10")
    plan = plan_variant(
        layout,
        "modbus.write_multiple_registers",
        16,
        {"quantity": 5, "values": [1, 1]},
        Variant.NORMAL,
    )
    assert plan.request_values["values"] == [1, 1, 0, 0, 0]
    assert plan.request_values["byte_count"] == 10


def test_fc0f_request_bitmap_follows_quantity():
    """FC0F 的线圈位图字节数是线圈数除以 8 向上取整。"""
    layout = get_layout("fc0f")
    plan = plan_variant(
        layout,
        "modbus.write_multiple_coils",
        15,
        {"quantity": 16, "values": b"\xff"},
        Variant.NORMAL,
    )
    assert plan.request_values["values"] == b"\xff\x00"
    assert plan.request_values["byte_count"] == 2


def test_fc17_write_values_follows_write_quantity():
    """FC17 的写入数组长度跟随 write_quantity。"""
    layout = get_layout("fc17")
    plan = plan_variant(
        layout,
        "modbus.read_write_multiple_registers",
        23,
        {"write_quantity": 3, "write_values": [1]},
        Variant.NORMAL,
    )
    assert plan.request_values["write_values"] == [1, 0, 0]
    assert plan.request_values["write_byte_count"] == 6


def test_count_scalar_is_authoritative_over_array():
    """计数标量与数组矛盾时以计数标量为准：数组截断，不反过来改写计数标量。"""
    layout = get_layout("fc10")
    plan = plan_variant(
        layout,
        "modbus.write_multiple_registers",
        16,
        {"quantity": 1, "values": [1, 2, 3]},
        Variant.NORMAL,
    )
    assert plan.request_values["quantity"] == 1
    assert plan.request_values["values"] == [1]
    assert plan.request_values["byte_count"] == 2


def test_boundary_grows_array_to_max_count():
    """边界变体把数组顶到最大元素个数，长度字段随之自洽。"""
    layout = get_layout("fc10")
    plan = plan_variant(
        layout,
        "modbus.write_multiple_registers",
        16,
        {"quantity": 2, "values": [1, 1]},
        Variant.BOUNDARY,
        maxima={"quantity": 123, "values": 0xFFFF},
        max_counts={"values": 123},
    )
    assert plan.request_values["quantity"] == 123
    assert plan.request_values["values"] == [0xFFFF] * 123
    assert plan.request_values["byte_count"] == 246


def test_boundary_grows_bytes_array_to_max_count():
    """字节数组（FC0F 的线圈位图）同样顶到最大元素个数。"""
    layout = get_layout("fc0f")
    plan = plan_variant(
        layout,
        "modbus.write_multiple_coils",
        15,
        {"quantity": 8, "values": b"\xff"},
        Variant.BOUNDARY,
        maxima={"quantity": 1968, "values": 255},
        max_counts={"values": 246},
    )
    assert plan.request_values["quantity"] == 1968
    assert plan.request_values["values"] == b"\xff" * 246
    assert plan.request_values["byte_count"] == 246


def test_boundary_grows_fc17_write_values_to_max_count():
    """FC17 的写入数组在边界变体下同样跟随计数标量。"""
    layout = get_layout("fc17")
    plan = plan_variant(
        layout,
        "modbus.read_write_multiple_registers",
        23,
        {"write_quantity": 1, "write_values": [1]},
        Variant.BOUNDARY,
        maxima={"write_quantity": 121, "write_values": 0xFFFF},
        max_counts={"write_values": 121},
    )
    assert plan.request_values["write_quantity"] == 121
    assert plan.request_values["write_values"] == [0xFFFF] * 121
    assert plan.request_values["write_byte_count"] == 242


def test_fc14_response_record_data_follows_requested_length():
    """FC14 响应带回请求的记录长度：记录长度以寄存器计，字节数是它的两倍。"""
    layout = get_layout("fc14")
    plan = plan_variant(
        layout,
        "modbus.read_file_record",
        20,
        {"record_length": 2},
        Variant.NORMAL,
    )
    assert plan.response_values["record_data"] == b"\x00\x00\x00\x00"
    assert plan.response_values["file_response_length"] == 5
    assert plan.response_values["byte_count"] == 6


def test_metadata_carries_operation_name():
    """取值方案的元数据带上操作名，帧才能溯源到操作类型。"""
    layout = get_layout("fc03")
    plan = plan_variant(layout, "modbus.read_holding_registers", 3, {"quantity": 3}, Variant.NORMAL)
    assert plan.metadata["op"] == "modbus.read_holding_registers"
```

- [ ] **Step 2: 运行测试确认失败**

Run: `python3 -m pytest tests/test_modbus_variants.py -v`
Expected: FAIL —— `ModuleNotFoundError: No module named 'icsgen.protocols.modbus.variants'`

- [ ] **Step 3: 写最小实现**

创建 `icsgen/protocols/modbus/variants.py`：

```python
"""Modbus 变体语义。

同一操作在不同变体下的取值策略集中在这里：normal 取常规值，boundary 取
参数上界，exception 产生协议异常响应，illegal_fc 使用非法功能码，
malformed 构造长度字段与实际内容不符的畸形帧。

帧里的计数标量必须与实际内容自洽：请求内数组的长度由计数标量决定
（FC10 的 quantity、FC0F 的 quantity、FC17 的 write_quantity），长度字段
再由数组长度推出。

边界变体需要两个上界：``maxima`` 是标量参数的上界与数组元素的上界，
``max_counts`` 是数组参数的元素个数上界（用于没有计数标量的数组，如
FC15 的记录数据）。两者都来自 catalog，缺一不可 —— 只顶元素值会让帧里
的计数标量与实际内容自相矛盾。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from icsgen.codec.fields import Field, Layout
from icsgen.spec.model import Variant

#: 协议异常码：0x02 非法数据地址
DEFAULT_EXCEPTION_CODE = 0x02

#: 协议异常码：0x01 非法功能码
ILLEGAL_FUNCTION_EXCEPTION_CODE = 0x01


@dataclass(frozen=True)
class VariantPlan:
    """一个操作在特定变体下的完整取值方案。"""

    func_code: int
    request_values: dict[str, Any] = field(default_factory=dict)
    response_values: dict[str, Any] = field(default_factory=dict)
    is_exception: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


def _default_for(f: Field) -> Any:
    """给没有默认值的字段造一个合理的占位值。"""
    if f.type == "bytes":
        return b""
    return 0


def _array_placeholder(f: Field) -> Any:
    """给变长数组造一个类型正确的占位值（一个元素）。

    数组的元素个数来自长度字段、而长度字段又由数组长度推出时，数组无法
    反推，只能给一个最小长度的占位。占位必须是序列：给标量会让编码器在
    遍历数组时抛裸 TypeError。
    """
    if f.type == "bytes":
        return b"\x00"
    return [0]


def _fit_array(current: Any, count: int, ftype: str) -> Any:
    """把数组调整到 count 个元素：不足补零，超出截断。

    结果形态跟随字段类型：bytes 型字段给出字节串，其余给出列表。
    """
    if count < 0:
        count = 0
    if ftype == "bytes":
        if isinstance(current, (bytes, bytearray)):
            data = bytes(current)
        elif isinstance(current, (list, tuple)):
            data = bytes(int(item) & 0xFF for item in current)
        else:
            data = b""
        if len(data) >= count:
            return data[:count]
        return data + b"\x00" * (count - len(data))
    items = list(current) if isinstance(current, (list, tuple)) else []
    if len(items) >= count:
        return items[:count]
    return items + [0] * (count - len(items))


def _align_arrays(layout: Layout, values: dict[str, Any]) -> None:
    """让请求里的数组长度跟随计数标量，就地更新取值字典。

    计数标量（FC10 的 quantity、FC0F 的 quantity、FC17 的 write_quantity）
    决定数组该有多长；数组长度必须与它一致，否则帧里的计数标量与实际内容
    自相矛盾。内容不足时补零、超出时截断。
    """
    for f in layout.request:
        if f.len_from_request is None:
            continue
        raw = values.get(f.len_from_request)
        if raw is None:
            continue
        count = _element_count(f, int(raw), from_request=True)
        values[f.name] = _fit_array(values.get(f.name), count, f.type)


def _array_length(
    f: Field | None,
    values: dict[str, Any],
    max_counts: dict[str, int],
    name: str,
) -> int:
    """数组在边界变体下该有的长度。

    有计数标量时以计数标量为准（帧里的计数必须与内容一致）；没有计数标量
    的数组（如 FC15 的记录数据）取最大元素个数 ``max_counts``。
    """
    if f is not None and f.len_from_request is not None:
        raw = values.get(f.len_from_request)
        if raw is not None:
            return _element_count(f, int(raw), from_request=True)
    current = values.get(name)
    length = len(current) if isinstance(current, (list, tuple, bytes, bytearray)) else 0
    return max_counts.get(name, length)


def _element_count(f: Field, raw: int, from_request: bool = False) -> int:
    """把长度来源换算成元素个数。

    ``len_from_request`` 给出的已经是元素个数，再经 ``len_adjust`` 修正
    （FC01 的响应数据按位打包，字节数是线圈数 ÷ 8 向上取整）；
    ``count_from`` 给出的通常是字节计数，要除以元素宽度
    （bytes 型宽度为 1，除法无影响），再经 ``count_adjust`` 修正。
    """
    count = int(raw)
    if from_request:
        if f.len_adjust is not None:
            count = f.len_adjust(count)
        return count
    if not f.count_is_elements:
        count = count // (2 if f.type == "uint16" else 1)
    if f.count_adjust is not None:
        count = f.count_adjust(count)
    return count


def _apply_length_fields(fields: tuple[Field, ...], values: dict[str, Any]) -> None:
    """按数组长度算出长度字段（count_of），就地更新取值字典。"""
    for f in fields:
        if f.count_of is None:
            continue
        referenced = values.get(f.count_of)
        if isinstance(referenced, (list, tuple, bytes, bytearray)):
            count = len(referenced)
        else:
            count = int(referenced or 0)
        if f.adjust is not None:
            count = f.adjust(count)
        values[f.name] = count


def _build_values(layout: Layout, params: dict[str, Any]) -> dict[str, Any]:
    """按布局与参数填充取值字典。

    四遍处理：先填普通字段，再定出变长数组，然后让数组长度跟随计数标量，
    最后由数组长度算出长度字段。参数优先，其次是字段声明的缺省值，最后
    才是占位值；变长数组若既没有参数也没有缺省值，按其长度来源补一份零
    填充数据。长度字段与数组内容必须自洽，否则编码出来的帧与声明的规模
    对不上。
    """
    values: dict[str, Any] = {}

    # 第一遍：普通字段
    for f in layout.request:
        if f.count_of is not None or f.count_from is not None:
            continue
        if f.name in params:
            values[f.name] = params[f.name]
        elif f.default is not None:
            values[f.name] = f.default
        else:
            values[f.name] = _default_for(f)

    # 第二遍：变长数组
    by_name = {f.name: f for f in layout.request}
    for f in layout.request:
        if f.count_from is None:
            continue
        if f.name in params:
            values[f.name] = params[f.name]
            continue
        if f.default is not None:
            values[f.name] = f.default
            continue
        # 长度来源：优先用请求内的计数标量，否则用长度字段
        source_name = f.len_from_request or f.count_from
        source = by_name.get(source_name)
        raw = values.get(source_name) if source is not None else None
        if source is None or raw is None:
            values[f.name] = _array_placeholder(f)
            continue
        if f.len_from_request is None and source.count_of is not None:
            # 长度字段本身由数组长度推出，无法反推数组
            values[f.name] = _array_placeholder(f)
            continue
        count = _element_count(f, raw, from_request=f.len_from_request is not None)
        values[f.name] = b"\x00" * count if f.type == "bytes" else [0] * count

    # 第三遍：数组长度跟随计数标量
    _align_arrays(layout, values)

    # 第四遍：长度字段
    _apply_length_fields(layout.request, values)
    return values


def _apply_boundary(
    layout: Layout,
    params: dict[str, Any],
    maxima: dict[str, int],
    max_counts: dict[str, int],
) -> dict[str, Any]:
    """把参数顶到上界。

    标量参数取其最大值；数组参数取其应有的长度（有计数标量的以计数标量
    为准，没有的取最大元素个数 ``max_counts``），并把每个元素顶到元素上界
    （``maxima``）。数组长度与元素值必须一起顶 —— 只顶元素值会让帧里的
    计数标量与实际内容对不上。
    """
    values = _build_values(layout, params)
    by_name = {f.name: f for f in layout.request}

    # 标量参数顶到上界
    for name, maximum in maxima.items():
        current = values.get(name)
        if isinstance(current, bool):
            continue
        if isinstance(current, int):
            values[name] = maximum

    # 数组参数：长度取应有的长度，元素值顶到元素上界
    for name, maximum in maxima.items():
        current = values.get(name)
        if isinstance(current, (list, tuple)):
            count = _array_length(by_name.get(name), values, max_counts, name)
            values[name] = [maximum] * count
        elif isinstance(current, (bytes, bytearray)):
            count = _array_length(by_name.get(name), values, max_counts, name)
            values[name] = bytes([maximum & 0xFF]) * count

    # 没有元素上界的数组也要跟随计数标量
    _align_arrays(layout, values)

    _apply_length_fields(layout.request, values)
    return values


def _build_response(layout: Layout, request_values: dict[str, Any]) -> dict[str, Any]:
    """构造与请求规模匹配的响应取值。

    三遍处理：先定出各变长数组的长度，再填普通字段，最后由数组长度算出
    长度字段。顺序颠倒会让 FC03 响应的 byte_count 算成 0。
    """
    values: dict[str, Any] = {}

    # 第一遍：变长数组
    for f in layout.response:
        if f.count_from is None:
            continue
        source = f.len_from_request or f.count_from
        raw = request_values.get(source)
        if raw is None:
            # 长度来源不可得（它本身由数组长度推出），退回字段缺省值
            values[f.name] = f.default if f.default is not None else _array_placeholder(f)
            continue
        count = _element_count(f, raw, from_request=f.len_from_request is not None)
        values[f.name] = b"\x00" * count if f.type == "bytes" else [0] * count

    # 第二遍：普通字段
    for f in layout.response:
        if f.count_of is not None or f.count_from is not None:
            continue
        values[f.name] = f.default if f.default is not None else _default_for(f)

    # 第三遍：长度字段
    _apply_length_fields(layout.response, values)
    return values


def plan_variant(
    layout: Layout,
    op_name: str,
    func_code: int,
    params: dict[str, Any],
    variant: Variant,
    maxima: dict[str, int] | None = None,
    max_counts: dict[str, int] | None = None,
) -> VariantPlan:
    """为一个操作在特定变体下制定取值方案。

    maxima 是标量参数的上界与数组元素的上界，max_counts 是数组参数的元素
    个数上界；boundary 变体据此把参数顶到边界。
    """
    maxima = maxima or {}
    max_counts = max_counts or {}

    if variant is Variant.ILLEGAL_FC:
        # 非法功能码由 catalog 条目自身的 func_code 决定
        request_values = _build_values(layout, params)
        return VariantPlan(
            func_code=func_code,
            request_values=request_values,
            response_values={},
            is_exception=True,
            metadata={
                "op": op_name,
                "exception_code": ILLEGAL_FUNCTION_EXCEPTION_CODE,
                "illegal_function_code": func_code,
            },
        )

    if variant is Variant.MALFORMED:
        request_values = _build_values(layout, params)
        return VariantPlan(
            func_code=func_code,
            request_values=request_values,
            response_values={},
            is_exception=False,
            metadata={"op": op_name, "malformed": True},
        )

    if variant is Variant.BOUNDARY:
        request_values = _apply_boundary(layout, params, maxima, max_counts)
    else:
        request_values = _build_values(layout, params)

    response_values = _build_response(layout, request_values)

    if variant is Variant.EXCEPTION:
        return VariantPlan(
            func_code=func_code,
            request_values=request_values,
            response_values={},
            is_exception=True,
            metadata={"op": op_name, "exception_code": DEFAULT_EXCEPTION_CODE},
        )

    return VariantPlan(
        func_code=func_code,
        request_values=request_values,
        response_values=response_values,
        is_exception=False,
        metadata={"op": op_name},
    )
```

- [ ] **Step 4: 运行测试确认通过**

Run: `python3 -m pytest tests/test_modbus_variants.py -v`
Expected: PASS —— 21 passed

- [ ] **Step 5: 提交**

```bash
git add icsgen/protocols/modbus/variants.py icsgen/protocols/modbus/layouts.py tests/test_modbus_variants.py
git commit -m "$(cat <<'EOF'
feat: Modbus 变体语义

normal/boundary/exception/illegal_fc/malformed 五种变体的取值策略
集中到 plan_variant，异常响应与畸形帧由变体直接产出。

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Modbus 组帧（MBAP / RTU / CRC16）

**Files:**
- Create: `icsgen/protocols/modbus/crc.py`
- Create: `icsgen/protocols/modbus/framing.py`
- Create: `tests/test_modbus_framing.py`

**Interfaces:**
- Consumes: `icsgen.codec.encoder.encode`、`icsgen.codec.decoder.decode`（Task 2）、`icsgen.protocols.modbus.layouts.get_layout`（Task 4）、`icsgen.protocols.modbus.variants.VariantPlan`（Task 5）
- Produces:
  - `icsgen.protocols.modbus.crc.crc16(data: bytes) -> int` —— Modbus RTU 的 CRC16（多项式 0xA001，初值 0xFFFF），返回 16 位整数
  - `icsgen.protocols.modbus.framing.build_pdu(func_code: int, payload: bytes) -> bytes`
  - `icsgen.protocols.modbus.framing.build_mbap(transaction_id: int, unit_id: int, pdu: bytes) -> bytes` —— 7 字节 MBAP 头 + PDU
  - `icsgen.protocols.modbus.framing.build_rtu(unit_id: int, pdu: bytes) -> bytes` —— 地址 + PDU + CRC16 小端
  - `icsgen.protocols.modbus.framing.build_exception_pdu(func_code: int, exception_code: int) -> bytes`
  - `icsgen.protocols.modbus.framing.parse_mbap(data: bytes) -> dict[str, Any]` —— 解析出 transaction_id / unit_id / pdu
  - `icsgen.protocols.modbus.framing.parse_rtu(data: bytes) -> dict[str, Any]` —— 解析出 unit_id / pdu 并校验 CRC

- [ ] **Step 1: 写失败的测试**

创建 `tests/test_modbus_framing.py`：

```python
"""Modbus 组帧：MBAP、RTU 与 CRC16。"""

from icsgen.protocols.modbus.crc import crc16
from icsgen.protocols.modbus.framing import (
    build_exception_pdu,
    build_mbap,
    build_pdu,
    build_rtu,
    parse_mbap,
    parse_rtu,
)


def test_crc16_known_vector():
    """CRC-16/MODBUS 的标准校验值：ASCII "123456789" 的 CRC 为 0x4B37。

    该值取自 CRC catalogue，与任何字节序约定无关，用来锚定算法本身。
    """
    assert crc16(b"123456789") == 0x4B37


def test_crc16_rtu_vector_is_low_byte_first():
    """0x01 0x04 0x02 0xFF 0xFF 的 CRC 值为 0x80B8，线上按低字节在前附加。"""
    assert crc16(b"\x01\x04\x02\xff\xff") == 0x80B8
    assert crc16(b"\x01\x04\x02\xff\xff").to_bytes(2, "little") == b"\xb8\x80"


def test_crc16_empty_is_init_value():
    assert crc16(b"") == 0xFFFF


def test_build_pdu_prefixes_function_code():
    assert build_pdu(0x03, b"\x00\x00\x00\x03") == b"\x03\x00\x00\x00\x03"


def test_build_mbap_header():
    """MBAP 头：事务 id、协议 id、长度、单元 id。"""
    pdu = build_pdu(0x03, b"\x00\x00\x00\x03")
    frame = build_mbap(transaction_id=1, unit_id=0xFF, pdu=pdu)
    assert frame[:7] == b"\x00\x01\x00\x00\x00\x06\xff"
    assert len(frame) == 7 + len(pdu)
    assert frame[7:] == pdu


def test_build_mbap_length_field_counts_unit_and_pdu():
    pdu = build_pdu(0x03, b"\x00\x00\x00\x03")
    frame = build_mbap(transaction_id=0, unit_id=0x0A, pdu=pdu)
    length = int.from_bytes(frame[4:6], "big")
    assert length == 1 + len(pdu)


def test_parse_mbap_round_trip():
    pdu = build_pdu(0x03, b"\x00\x00\x00\x03")
    frame = build_mbap(transaction_id=7, unit_id=0x11, pdu=pdu)
    parsed = parse_mbap(frame)
    assert parsed["transaction_id"] == 7
    assert parsed["unit_id"] == 0x11
    assert parsed["pdu"] == pdu


def test_build_rtu_appends_crc_little_endian():
    pdu = build_pdu(0x03, b"\x00\x00\x00\x03")
    frame = build_rtu(unit_id=0x11, pdu=pdu)
    assert frame[0] == 0x11
    assert frame[1:-2] == pdu
    expected = crc16(frame[:-2])
    assert frame[-2:] == expected.to_bytes(2, "little")


def test_build_rtu_matches_known_wire_frame():
    """整帧字节锚定：地址 0x01、FC04、02 FF FF 的 RTU 帧是 01 04 02 FF FF B8 80。"""
    frame = build_rtu(unit_id=0x01, pdu=build_pdu(0x04, b"\x02\xff\xff"))
    assert frame == b"\x01\x04\x02\xff\xff\xb8\x80"


def test_parse_rtu_round_trip():
    pdu = build_pdu(0x03, b"\x00\x00\x00\x03")
    frame = build_rtu(unit_id=0x11, pdu=pdu)
    parsed = parse_rtu(frame)
    assert parsed["unit_id"] == 0x11
    assert parsed["pdu"] == pdu


def test_parse_rtu_rejects_bad_crc():
    pdu = build_pdu(0x03, b"\x00\x00\x00\x03")
    frame = bytearray(build_rtu(unit_id=0x11, pdu=pdu))
    frame[-1] ^= 0xFF
    try:
        parse_rtu(bytes(frame))
    except ValueError as exc:
        assert "CRC" in str(exc)
    else:
        raise AssertionError("应当拒绝 CRC 错误的 RTU 帧")


def test_build_exception_pdu():
    """异常响应：功能码置最高位 + 异常码。"""
    assert build_exception_pdu(0x03, 0x02) == b"\x83\x02"
```

- [ ] **Step 2: 运行测试确认失败**

Run: `python3 -m pytest tests/test_modbus_framing.py -v`
Expected: FAIL —— `ModuleNotFoundError: No module named 'icsgen.protocols.modbus.crc'`

- [ ] **Step 3: 写最小实现**

创建 `icsgen/protocols/modbus/crc.py`：

```python
"""Modbus RTU 的 CRC16 计算。

采用 Modbus 规范的多项式 0xA001（0x8005 的反转形式），初值 0xFFFF，
结果按低字节在前附加到帧尾。
"""

from __future__ import annotations


def crc16(data: bytes) -> int:
    """计算 Modbus RTU CRC16，返回 16 位整数。"""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc
```

创建 `icsgen/protocols/modbus/framing.py`：

```python
"""Modbus 帧的组装与解析。

TCP 用 7 字节 MBAP 头（事务 id、协议 id、长度、单元 id），
RTU 用「地址 + PDU + CRC16」结构。
"""

from __future__ import annotations

from typing import Any

from .crc import crc16

#: MBAP 头长度
MBAP_HEADER_LEN = 7


def build_pdu(func_code: int, payload: bytes) -> bytes:
    """功能码 + PDU 数据。"""
    return bytes([func_code]) + payload


def build_mbap(transaction_id: int, unit_id: int, pdu: bytes) -> bytes:
    """组装 Modbus TCP 帧（MBAP 头 + PDU）。"""
    header = (
        transaction_id.to_bytes(2, "big")
        + b"\x00\x00"
        + (len(pdu) + 1).to_bytes(2, "big")
        + bytes([unit_id])
    )
    return header + pdu


def build_rtu(unit_id: int, pdu: bytes) -> bytes:
    """组装 Modbus RTU 帧（地址 + PDU + CRC16）。"""
    body = bytes([unit_id]) + pdu
    return body + crc16(body).to_bytes(2, "little")


def build_exception_pdu(func_code: int, exception_code: int) -> bytes:
    """组装异常响应 PDU：功能码置最高位，后跟异常码。"""
    return bytes([func_code | 0x80, exception_code])


def parse_mbap(data: bytes) -> dict[str, Any]:
    """解析 Modbus TCP 帧。"""
    if len(data) < MBAP_HEADER_LEN:
        raise ValueError(f"Modbus TCP 帧过短：{len(data)} 字节，至少需要 {MBAP_HEADER_LEN} 字节")
    transaction_id = int.from_bytes(data[0:2], "big")
    protocol_id = int.from_bytes(data[2:4], "big")
    length = int.from_bytes(data[4:6], "big")
    unit_id = data[6]
    return {
        "transaction_id": transaction_id,
        "protocol_id": protocol_id,
        "length": length,
        "unit_id": unit_id,
        "pdu": data[MBAP_HEADER_LEN:],
    }


def parse_rtu(data: bytes) -> dict[str, Any]:
    """解析 Modbus RTU 帧，并校验 CRC。"""
    if len(data) < 4:
        raise ValueError(f"Modbus RTU 帧过短：{len(data)} 字节")
    unit_id = data[0]
    body = data[:-2]
    received = int.from_bytes(data[-2:], "little")
    expected = crc16(body)
    if received != expected:
        raise ValueError(f"Modbus RTU 帧 CRC 校验失败：收到 {received:#06x}，期望 {expected:#06x}")
    return {"unit_id": unit_id, "pdu": data[1:-2]}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `python3 -m pytest tests/test_modbus_framing.py -v`
Expected: PASS —— 12 passed

- [ ] **Step 5: 提交**

```bash
git add icsgen/protocols/modbus/crc.py icsgen/protocols/modbus/framing.py tests/test_modbus_framing.py
git commit -m "$(cat <<'EOF'
feat: Modbus 组帧与 CRC16

MBAP 头组装与解析、RTU 帧组装与解析（含 CRC16 校验）、
异常响应 PDU 构造。

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: 传输封装层

**Files:**
- Create: `icsgen/transport/__init__.py`
- Create: `icsgen/transport/spec.py`
- Create: `icsgen/transport/link.py`
- Create: `tests/test_transport_link.py`

**Interfaces:**
- Consumes: 无（依赖 Scapy）
- Produces:
  - `icsgen.transport.spec.TransportSpec`：`frozen dataclass`，字段 `kind: str = "tcp"`、`dport: int = 502`、`sport: int | None = None`、`src_ip: str = "192.168.1.10"`、`dst_ip: str = "192.168.1.20"`、`mac_src: str = "02:00:00:00:00:01"`、`mac_dst: str = "02:00:00:00:00:02"`、`vlan_id: int | None = None`；方法 `reversed() -> TransportSpec` —— 返回方向相反的传输配置（源/目的 IP 与 MAC 对调、端口对调），用于响应的反向链路封装
  - `icsgen.transport.spec.DEFAULT_SOURCE_PORT = 40001` —— 未指定源端口时的起始端口（由 `TransportSpec.reversed()` 与链路封装共用）
  - `icsgen.transport.link.encapsulate(payload: bytes, transport: TransportSpec, *, seq: int = 0, ack: int = 0, flags: str = "PA") -> bytes` —— 返回完整链路字节

- [ ] **Step 1: 写失败的测试**

创建 `tests/test_transport_link.py`：

```python
"""传输封装层：Ethernet / IP / TCP / UDP。"""

from scapy.all import Ether, IP, TCP, UDP

from icsgen.transport.link import encapsulate
from icsgen.transport.spec import TransportSpec


def _parse(raw: bytes):
    return Ether(raw)


def test_tcp_frame_structure():
    raw = encapsulate(b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x03", TransportSpec())
    pkt = _parse(raw)
    assert pkt[IP].src == "192.168.1.10"
    assert pkt[IP].dst == "192.168.1.20"
    assert pkt[TCP].dport == 502
    assert bytes(pkt[TCP].payload) == b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x03"


def test_tcp_checksum_is_computed():
    raw = encapsulate(b"\xaa" * 6, TransportSpec())
    pkt = _parse(raw)
    assert pkt[TCP].chksum is not None
    assert pkt[IP].chksum is not None


def test_udp_frame_structure():
    raw = encapsulate(b"\x01\x02", TransportSpec(kind="udp", dport=502))
    pkt = _parse(raw)
    assert pkt[UDP].dport == 502
    assert bytes(pkt[UDP].payload) == b"\x01\x02"


def test_serial_kind_returns_raw_payload():
    """串口传输不封装链路层。"""
    raw = encapsulate(b"\x11\x03\x00\x00", TransportSpec(kind="serial"))
    assert raw == b"\x11\x03\x00\x00"


def test_vlan_tag_is_applied():
    raw = encapsulate(b"\x01", TransportSpec(vlan_id=100))
    pkt = _parse(raw)
    assert pkt[Ether].type == 0x8100


def test_custom_ports_are_used():
    raw = encapsulate(b"\x01", TransportSpec(dport=1502, sport=40001))
    pkt = _parse(raw)
    assert pkt[TCP].dport == 1502
    assert pkt[TCP].sport == 40001


def test_reversed_spec_swaps_endpoints():
    """反向配置把源/目的对调：响应当由服务端发往客户端。"""
    spec = TransportSpec(dport=502, sport=40001)
    rev = spec.reversed()
    assert rev.src_ip == spec.dst_ip
    assert rev.dst_ip == spec.src_ip
    assert rev.mac_src == spec.mac_dst
    assert rev.mac_dst == spec.mac_src
    assert rev.sport == spec.dport
    assert rev.dport == 40001


def test_reversed_spec_yields_opposite_direction_on_the_wire():
    spec = TransportSpec()
    request = _parse(encapsulate(b"\x01", spec))
    response = _parse(encapsulate(b"\x02", spec.reversed()))
    assert request[IP].src == response[IP].dst
    assert request[IP].dst == response[IP].src
    assert request[TCP].sport == response[TCP].dport
    assert request[TCP].dport == response[TCP].sport
```

- [ ] **Step 2: 运行测试确认失败**

Run: `python3 -m pytest tests/test_transport_link.py -v`
Expected: FAIL —— `ModuleNotFoundError: No module named 'icsgen.transport'`

- [ ] **Step 3: 写最小实现**

创建 `icsgen/transport/__init__.py`（空文件）。

创建 `icsgen/transport/spec.py`：

```python
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
```

创建 `icsgen/transport/link.py`：

```python
"""链路封装：把协议帧包装成 Ethernet / IP / TCP / UDP 字节。

序列化时由 Scapy 填充 IP 与 TCP/UDP 的校验和。
"""

from __future__ import annotations

from scapy.all import Dot1Q, Ether, IP, TCP, UDP

from .spec import DEFAULT_SOURCE_PORT, TransportSpec


def encapsulate(
    payload: bytes,
    transport: TransportSpec,
    *,
    seq: int = 0,
    ack: int = 0,
    flags: str = "PA",
) -> bytes:
    """把协议帧封装为链路字节。

    kind 为 serial 时直接返回原始字节（串口链路无 IP/TCP 封装）。
    """
    if transport.kind == "serial":
        return payload

    ether = Ether(src=transport.mac_src, dst=transport.mac_dst)
    ip = IP(src=transport.src_ip, dst=transport.dst_ip)
    sport = transport.sport if transport.sport is not None else DEFAULT_SOURCE_PORT

    if transport.kind == "tcp":
        layer = TCP(sport=sport, dport=transport.dport, seq=seq, ack=ack, flags=flags)
    elif transport.kind == "udp":
        layer = UDP(sport=sport, dport=transport.dport)
    else:
        raise ValueError(f"不支持的传输类型 {transport.kind!r}")

    if transport.vlan_id is not None:
        ether = Ether(src=transport.mac_src, dst=transport.mac_dst, type=0x8100)
        ip = Dot1Q(vlan=transport.vlan_id) / ip

    return bytes(ether / ip / layer / payload)
```

- [ ] **Step 4: 运行测试确认通过**

Run: `python3 -m pytest tests/test_transport_link.py -v`
Expected: PASS —— 8 passed

- [ ] **Step 5: 提交**

```bash
git add icsgen/transport/ tests/test_transport_link.py
git commit -m "$(cat <<'EOF'
feat: 传输封装层

Ethernet/IP/TCP/UDP 封装，序列化时自动填充校验和；
serial 类型直通原始字节以适配 RTU。

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: pcap 写出与原始字节导出

**Files:**
- Create: `icsgen/transport/pcap.py`
- Create: `icsgen/emit/__init__.py`
- Create: `icsgen/emit/raw.py`
- Create: `tests/test_pcap.py`

**Interfaces:**
- Consumes: 无
- Produces:
  - `icsgen.transport.pcap.write_pcap(path: Path, packets: list[bytes], *, link_type: int = 1) -> None` —— 写标准 libpcap 文件（link_type 1 = Ethernet）
  - `icsgen.emit.raw.write_raw(directory: Path, name: str, payload: bytes) -> tuple[Path, Path]` —— 写 `.bin` 与 `.hex`，返回两个路径

- [ ] **Step 1: 写失败的测试**

创建 `tests/test_pcap.py`：

```python
"""pcap 写出与原始字节导出。"""

from scapy.all import Ether, IP, TCP, rdpcap

from icsgen.emit.raw import write_raw
from icsgen.transport.link import encapsulate
from icsgen.transport.pcap import write_pcap
from icsgen.transport.spec import TransportSpec


def test_write_pcap_creates_readable_file(tmp_path):
    path = tmp_path / "out.pcap"
    packets = [encapsulate(b"\x01\x02\x03", TransportSpec()), encapsulate(b"\x04\x05", TransportSpec())]
    write_pcap(path, packets)
    assert path.exists()
    read = rdpcap(str(path))
    assert len(read) == 2
    assert bytes(read[0][TCP].payload) == b"\x01\x02\x03"


def test_pcap_global_header_is_little_endian(tmp_path):
    path = tmp_path / "out.pcap"
    write_pcap(path, [])
    header = path.read_bytes()[:24]
    assert header[:4] == b"\xd4\xc3\xb2\xa1"
    assert int.from_bytes(header[20:24], "little") == 1


def test_write_raw_creates_bin_and_hex(tmp_path):
    bin_path, hex_path = write_raw(tmp_path, "sample", b"\x01\x02\xff")
    assert bin_path.read_bytes() == b"\x01\x02\xff"
    assert hex_path.read_text(encoding="utf-8").strip() == "01 02 ff"


def test_write_raw_hex_is_readable_back(tmp_path):
    bin_path, hex_path = write_raw(tmp_path, "sample", b"\xde\xad\xbe\xef")
    text = hex_path.read_text(encoding="utf-8")
    assert bytes.fromhex(text.replace(" ", "")) == bin_path.read_bytes()
```

- [ ] **Step 2: 运行测试确认失败**

Run: `python3 -m pytest tests/test_pcap.py -v`
Expected: FAIL —— `ModuleNotFoundError: No module named 'icsgen.transport.pcap'`

- [ ] **Step 3: 写最小实现**

创建 `icsgen/transport/pcap.py`：

```python
"""标准 libpcap 文件写出。

自己写文件头与包记录，不依赖 Scapy 的 pcap 写出，以便精确控制字节；
产物可被 Scapy 的 rdpcap 与 Wireshark 正常读取。
"""

from __future__ import annotations

import struct
from pathlib import Path

#: libpcap 文件头的 magic（小端）
PCAP_MAGIC = 0xA1B2C3D4
#: 链路类型：1 = Ethernet
LINKTYPE_ETHERNET = 1
#: 单包最大长度
SNAPLEN = 65535


def write_pcap(path: Path, packets: list[bytes], *, link_type: int = LINKTYPE_ETHERNET) -> None:
    """把若干链路字节写成 pcap 文件。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        fh.write(
            struct.pack(
                "<IHHiIII",
                PCAP_MAGIC,
                2,
                4,
                0,
                0,
                SNAPLEN,
                link_type,
            )
        )
        for packet in packets:
            fh.write(struct.pack("<IIII", 0, 0, len(packet), len(packet)))
            fh.write(packet)
```

创建 `icsgen/emit/__init__.py`（空文件）。

创建 `icsgen/emit/raw.py`：

```python
"""原始协议帧导出。

.bin 为纯协议字节，.hex 为其空格分隔的十六进制文本，便于在测试中直接
断言字节或人工粘贴到其他工具中。
"""

from __future__ import annotations

from pathlib import Path


def write_raw(directory: Path, name: str, payload: bytes) -> tuple[Path, Path]:
    """写出 .bin 与 .hex 两个文件，返回它们的路径。"""
    directory.mkdir(parents=True, exist_ok=True)
    bin_path = directory / f"{name}.bin"
    hex_path = directory / f"{name}.hex"
    bin_path.write_bytes(payload)
    hex_path.write_text(payload.hex(" "), encoding="utf-8")
    return bin_path, hex_path
```

- [ ] **Step 4: 运行测试确认通过**

Run: `python3 -m pytest tests/test_pcap.py -v`
Expected: PASS —— 4 passed

- [ ] **Step 5: 提交**

```bash
git add icsgen/transport/pcap.py icsgen/emit/ tests/test_pcap.py
git commit -m "$(cat <<'EOF'
feat: pcap 写出与原始字节导出

自写 libpcap 文件头与包记录以精确控制字节；.bin 存纯协议帧，
.hex 为空格分隔十六进制文本。

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: 分层数据集与 manifest

**Files:**
- Create: `icsgen/emit/dataset.py`
- Create: `tests/test_emit_dataset.py`

**Interfaces:**
- Consumes: `icsgen.emit.raw.write_raw`（Task 8）、`icsgen.transport.pcap.write_pcap`（Task 8）
- Produces:
  - `icsgen.emit.dataset.Artifact`：`frozen dataclass`，字段 `id: str`、`protocol: str`、`transport: str`、`op: str`、`variant: str`、`tier: str`、`payload: bytes`、`response: bytes | None = None`、`metadata: dict[str, Any] = {}`、`parent_id: str | None = None`、`mutation: dict[str, Any] | None = None` —— 一次操作 = 一个 Artifact，请求与响应都挂在同一条记录上（spec §11.1）
  - `icsgen.emit.dataset.DatasetBuilder`：`__init__(self, name: str, root: Path)`；方法 `add(artifact: Artifact) -> None`、`add_linked_packets(artifact_id: str, packets: list[bytes]) -> None`、`write() -> Path`
  - `icsgen.emit.dataset.write_dataset(name: str, root: Path, artifacts: list[Artifact], packets: dict[str, list[bytes]], positions: dict[str, tuple[str, int]] | None = None, response_positions: dict[str, tuple[str, int]] | None = None) -> Path`

**请求与响应**：一次操作产出一帧请求与一帧响应，二者在 pcap 里连续（spec §11.1「请求+响应连续」）。
`add_linked_packets` 接受一组包：首个是请求（记为 `pcap_index`），次个是响应（记为 `pcap_resp_index`）。
响应字节另存为 `<id>.resp.bin` / `<id>.resp.hex`，manifest 记 `resp_len` / `resp_sha256`。

**数据集布局**（tier 与 transport 分目录，pcap 按 (tier, transport) 聚合）：

```
datasets/<name>/
├── manifest.json
├── legit/modbus_tcp/
│   ├── session.pcap
│   └── frames/
│       ├── <op>#<n>.bin|.hex        # 请求帧
│       └── <op>#<n>.resp.bin|.hex   # 响应帧
└── abnormal/modbus_tcp/...
```

- [ ] **Step 1: 写失败的测试**

创建 `tests/test_emit_dataset.py`：

```python
"""分层数据集组装与 manifest。"""

import json

from icsgen.emit.dataset import Artifact, DatasetBuilder, write_dataset
from icsgen.transport.link import encapsulate
from icsgen.transport.spec import TransportSpec


def _artifact(op="modbus.read_holding_registers", tier="legit", payload=b"\x01\x02"):
    return Artifact(
        id=f"{op}#001",
        protocol="modbus",
        transport="tcp",
        op=op,
        variant="normal",
        tier=tier,
        payload=payload,
        metadata={"fc": 3},
    )


def test_write_dataset_creates_tier_directories(tmp_path):
    root = tmp_path / "ds"
    write_dataset("demo", root, [_artifact()], {})
    assert (root / "legit" / "modbus_tcp" / "frames" / "modbus.read_holding_registers#001.bin").exists()


def test_write_dataset_writes_manifest(tmp_path):
    root = tmp_path / "ds"
    write_dataset("demo", root, [_artifact()], {})
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["dataset"] == "demo"
    assert manifest["counts"]["legit"] == 1
    assert manifest["artifacts"][0]["op"] == "modbus.read_holding_registers"
    assert manifest["artifacts"][0]["sha256"]
    assert manifest["artifacts"][0]["len"] == 2


def test_write_dataset_separates_tiers(tmp_path):
    root = tmp_path / "ds"
    write_dataset(
        "demo",
        root,
        [_artifact(tier="legit"), _artifact(op="modbus.write_coil", tier="abnormal")],
        {},
    )
    assert (root / "legit" / "modbus_tcp").is_dir()
    assert (root / "abnormal" / "modbus_tcp").is_dir()


def test_pcap_is_grouped_by_tier_and_transport(tmp_path):
    root = tmp_path / "ds"
    packet = encapsulate(b"\x01", TransportSpec())
    write_dataset(
        "demo",
        root,
        [_artifact(tier="legit"), _artifact(op="x.y", tier="abnormal")],
        {"legit/modbus_tcp": [packet], "abnormal/modbus_tcp": [packet]},
    )
    assert (root / "legit" / "modbus_tcp" / "session.pcap").exists()
    assert (root / "abnormal" / "modbus_tcp" / "session.pcap").exists()


def test_manifest_records_pcap_position(tmp_path):
    root = tmp_path / "ds"
    write_dataset(
        "demo",
        root,
        [_artifact()],
        {"legit/modbus_tcp": [encapsulate(b"\x01", TransportSpec())]},
    )
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    entry = manifest["artifacts"][0]
    assert entry["pcap_file"] == "legit/modbus_tcp/session.pcap"
    assert entry["pcap_index"] == 0


def test_pcap_index_differs_within_one_session(tmp_path):
    """同一会话中的多条产物应有各自的包序号。"""
    builder = DatasetBuilder("demo", tmp_path / "ds")
    for index, op in enumerate(["modbus.read_coils", "modbus.write_coil", "modbus.read_hold"]):
        artifact_id = f"{op}#{index + 1:03d}"
        builder.add(
            Artifact(
                id=artifact_id,
                protocol="modbus",
                transport="tcp",
                op=op,
                variant="normal",
                tier="legit",
                payload=bytes([index]),
            )
        )
        builder.add_linked_packets(artifact_id, [encapsulate(b"\x01", TransportSpec())])
    root = builder.write()
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    indexes = [entry["pcap_index"] for entry in manifest["artifacts"]]
    assert indexes == [0, 1, 2]


def test_response_frame_is_written_and_indexed(tmp_path):
    """响应帧另存为 <id>.resp.bin，并在 manifest 里记录它在会话中的位置。"""
    builder = DatasetBuilder("demo", tmp_path / "ds")
    builder.add(
        Artifact(
            id="modbus.read_holding_registers#001",
            protocol="modbus",
            transport="tcp",
            op="modbus.read_holding_registers",
            variant="normal",
            tier="legit",
            payload=b"\x01\x03",
            response=b"\x01\x03\x06\x00",
        )
    )
    builder.add_linked_packets(
        "modbus.read_holding_registers#001",
        [encapsulate(b"\x01\x03", TransportSpec()), encapsulate(b"\x01\x03\x06\x00", TransportSpec().reversed())],
    )
    root = builder.write()
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    entry = manifest["artifacts"][0]
    assert entry["resp_len"] == 4
    assert entry["resp_sha256"]
    assert entry["pcap_index"] == 0
    assert entry["pcap_resp_index"] == 1
    frames = root / "legit" / "modbus_tcp" / "frames"
    assert (frames / "modbus.read_holding_registers#001.resp.bin").read_bytes() == b"\x01\x03\x06\x00"


def test_builder_collects_artifacts(tmp_path):
    builder = DatasetBuilder("demo", tmp_path / "ds")
    builder.add(_artifact())
    builder.add_linked_packets("modbus.read_holding_registers#001", [encapsulate(b"\x01", TransportSpec())])
    path = builder.write()
    assert (path / "manifest.json").exists()
```

- [ ] **Step 2: 运行测试确认失败**

Run: `python3 -m pytest tests/test_emit_dataset.py -v`
Expected: FAIL —— `ModuleNotFoundError: No module named 'icsgen.emit.dataset'`

- [ ] **Step 3: 写最小实现**

创建 `icsgen/emit/dataset.py`：

```python
"""分层数据集的组装与 manifest 生成。

产物按 tier（legit/abnormal/mutated）与 transport 双层分目录，
pcap 按 (tier, transport) 聚合为一个文件，保持会话内请求/响应连续。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..transport.pcap import write_pcap
from .raw import write_raw


@dataclass(frozen=True)
class Artifact:
    """一条产物记录。

    一次操作 = 一个 Artifact：请求与响应都挂在同一条记录上，
    response 为 None 表示这次操作不应有响应（如畸形帧）。
    """

    id: str
    protocol: str
    transport: str
    op: str
    variant: str
    tier: str
    payload: bytes
    response: bytes | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    parent_id: str | None = None
    mutation: dict[str, Any] | None = None


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class DatasetBuilder:
    """收集产物并写出分层数据集。"""

    def __init__(self, name: str, root: Path) -> None:
        self.name = name
        self.root = root
        self.artifacts: list[Artifact] = []
        self._packets: dict[str, list[bytes]] = {}
        self._positions: dict[str, tuple[str, int]] = {}
        self._response_positions: dict[str, tuple[str, int]] = {}

    def add(self, artifact: Artifact) -> None:
        """登记一条产物。"""
        self.artifacts.append(artifact)

    def add_linked_packets(self, artifact_id: str, packets: list[bytes]) -> None:
        """把链路字节挂到它所属的 (tier, transport) 会话中。

        artifact_id 形如 ``<op>#<n>``，需与已登记的产物 id 对应。
        一次操作在会话里是连续的请求与响应，因此这里接受一组包：首个是
        请求，次个是响应。挂载时即记录各自在会话中的包序号，供 manifest 索引。
        """
        artifact = next((a for a in self.artifacts if a.id == artifact_id), None)
        if artifact is None:
            raise KeyError(f"未登记的产物 id：{artifact_id!r}")
        if not packets:
            raise ValueError(f"产物 {artifact_id!r} 至少要挂一个包")
        key = f"{artifact.tier}/{artifact.protocol}_{artifact.transport}"
        session = self._packets.setdefault(key, [])
        for offset, packet in enumerate(packets):
            index = len(session)
            session.append(packet)
            if offset == 0:
                self._positions[artifact_id] = (key, index)
            elif offset == 1:
                self._response_positions[artifact_id] = (key, index)

    def write(self) -> Path:
        """写出数据集目录，返回根路径。"""
        return write_dataset(
            self.name,
            self.root,
            self.artifacts,
            self._packets,
            self._positions,
            self._response_positions,
        )


def write_dataset(
    name: str,
    root: Path,
    artifacts: list[Artifact],
    packets: dict[str, list[bytes]],
    positions: dict[str, tuple[str, int]] | None = None,
    response_positions: dict[str, tuple[str, int]] | None = None,
) -> Path:
    """写出分层数据集与 manifest.json。

    positions 为「产物 id → (会话键, 包序号)」，response_positions 为响应
    帧的同类记录，由 DatasetBuilder 在挂载链路字节时记录，用于在 manifest
    中精确定位每条产物所在的请求包与响应包。
    """
    root.mkdir(parents=True, exist_ok=True)
    positions = positions or {}
    response_positions = response_positions or {}

    counts: dict[str, int] = {}
    entries: list[dict[str, Any]] = []

    for artifact in artifacts:
        tier_dir = root / artifact.tier / f"{artifact.protocol}_{artifact.transport}"
        frames_dir = tier_dir / "frames"
        write_raw(frames_dir, artifact.id, artifact.payload)

        counts[artifact.tier] = counts.get(artifact.tier, 0) + 1
        entry: dict[str, Any] = {
            "id": artifact.id,
            "protocol": artifact.protocol,
            "transport": artifact.transport,
            "op": artifact.op,
            "variant": artifact.variant,
            "tier": artifact.tier,
            "len": len(artifact.payload),
            "sha256": _sha256(artifact.payload),
            "meta": artifact.metadata,
        }
        position = positions.get(artifact.id)
        if position is not None:
            key, index = position
            entry["pcap_file"] = f"{key}/session.pcap"
            entry["pcap_index"] = index
        if artifact.response is not None:
            write_raw(frames_dir, f"{artifact.id}.resp", artifact.response)
            entry["resp_len"] = len(artifact.response)
            entry["resp_sha256"] = _sha256(artifact.response)
        response_position = response_positions.get(artifact.id)
        if response_position is not None:
            _, index = response_position
            entry["pcap_resp_index"] = index
        if artifact.parent_id is not None:
            entry["parent_id"] = artifact.parent_id
        if artifact.mutation is not None:
            entry["mutation"] = artifact.mutation
        entries.append(entry)

    for key, plist in packets.items():
        tier, transport_dir = key.split("/", 1)
        write_pcap(root / tier / transport_dir / "session.pcap", plist)

    manifest = {
        "dataset": name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "artifacts": entries,
    }
    (root / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return root
```

- [ ] **Step 4: 运行测试确认通过**

Run: `python3 -m pytest tests/test_emit_dataset.py -v`
Expected: PASS —— 7 passed

- [ ] **Step 5: 提交**

```bash
git add icsgen/emit/dataset.py tests/test_emit_dataset.py
git commit -m "$(cat <<'EOF'
feat: 分层数据集组装与 manifest

产物按 tier 与 transport 双层分目录，pcap 按 (tier, transport) 聚合；
manifest 记录每条产物的 sha256、长度、语义元数据与 pcap 位置。

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: 变异引擎

**Files:**
- Create: `icsgen/mutate/__init__.py`
- Create: `icsgen/mutate/rules.py`
- Create: `icsgen/mutate/engine.py`
- Create: `tests/test_mutate.py`

**Interfaces:**
- Consumes: 无
- Produces:
  - `icsgen.mutate.rules.MutationRule`：`frozen dataclass`，字段 `name: str`、`description: str`、`apply: Callable[[bytes, random.Random], bytes | None]`
  - `icsgen.mutate.rules.RULES: dict[str, MutationRule]` —— 12 条规则
  - `icsgen.mutate.rules.RULE_NAMES: tuple[str, ...]`
  - `icsgen.mutate.engine.MutatedFrame`：`frozen dataclass`，字段 `payload: bytes`、`rule: str`、`seed: int`、`offset: int`、`original_sha256: str`
  - `icsgen.mutate.engine.mutate(payload: bytes, rules: list[str], seed: int) -> list[MutatedFrame]` —— 规则名为 `all` 时应用全部规则

**12 条规则**：`bit_flip`、`byte_flip`、`byte_set`、`truncate`、`extend_garbage`、`length_field_corrupt`、`func_code_corrupt`、`address_corrupt`、`value_extreme`、`crc_corrupt`、`duplicate_replay`、`interleave_frames`

其中 `duplicate_replay` 与 `interleave_frames` 需要成对输入，对单帧输入退化为 `byte_flip` 的等价行为；实现上这两条规则在只有单帧时返回 `None`（不产生变异），由引擎跳过。

- [ ] **Step 1: 写失败的测试**

创建 `tests/test_mutate.py`：

```python
"""变异引擎：规则集与确定性。"""

import pytest

from icsgen.mutate.engine import mutate
from icsgen.mutate.rules import RULE_NAMES


def test_rule_set_has_twelve_rules():
    assert len(RULE_NAMES) == 12


def test_mutate_is_deterministic_for_same_seed():
    payload = bytes(range(20))
    first = mutate(payload, ["all"], seed=42)
    second = mutate(payload, ["all"], seed=42)
    assert [m.payload for m in first] == [m.payload for m in second]


def test_mutate_differs_across_seeds():
    payload = bytes(range(20))
    first = mutate(payload, ["all"], seed=1)
    second = mutate(payload, ["all"], seed=2)
    assert [m.payload for m in first] != [m.payload for m in second]


def test_every_rule_produces_a_mutation():
    """单帧适用的每条规则都应产生变异。

    duplicate_replay 与 interleave_frames 需要成对输入，单帧时不适用，
    单独断言其返回空结果。
    """
    payload = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x03"
    paired_only = {"duplicate_replay", "interleave_frames"}
    for name in RULE_NAMES:
        results = mutate(payload, [name], seed=7)
        if name in paired_only:
            assert results == [], f"规则 {name} 在单帧输入下应返回空结果"
            continue
        assert results, f"规则 {name} 未产生任何变异"
        assert all(m.rule == name for m in results)


def test_mutation_records_original_hash():
    import hashlib

    payload = b"\x01\x02\x03"
    result = mutate(payload, ["bit_flip"], seed=1)[0]
    assert result.original_sha256 == hashlib.sha256(payload).hexdigest()


def test_truncate_shortens_payload():
    payload = bytes(range(20))
    result = mutate(payload, ["truncate"], seed=3)[0]
    assert len(result.payload) < len(payload)


def test_func_code_corrupt_changes_first_byte():
    payload = b"\x03\x00\x00\x00\x03"
    result = mutate(payload, ["func_code_corrupt"], seed=5)[0]
    assert result.payload[0] != 0x03


def test_mutated_payload_differs_from_original():
    payload = bytes(range(20))
    for result in mutate(payload, ["all"], seed=9):
        assert result.payload != payload


def test_unknown_rule_raises():
    with pytest.raises(KeyError):
        mutate(b"\x00", ["no_such_rule"], seed=1)
```

- [ ] **Step 2: 运行测试确认失败**

Run: `python3 -m pytest tests/test_mutate.py -v`
Expected: FAIL —— `ModuleNotFoundError: No module named 'icsgen.mutate'`

- [ ] **Step 3: 写最小实现**

创建 `icsgen/mutate/__init__.py`（空文件）。

创建 `icsgen/mutate/rules.py`：

```python
"""变异规则集。

每条规则接收原始字节与随机数发生器，返回变异后的字节；返回 None 表示
该规则在当前输入上不适用（例如需要成对帧的规则遇到单帧）。
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class MutationRule:
    """一条变异规则。"""

    name: str
    description: str
    apply: Callable[[bytes, random.Random], bytes | None]


def _bit_flip(data: bytes, rng: random.Random) -> bytes | None:
    if not data:
        return None
    buf = bytearray(data)
    index = rng.randrange(len(buf))
    bit = rng.randrange(8)
    buf[index] ^= 1 << bit
    return bytes(buf)


def _byte_flip(data: bytes, rng: random.Random) -> bytes | None:
    if not data:
        return None
    buf = bytearray(data)
    buf[rng.randrange(len(buf))] ^= 0xFF
    return bytes(buf)


def _byte_set(data: bytes, rng: random.Random) -> bytes | None:
    if not data:
        return None
    buf = bytearray(data)
    buf[rng.randrange(len(buf))] = rng.randrange(256)
    return bytes(buf)


def _truncate(data: bytes, rng: random.Random) -> bytes | None:
    if len(data) < 2:
        return None
    return data[: rng.randrange(1, len(data))]


def _extend_garbage(data: bytes, rng: random.Random) -> bytes | None:
    extra = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 16)))
    return data + extra


def _length_field_corrupt(data: bytes, rng: random.Random) -> bytes | None:
    """篡改 Modbus MBAP 头的长度字段（第 4-5 字节）。"""
    if len(data) < 6:
        return None
    buf = bytearray(data)
    buf[4] = rng.randrange(256)
    buf[5] = rng.randrange(256)
    return bytes(buf)


def _func_code_corrupt(data: bytes, rng: random.Random) -> bytes | None:
    """篡改功能码字节。"""
    if not data:
        return None
    buf = bytearray(data)
    buf[0] = rng.randrange(1, 256)
    return bytes(buf)


def _address_corrupt(data: bytes, rng: random.Random) -> bytes | None:
    """篡改地址字段（第 2-3 字节）。"""
    if len(data) < 4:
        return None
    buf = bytearray(data)
    buf[2] = rng.randrange(256)
    buf[3] = rng.randrange(256)
    return bytes(buf)


def _value_extreme(data: bytes, rng: random.Random) -> bytes | None:
    """把某字节置为极值。"""
    if not data:
        return None
    buf = bytearray(data)
    buf[rng.randrange(len(buf))] = rng.choice([0x00, 0xFF, 0x7F, 0x80])
    return bytes(buf)


def _crc_corrupt(data: bytes, rng: random.Random) -> bytes | None:
    """破坏尾部 CRC 字节。"""
    if len(data) < 3:
        return None
    buf = bytearray(data)
    buf[-1] ^= 0xFF
    return bytes(buf)


def _duplicate_replay(data: bytes, rng: random.Random) -> bytes | None:
    """复制整帧形成重放，需要成对输入，单帧时不适用。"""
    return None


def _interleave_frames(data: bytes, rng: random.Random) -> bytes | None:
    """交错两帧，需要成对输入，单帧时不适用。"""
    return None


RULES: dict[str, MutationRule] = {
    rule.name: rule
    for rule in (
        MutationRule("bit_flip", "翻转随机 bit", _bit_flip),
        MutationRule("byte_flip", "随机字节取反", _byte_flip),
        MutationRule("byte_set", "随机字节替换为随机值", _byte_set),
        MutationRule("truncate", "截断到随机长度", _truncate),
        MutationRule("extend_garbage", "追加随机垃圾字节", _extend_garbage),
        MutationRule("length_field_corrupt", "篡改长度字段", _length_field_corrupt),
        MutationRule("func_code_corrupt", "篡改功能码", _func_code_corrupt),
        MutationRule("address_corrupt", "篡改地址字段", _address_corrupt),
        MutationRule("value_extreme", "数值置为极值", _value_extreme),
        MutationRule("crc_corrupt", "破坏 CRC 字节", _crc_corrupt),
        MutationRule("duplicate_replay", "复制帧形成重放", _duplicate_replay),
        MutationRule("interleave_frames", "交错两帧", _interleave_frames),
    )
}

#: 全部规则名，按定义顺序
RULE_NAMES: tuple[str, ...] = tuple(RULES)
```

创建 `icsgen/mutate/engine.py`：

```python
"""变异引擎：对合法报文做确定性变异。

同一 seed 与同一输入必得同一输出，产物带溯源信息（规则名、seed、偏移、
原始哈希）。
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass

from .rules import RULES, RULE_NAMES


@dataclass(frozen=True)
class MutatedFrame:
    """一条变异产物。"""

    payload: bytes
    rule: str
    seed: int
    offset: int
    original_sha256: str


def mutate(payload: bytes, rules: list[str], seed: int) -> list[MutatedFrame]:
    """对 payload 应用给定规则，返回全部变异结果。

    rules 中的 "all" 表示应用全部规则。规则名未知时抛 KeyError。
    """
    selected = list(RULE_NAMES) if "all" in rules else list(rules)
    for name in selected:
        if name not in RULES:
            raise KeyError(f"不存在变异规则 {name!r}，可用规则：{list(RULE_NAMES)}")

    original_hash = hashlib.sha256(payload).hexdigest()
    results: list[MutatedFrame] = []

    for name in selected:
        rule = RULES[name]
        rng = random.Random(f"{seed}:{name}")
        mutated = rule.apply(payload, rng)
        if mutated is None or mutated == payload:
            continue
        offset = _first_difference(payload, mutated)
        results.append(
            MutatedFrame(
                payload=mutated,
                rule=name,
                seed=seed,
                offset=offset,
                original_sha256=original_hash,
            )
        )
    return results


def _first_difference(original: bytes, mutated: bytes) -> int:
    """返回第一个不同的字节偏移，全同则为 0。"""
    for index, (a, b) in enumerate(zip(original, mutated)):
        if a != b:
            return index
    return min(len(original), len(mutated))
```

- [ ] **Step 4: 运行测试确认通过**

Run: `python3 -m pytest tests/test_mutate.py -v`
Expected: PASS —— 8 passed

- [ ] **Step 5: 提交**

```bash
git add icsgen/mutate/ tests/test_mutate.py
git commit -m "$(cat <<'EOF'
feat: 确定性变异引擎

12 条规则，按 seed 派生每条规则的独立随机流，同 seed 同输入必得同输出。
产物记录规则名、seed、首个差异偏移与原始哈希用于溯源。

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 11: Modbus 适配器与生成流水线

**Files:**
- Create: `icsgen/protocols/base.py`
- Create: `icsgen/protocols/modbus/adapter.py`
- Create: `icsgen/generator.py`
- Create: `tests/test_generator.py`
- Modify: `icsgen/spec/catalog.py`（修正 `OperationEntry.params` 的 docstring —— catalog 的 `default` 是参数的权威缺省值，场景显式给出的值优先；布局里 `Field.default` 是更靠后的兜底）

**Interfaces:**
- Consumes: `icsgen.protocols.modbus.layouts.get_layout`（Task 4）、`icsgen.protocols.modbus.variants.plan_variant`（Task 5）、`icsgen.protocols.modbus.framing`（Task 6）、`icsgen.transport.link.encapsulate`（Task 7）、`icsgen.emit.dataset.Artifact`/`DatasetBuilder`（Task 9）
- Produces:
  - `icsgen.protocols.base.ProtocolFrame`：`frozen dataclass`，字段 `payload: bytes`、`metadata: dict[str, Any] = {}`
  - `icsgen.protocols.base.BuildContext`：`frozen dataclass`，字段 `transaction_id: int = 0`、`unit_id: int = 0xFF`、`transport: str = "tcp"`、`seed: int = 0`
  - `icsgen.protocols.base.OperationSpec`：`frozen dataclass`，字段 `name: str`、`summary: str`、`layout: str`、`variants: tuple[str, ...]`、`params_schema: dict[str, Any]`（无 `tier` 字段 —— tier 由变体推导）
  - `icsgen.protocols.base.ProtocolAdapter`：`Protocol`，字段 `name: str`、`operations: Mapping[str, OperationSpec]`，方法 `build(op: Operation, ctx: BuildContext) -> ProtocolFrame`、`build_response(op: Operation, ctx: BuildContext) -> ProtocolFrame | None`
  - `icsgen.protocols.modbus.adapter.ModbusAdapter`：`__init__(self, catalog: Catalog)`；实现 `build` 与 `build_response`
  - `icsgen.protocols.modbus.adapter.load_modbus_adapter() -> ModbusAdapter`
  - `icsgen.generator.build_dataset(scenario: Scenario, adapter: ProtocolAdapter, root: Path, name: str) -> Path`

- [ ] **Step 1: 写失败的测试**

创建 `tests/test_generator.py`：

```python
"""Modbus 适配器与生成流水线。"""

import json
from pathlib import Path

from icsgen.generator import build_dataset
from icsgen.protocols.modbus.adapter import load_modbus_adapter
from icsgen.spec.catalog import load_catalog
from icsgen.spec.loader import load_scenario
from icsgen.spec.model import Scenario, Tier, Variant

CATALOG_PATH = Path(__file__).resolve().parents[1] / "icsgen" / "protocols" / "modbus" / "catalog.yaml"


def _catalog():
    return load_catalog(CATALOG_PATH)


def test_adapter_exposes_catalog_entries():
    adapter = load_modbus_adapter()
    catalog = _catalog()
    assert adapter.name == "modbus"
    assert set(adapter.operations) == set(catalog.operations)


def test_build_request_frame_starts_with_mbap():
    from icsgen.protocols.base import BuildContext
    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    op = Operation(op="modbus.read_holding_registers", params={"start_addr": 0, "quantity": 3})
    frame = adapter.build(op, BuildContext(transaction_id=1, unit_id=0xFF))
    assert frame.payload[:7] == b"\x00\x01\x00\x00\x00\x06\xff"
    assert frame.payload[7] == 0x03
    assert frame.metadata["fc"] == 3


def test_build_exception_variant_marks_metadata():
    from icsgen.protocols.base import BuildContext
    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    op = Operation(
        op="modbus.read_holding_registers",
        params={"quantity": 3},
        variant=Variant.EXCEPTION,
    )
    frame = adapter.build(op, BuildContext())
    assert frame.metadata["is_exception"] is True
    assert frame.metadata["exception_code"] == 2


def test_build_rtu_variant_produces_crc():
    from icsgen.protocols.base import BuildContext
    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    op = Operation(op="modbus.read_holding_registers", params={"quantity": 3})
    frame = adapter.build(op, BuildContext(transport="rtu"))
    assert frame.metadata["transport"] == "rtu"
    from icsgen.protocols.modbus.framing import parse_rtu

    parsed = parse_rtu(frame.payload)
    assert parsed["pdu"][0] == 0x03


def test_build_dataset_writes_manifest_and_frames(tmp_path):
    adapter = load_modbus_adapter()
    scenario = Scenario(
        name="demo",
        transport={"kind": "tcp"},
        operations=(),
    )
    from icsgen.spec.model import Operation

    scenario = Scenario(
        name="demo",
        transport={"kind": "tcp"},
        operations=(
            Operation(op="modbus.read_holding_registers", params={"quantity": 3}),
            Operation(op="modbus.write_multiple_registers", params={"quantity": 2}),
        ),
    )
    root = build_dataset(scenario, adapter, tmp_path / "ds", name="demo")
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["counts"]["legit"] == 2
    assert len(manifest["artifacts"]) == 2
    assert (root / "legit" / "modbus_tcp" / "frames").is_dir()


def test_build_dataset_separates_abnormal_tier(tmp_path):
    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    scenario = Scenario(
        name="demo",
        transport={"kind": "tcp"},
        operations=(
            Operation(op="modbus.read_holding_registers", params={"quantity": 3}),
            Operation(
                op="modbus.read_holding_registers",
                params={"quantity": 3},
                variant=Variant.EXCEPTION,
            ),
        ),
    )
    root = build_dataset(scenario, adapter, tmp_path / "ds", name="demo")
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["counts"]["legit"] == 1
    assert manifest["counts"]["abnormal"] == 1
    assert (root / "abnormal" / "modbus_tcp" / "frames").is_dir()


def test_build_response_returns_normal_response():
    """正常变体的响应是 FC03 的正常响应：byte_count + 寄存器数据。"""
    from icsgen.protocols.base import BuildContext
    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    op = Operation(op="modbus.read_holding_registers", params={"start_addr": 0, "quantity": 3})
    frame = adapter.build_response(op, BuildContext(transaction_id=1, unit_id=0xFF))
    assert frame is not None
    assert frame.payload[:7] == b"\x00\x01\x00\x00\x00\x09\xff"
    assert frame.payload[7] == 0x03
    assert frame.payload[8] == 6


def test_build_response_returns_exception_response():
    """异常变体的响应是 FC|0x80 + 异常码。"""
    from icsgen.protocols.base import BuildContext
    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    op = Operation(
        op="modbus.read_holding_registers",
        params={"quantity": 3},
        variant=Variant.EXCEPTION,
    )
    frame = adapter.build_response(op, BuildContext(transaction_id=1, unit_id=0xFF))
    assert frame is not None
    assert frame.payload[7] == 0x83
    assert frame.payload[8] == 0x02


def test_malformed_variant_has_no_response():
    """畸形帧没有可解析的响应。"""
    from icsgen.protocols.base import BuildContext
    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    op = Operation(
        op="modbus.read_holding_registers",
        params={"quantity": 3},
        variant=Variant.MALFORMED,
    )
    assert adapter.build_response(op, BuildContext()) is None


def test_dataset_pairs_request_and_response(tmp_path):
    """一次操作在 pcap 里是连续的请求与响应两包。"""
    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    scenario = Scenario(
        name="demo",
        transport={"kind": "tcp"},
        operations=(Operation(op="modbus.read_holding_registers", params={"quantity": 3}),),
    )
    root = build_dataset(scenario, adapter, tmp_path / "ds", name="demo")
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    entry = manifest["artifacts"][0]
    assert entry["pcap_index"] == 0
    assert entry["pcap_resp_index"] == 1
    assert entry["resp_len"] > 0
    frames = root / "legit" / "modbus_tcp" / "frames"
    assert (frames / f"{entry['id']}.resp.bin").exists()
```

- [ ] **Step 2: 运行测试确认失败**

Run: `python3 -m pytest tests/test_generator.py -v`
Expected: FAIL —— `ModuleNotFoundError: No module named 'icsgen.protocols.base'`

- [ ] **Step 3: 写最小实现**

创建 `icsgen/protocols/base.py`：

```python
"""协议适配器的公共契约。

适配器只负责协议层的语义 —— 由 catalog 声明的操作与字段布局如何变成
协议帧。它不涉及 IP/TCP/以太等链路封装。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol

from ..spec.model import Operation


@dataclass(frozen=True)
class BuildContext:
    """构建协议帧时的会话级上下文。"""

    transaction_id: int = 0
    unit_id: int = 0xFF
    transport: str = "tcp"
    seed: int = 0


@dataclass(frozen=True)
class ProtocolFrame:
    """一条协议帧及其语义元数据。"""

    payload: bytes
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OperationSpec:
    """一个操作类型在适配器侧的描述。"""

    name: str
    summary: str
    layout: str
    variants: tuple[str, ...]
    params_schema: dict[str, Any]


class ProtocolAdapter(Protocol):
    """协议适配器契约。"""

    name: str
    operations: Mapping[str, OperationSpec]

    def build(self, op: Operation, ctx: BuildContext) -> ProtocolFrame: ...

    def build_response(self, op: Operation, ctx: BuildContext) -> ProtocolFrame | None: ...
```

创建 `icsgen/protocols/modbus/adapter.py`：

```python
"""Modbus 协议适配器。

按 catalog 声明的布局与变体语义把一次操作变成协议帧：
TCP 用 MBAP 组帧，RTU 用地址 + PDU + CRC 组帧。
一次操作产出请求与响应两帧，响应由服务端发往客户端。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ...codec.encoder import encode
from ...codec.fields import Layout
from ...spec.catalog import Catalog, OperationEntry, load_catalog
from ...spec.model import Operation, Variant
from ..base import BuildContext, OperationSpec, ProtocolFrame
from . import framing
from .layouts import get_layout
from .variants import DEFAULT_EXCEPTION_CODE, VariantPlan, plan_variant

#: catalog 文件位置
CATALOG_PATH = Path(__file__).resolve().parent / "catalog.yaml"


class ModbusAdapter:
    """Modbus 协议适配器。"""

    name = "modbus"

    def __init__(self, catalog: Catalog) -> None:
        self.catalog = catalog
        self.operations = {
            name: OperationSpec(
                name=name,
                summary=entry.summary,
                layout=entry.layout,
                variants=tuple(entry.variants),
                params_schema=entry.params,
            )
            for name, entry in catalog.operations.items()
        }

    def build(self, op: Operation, ctx: BuildContext) -> ProtocolFrame:
        """把一次操作构建成请求帧。"""
        layout, plan = self._plan(op)
        request_pdu = framing.build_pdu(
            plan.func_code,
            encode(layout.request, plan.request_values),
        )
        metadata: dict[str, Any] = {
            "fc": plan.func_code,
            "unit_id": ctx.unit_id,
            "transport": ctx.transport,
            "is_exception": plan.is_exception,
        }
        metadata.update(plan.metadata)

        return ProtocolFrame(payload=self._frame(request_pdu, ctx), metadata=metadata)

    def build_response(self, op: Operation, ctx: BuildContext) -> ProtocolFrame | None:
        """把一次操作构建成响应帧。

        异常变体按 Modbus 规范回异常响应（功能码 | 0x80 + 异常码）；
        畸形帧没有可解析的响应，返回 None。
        """
        layout, plan = self._plan(op)
        if op.variant is Variant.MALFORMED:
            return None
        if plan.is_exception:
            code = int(plan.metadata.get("exception_code", DEFAULT_EXCEPTION_CODE))
            response_pdu = bytes([plan.func_code | 0x80, code])
        else:
            response_pdu = framing.build_pdu(
                plan.func_code,
                encode(layout.response, plan.response_values),
            )
        metadata: dict[str, Any] = {
            "fc": plan.func_code,
            "unit_id": ctx.unit_id,
            "transport": ctx.transport,
        }
        return ProtocolFrame(payload=self._frame(response_pdu, ctx), metadata=metadata)

    def _plan(self, op: Operation) -> tuple[Layout, VariantPlan]:
        """解析一次操作：catalog 缺省值 + 场景参数 → 布局与取值方案。"""
        entry: OperationEntry = self.catalog.get(op.op)
        layout = get_layout(entry.layout)
        # 场景没给的参数用 catalog 声明的缺省值补齐
        defaults = {
            name: spec["default"]
            for name, spec in entry.params.items()
            if isinstance(spec, dict) and "default" in spec
        }
        # 边界变体的上界：标量参数取 maximum，数组参数取元素上界
        maxima = {
            name: int(spec["maximum"])
            for name, spec in entry.params.items()
            if isinstance(spec, dict) and "maximum" in spec
        }
        maxima.update(
            {
                name: int(spec["items"]["maximum"])
                for name, spec in entry.params.items()
                if isinstance(spec, dict)
                and spec.get("type") == "array"
                and isinstance(spec.get("items"), dict)
                and "maximum" in spec["items"]
            }
        )
        # 数组参数的元素个数上界：只顶元素值而不顶个数，帧里的计数标量
        # 会与实际内容对不上
        max_counts = {
            name: int(spec["maxItems"])
            for name, spec in entry.params.items()
            if isinstance(spec, dict)
            and spec.get("type") == "array"
            and "maxItems" in spec
        }
        func_code = entry.func_code if entry.func_code is not None else 0
        plan = plan_variant(
            layout=layout,
            op_name=op.op,
            func_code=func_code,
            params={**defaults, **op.params},
            variant=op.variant,
            maxima=maxima,
            max_counts=max_counts,
        )
        return layout, plan

    @staticmethod
    def _frame(pdu: bytes, ctx: BuildContext) -> bytes:
        """按传输方式把 PDU 组成完整帧。"""
        if ctx.transport == "rtu":
            return framing.build_rtu(ctx.unit_id, pdu)
        return framing.build_mbap(ctx.transaction_id, ctx.unit_id, pdu)


def load_modbus_adapter() -> ModbusAdapter:
    """加载内置 catalog 并构造适配器。"""
    return ModbusAdapter(load_catalog(CATALOG_PATH))
```

修改 `icsgen/spec/catalog.py` 中 `OperationEntry` 的 docstring（只改注释，不改行为）：

```python
class OperationEntry(BaseModel):
    """catalog 中的一个操作类型条目。

    params 是「参数名 -> 该参数的 JSON Schema 片段」的映射；其中的 default
    键是该参数的权威缺省值 —— 适配器在场景未显式给出该参数时用它填充，
    场景显式给出的值优先。字段布局里的 Field.default 是更靠后的兜底
    （构造响应时请求参数不可得的情况）。

    本条目不声明 tier：语义层由变体唯一决定（icsgen.spec.model.VARIANT_TIER），
    catalog 再声明一个 tier 会成为第二事实源，且对同时含合法变体与异常变体的
    操作类型必然自相矛盾。
    """
```

创建 `icsgen/generator.py`：

```python
"""生成流水线：把场景变成分层数据集。

流程：场景 → 逐条操作构建请求帧与响应帧 → 封装链路 → 登记为产物 → 写盘。
请求与响应连续进入同一会话的 pcap，保持会话内可配对。
"""

from __future__ import annotations

from pathlib import Path

from .emit.dataset import Artifact, DatasetBuilder
from .protocols.base import BuildContext, ProtocolAdapter
from .spec.model import Scenario
from .transport.link import encapsulate
from .transport.spec import TransportSpec


def _transport_spec(scenario: Scenario) -> TransportSpec:
    raw = dict(scenario.transport)
    kind = raw.pop("kind", "tcp")
    return TransportSpec(kind=kind, **raw)


def build_dataset(
    scenario: Scenario,
    adapter: ProtocolAdapter,
    root: Path,
    name: str | None = None,
) -> Path:
    """按场景生成数据集，返回数据集根路径。"""
    spec = _transport_spec(scenario)
    builder = DatasetBuilder(name or scenario.name, root)

    for index, op in enumerate(scenario.operations):
        ctx = BuildContext(
            transaction_id=index,
            unit_id=0xFF,
            transport="rtu" if spec.kind == "serial" else "tcp",
            seed=index,
        )
        frame = adapter.build(op, ctx)
        response_frame = adapter.build_response(op, ctx) if op.expect_response else None
        artifact = Artifact(
            id=f"{op.op}#{index + 1:03d}",
            protocol=adapter.name,
            transport="rtu" if spec.kind == "serial" else "tcp",
            op=op.op,
            variant=op.variant.value,
            tier=op.tier.value if op.tier is not None else "legit",
            payload=frame.payload,
            response=response_frame.payload if response_frame is not None else None,
            metadata=frame.metadata,
        )
        builder.add(artifact)
        # 请求与响应连续进入同一会话：响应由服务端发回，链路方向相反
        seq = index * 10
        packets = [encapsulate(frame.payload, spec, seq=seq, ack=seq)]
        if response_frame is not None:
            packets.append(
                encapsulate(
                    response_frame.payload,
                    spec.reversed(),
                    seq=seq + len(frame.payload),
                    ack=seq + len(frame.payload),
                )
            )
        builder.add_linked_packets(artifact.id, packets)

    return builder.write()
```

- [ ] **Step 4: 运行测试确认通过**

Run: `python3 -m pytest tests/test_generator.py -v`
Expected: PASS —— 10 passed

- [ ] **Step 5: 提交**

```bash
git add icsgen/protocols/base.py icsgen/protocols/modbus/adapter.py icsgen/generator.py icsgen/spec/catalog.py tests/test_generator.py
git commit -m "$(cat <<'EOF'
feat: Modbus 适配器与生成流水线

适配器按 catalog 布局与变体语义构建协议帧（TCP MBAP / RTU CRC），
一次操作同时产出请求帧与响应帧（异常变体回 FC|0x80 + 异常码），
流水线把场景转成分层数据集并写出成对的链路包与 manifest。

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 12: 命令行界面

**Files:**
- Create: `icsgen/cli.py`
- Create: `tests/test_cli.py`

**Interfaces:**
- Consumes: `icsgen.protocols.modbus.adapter.load_modbus_adapter`（Task 11）、`icsgen.spec.catalog.load_catalog`（Task 3）、`icsgen.spec.loader.load_scenario`（Task 3）、`icsgen.generator.build_dataset`（Task 11）、`icsgen.mutate.engine.mutate`（Task 10）
- Produces: `icsgen.cli.app` —— Typer 应用，命令行入口 `icsgen`

**命令面**：

| 命令 | 作用 |
|---|---|
| `icsgen ops list --protocol modbus [--variant V] [--json]` | 列出操作类型 |
| `icsgen ops show <op 名>` | 显示单个操作详情 |
| `icsgen validate <场景.yaml>` | 校验场景文件 |
| `icsgen generate <场景.yaml> -o <目录>` | 生成数据集 |
| `icsgen mutate <数据集目录> -o <目录> --rules all --seed N` | 生成变异数据集 |
| `icsgen serve --protocol modbus --transport tcp --port N --role client` | 启动 PLC 模拟器（Task 13 实现） |
| `icsgen catalog --protocol modbus --count` | 统计操作类型数量（CI 防退化用） |

- [ ] **Step 1: 写失败的测试**

创建 `tests/test_cli.py`：

```python
"""命令行界面。"""

import json

from typer.testing import CliRunner

from icsgen.cli import app

runner = CliRunner()


def test_catalog_count_reports_number():
    """--count 输出覆盖条目数，是 §15 丰富度指标的 CI 口径。"""
    result = runner.invoke(app, ["catalog", "--protocol", "modbus", "--count"])
    assert result.exit_code == 0, result.output
    count = int(result.stdout.strip())
    assert count >= 90


def test_ops_list_lists_operation_names():
    result = runner.invoke(app, ["ops", "list", "--protocol", "modbus"])
    assert result.exit_code == 0, result.output
    assert "modbus.read_holding_registers" in result.stdout


def test_ops_list_json_output_is_parseable():
    result = runner.invoke(app, ["ops", "list", "--protocol", "modbus", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert any(item["name"] == "modbus.read_coils" for item in data)


def test_ops_show_prints_summary():
    result = runner.invoke(app, ["ops", "show", "modbus.read_holding_registers"])
    assert result.exit_code == 0, result.output
    assert "读保持寄存器" in result.stdout


def test_validate_rejects_bad_scenario(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("name: bad\noperations:\n  - op: modbus.not_exists\n", encoding="utf-8")
    result = runner.invoke(app, ["validate", str(bad)])
    assert result.exit_code != 0
    assert "不存在操作" in result.output


def test_generate_writes_dataset(tmp_path):
    scenario = tmp_path / "s.yaml"
    scenario.write_text(
        "name: demo\ntransport:\n  kind: tcp\noperations:\n"
        "  - op: modbus.read_holding_registers\n    params: {quantity: 3}\n",
        encoding="utf-8",
    )
    out = tmp_path / "ds"
    result = runner.invoke(app, ["generate", str(scenario), "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert (out / "manifest.json").exists()


def test_mutate_creates_mutated_tier(tmp_path):
    scenario = tmp_path / "s.yaml"
    scenario.write_text(
        "name: demo\ntransport:\n  kind: tcp\noperations:\n"
        "  - op: modbus.read_holding_registers\n    params: {quantity: 3}\n",
        encoding="utf-8",
    )
    src = tmp_path / "ds"
    runner.invoke(app, ["generate", str(scenario), "-o", str(src)])
    dst = tmp_path / "fuzz"
    result = runner.invoke(
        app, ["mutate", str(src), "-o", str(dst), "--rules", "all", "--seed", "42"]
    )
    assert result.exit_code == 0, result.output
    assert (dst / "manifest.json").exists()
    manifest = json.loads((dst / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["counts"].get("mutated", 0) > 0
```

- [ ] **Step 2: 运行测试确认失败**

Run: `python3 -m pytest tests/test_cli.py -v`
Expected: FAIL —— `ModuleNotFoundError: No module named 'icsgen.cli'`

- [ ] **Step 3: 写最小实现**

创建 `icsgen/cli.py`：

```python
"""icsgen 命令行界面。

所有命令都是薄封装，核心逻辑在 icsgen 的库接口中，命令行仅负责参数
解析与结果呈现。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer

from .emit.dataset import Artifact, DatasetBuilder, write_dataset
from .generator import build_dataset
from .mutate.engine import mutate
from .protocols.modbus.adapter import CATALOG_PATH, load_modbus_adapter
from .spec.catalog import Catalog, load_catalog
from .spec.loader import ScenarioError, load_scenario

app = typer.Typer(help="ICS 工控协议流量生成器")
ops_app = typer.Typer(help="操作类型目录")
app.add_typer(ops_app, name="ops")


def _catalog_for(protocol: str) -> Catalog:
    if protocol != "modbus":
        raise typer.BadParameter(f"暂不支持协议 {protocol!r}，当前仅支持 modbus")
    return load_catalog(CATALOG_PATH)


@ops_app.command("list")
def ops_list(
    protocol: str = typer.Option("modbus", "--protocol", help="协议名"),
    variant: str = typer.Option(None, "--variant", help="只列出支持该变体的操作"),
    as_json: bool = typer.Option(False, "--json", help="以 JSON 输出"),
) -> None:
    """列出操作类型。"""
    catalog = _catalog_for(protocol)
    items: list[dict[str, Any]] = []
    for name, entry in catalog.operations.items():
        if variant is not None and variant not in entry.variants:
            continue
        items.append(
            {
                "name": name,
                "summary": entry.summary,
                "layout": entry.layout,
                "variants": entry.variants,
                "func_code": entry.func_code,
            }
        )
    if as_json:
        typer.echo(json.dumps(items, ensure_ascii=False, indent=2))
        return
    for item in items:
        typer.echo(f"{item['name']:<52} {item['summary']}")


@ops_app.command("show")
def ops_show(name: str = typer.Argument(..., help="操作名")) -> None:
    """显示单个操作类型的详情。"""
    catalog = _catalog_for("modbus")
    entry = catalog.get(name)
    typer.echo(f"名称: {entry.name}")
    typer.echo(f"说明: {entry.summary}")
    typer.echo(f"布局: {entry.layout}")
    typer.echo(f"功能码: {entry.func_code}")
    typer.echo(f"可用变体: {', '.join(entry.variants)}")
    if entry.params:
        typer.echo("参数:")
        for param, spec in entry.params.items():
            typer.echo(f"  {param}: {json.dumps(spec, ensure_ascii=False)}")


@app.command("validate")
def validate(scenario: Path = typer.Argument(..., help="场景 YAML 路径")) -> None:
    """校验场景文件。"""
    catalog = _catalog_for("modbus")
    try:
        loaded = load_scenario(scenario, catalog)
    except ScenarioError as exc:
        typer.echo(f"校验失败: {exc}", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"校验通过: {loaded.name}，共 {len(loaded.operations)} 条操作")


@app.command("generate")
def generate(
    scenario: Path = typer.Argument(..., help="场景 YAML 路径"),
    output: Path = typer.Option(..., "-o", "--output", help="数据集输出目录"),
) -> None:
    """按场景生成分层数据集。"""
    catalog = _catalog_for("modbus")
    try:
        loaded = load_scenario(scenario, catalog)
    except ScenarioError as exc:
        typer.echo(f"场景不合法: {exc}", err=True)
        raise typer.Exit(code=1)
    adapter = load_modbus_adapter()
    root = build_dataset(loaded, adapter, output, name=loaded.name)
    typer.echo(f"已生成数据集: {root}")


@app.command("mutate")
def mutate_cmd(
    dataset: Path = typer.Argument(..., help="源数据集目录"),
    output: Path = typer.Option(..., "-o", "--output", help="变异数据集输出目录"),
    rules: str = typer.Option("all", "--rules", help="逗号分隔的规则名，all 表示全部"),
    seed: int = typer.Option(0, "--seed", help="随机种子"),
) -> None:
    """对数据集做变异，产出 mutated 层。"""
    manifest_path = dataset / "manifest.json"
    if not manifest_path.exists():
        typer.echo(f"找不到 {manifest_path}", err=True)
        raise typer.Exit(code=1)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    builder = DatasetBuilder(manifest.get("dataset", dataset.name), output)
    rule_names = [r.strip() for r in rules.split(",") if r.strip()]

    for entry in manifest["artifacts"]:
        source = dataset / entry["tier"] / f"{entry['protocol']}_{entry['transport']}" / "frames" / f"{entry['id']}.bin"
        if not source.exists():
            continue
        payload = source.read_bytes()
        for mutated in mutate(payload, rule_names, seed):
            builder.add(
                Artifact(
                    id=f"{entry['id']}~{mutated.rule}",
                    protocol=entry["protocol"],
                    transport=entry["transport"],
                    op=entry["op"],
                    variant=entry["variant"],
                    tier="mutated",
                    payload=mutated.payload,
                    metadata=entry.get("meta", {}),
                    parent_id=entry["id"],
                    mutation={
                        "rule": mutated.rule,
                        "seed": mutated.seed,
                        "offset": mutated.offset,
                        "original_sha256": mutated.original_sha256,
                    },
                )
            )
    root = builder.write()
    typer.echo(f"已生成变异数据集: {root}")


@app.command("catalog")
def catalog_cmd(
    protocol: str = typer.Option("modbus", "--protocol", help="协议名"),
    count: bool = typer.Option(False, "--count", help="只输出覆盖条目数"),
) -> None:
    """查看操作目录统计。"""
    catalog = _catalog_for(protocol)
    if count:
        typer.echo(str(catalog.coverage_count()))
        return
    typer.echo(
        f"协议 {catalog.protocol}，操作类型 {catalog.count()} 个，"
        f"传输 {'/'.join(catalog.transports)}，覆盖条目 {catalog.coverage_count()} 个"
    )


@app.command("serve")
def serve(
    protocol: str = typer.Option("modbus", "--protocol", help="协议名"),
    transport: str = typer.Option("tcp", "--transport", help="tcp 或 serial"),
    host: str = typer.Option("127.0.0.1", "--host", help="监听地址"),
    port: int = typer.Option(5020, "--port", help="监听端口"),
    role: str = typer.Option("plc", "--role", help="plc 被动应答 / client 主动请求"),
) -> None:
    """启动 PLC 服务端模拟。"""
    from .server.modbus_server import run_modbus_server

    run_modbus_server(transport=transport, host=host, port=port, role=role)
```

- [ ] **Step 4: 运行测试确认通过**

Run: `python3 -m pytest tests/test_cli.py -v`
Expected: PASS —— 7 passed

- [ ] **Step 5: 提交**

```bash
git add icsgen/cli.py tests/test_cli.py
git commit -m "$(cat <<'EOF'
feat: 命令行界面

提供 ops list/show、validate、generate、mutate、catalog、serve 七组命令，
全部为库接口的薄封装，支持 --json 输出。

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 13: PLC 服务端模拟

**Files:**
- Create: `icsgen/server/__init__.py`
- Create: `icsgen/server/base.py`
- Create: `icsgen/server/modbus_server.py`
- Create: `tests/test_server.py`

**Interfaces:**
- Consumes: `icsgen.spec.model.Operation`、`icsgen.protocols.modbus.adapter.load_modbus_adapter`（Task 11）
- Produces:
  - `icsgen.server.base.PlcServer`：`Protocol`，方法 `start() -> None`、`stop() -> None`、属性 `address: str`
  - `icsgen.server.modbus_server.ModbusPlcServer`：`__init__(self, host: str = "127.0.0.1", port: int = 5020, role: str = "plc", unit_id: int = 1)`；实现 `PlcServer`
  - `icsgen.server.modbus_server.run_modbus_server(transport: str, host: str, port: int, role: str) -> None` —— 阻塞运行

**两种角色**：

- `plc`：基于 pymodbus 起被动应答的服务端，模拟真实 PLC 被读写
- `client`：主动发起一组 Modbus 请求并接收响应，产出成对的请求/响应 —— 真实流量的主要来源

pymodbus 3.16 的服务端 API：`from pymodbus.datastore import ModbusServerContext, ModbusDeviceContext, ModbusSequentialDataBlock` 与 `from pymodbus.server import ModbusTcpServer`（提供 `serve_forever()` 与 `shutdown()`，可编程启停）；客户端为 `from pymodbus.client import ModbusTcpClient`。

- [ ] **Step 1: 写失败的测试**

创建 `tests/test_server.py`：

```python
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
        result = client.read_holding_registers(0, count=4, slave=1)
        assert not result.isError()
        assert len(result.registers) == 4
        client.close()
    finally:
        server.stop()


def test_plc_server_address_is_reported():
    server = ModbusPlcServer(host="127.0.0.1", port=15021, role="plc")
    assert "15021" in server.address
```

- [ ] **Step 2: 运行测试确认失败**

Run: `python3 -m pytest tests/test_server.py -v`
Expected: FAIL —— `ModuleNotFoundError: No module named 'icsgen.server'`

- [ ] **Step 3: 写最小实现**

创建 `icsgen/server/__init__.py`（空文件）。

创建 `icsgen/server/base.py`：

```python
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
```

创建 `icsgen/server/modbus_server.py`：

```python
"""基于 pymodbus 的 Modbus PLC 服务端模拟。

plc 角色被动应答，模拟被读取的现场设备；
client 角色主动发起请求并接收响应，产出成对的请求/响应会话。
"""

from __future__ import annotations

import threading
import time
from typing import Any

from pymodbus.client import ModbusTcpClient
from pymodbus.datastore import (
    ModbusDeviceContext,
    ModbusSequentialDataBlock,
    ModbusServerContext,
)
from pymodbus.server import ModbusTcpServer

#: 模拟寄存器区的初始值
INITIAL_REGISTER_VALUE = 0

#: 保持寄存器数量
HOLDING_REGISTER_COUNT = 1000


def _build_context() -> ModbusServerContext:
    """构造 pymodbus 服务端上下文。"""
    block = ModbusSequentialDataBlock(0, [INITIAL_REGISTER_VALUE] * HOLDING_REGISTER_COUNT)
    device = ModbusDeviceContext(
        di=block,
        co=block,
        ir=block,
        hr=block,
    )
    return ModbusServerContext(devices=device, single=True)


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
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

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
        self._server = ModbusTcpServer(
            context=_build_context(),
            address=(self.host, self.port),
        )
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """停止服务。"""
        self._stop_event.set()
        if self._server is not None:
            self._server.shutdown()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None

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
            client.read_holding_registers(0, count=8, slave=self.unit_id)
            client.write_register(0, value=0x1234, slave=self.unit_id)
            client.read_input_registers(0, count=8, slave=self.unit_id)
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
```

- [ ] **Step 4: 运行测试确认通过**

Run: `python3 -m pytest tests/test_server.py -v`
Expected: PASS —— 3 passed

- [ ] **Step 5: 提交**

```bash
git add icsgen/server/ tests/test_server.py
git commit -m "$(cat <<'EOF'
feat: Modbus PLC 服务端模拟

plc 角色基于 pymodbus 被动应答，client 角色主动发起读写交互，
后者是成对请求/响应流量的来源。

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 14: 端到端集成、示例场景与文档

**Files:**
- Create: `scenarios/modbus_demo.yaml`
- Create: `tests/test_e2e.py`
- Create: `README.md`

**Interfaces:**
- Consumes: 全部前述模块（Task 1–13）
- Produces: 可运行的示例场景与项目说明文档

- [ ] **Step 1: 写失败的测试**

创建 `tests/test_e2e.py`：

```python
"""端到端：场景 → 数据集 → 校验。"""

import json
from pathlib import Path

from scapy.all import IP, rdpcap

from icsgen.generator import build_dataset
from icsgen.protocols.modbus.adapter import load_modbus_adapter
from icsgen.spec.catalog import load_catalog
from icsgen.spec.loader import load_scenario

ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "icsgen" / "protocols" / "modbus" / "catalog.yaml"
SCENARIO_PATH = ROOT / "scenarios" / "modbus_demo.yaml"


def test_demo_scenario_loads():
    catalog = load_catalog(CATALOG_PATH)
    scenario = load_scenario(SCENARIO_PATH, catalog)
    assert scenario.name == "modbus_demo"
    assert len(scenario.operations) >= 4


def test_demo_scenario_covers_both_tiers():
    catalog = load_catalog(CATALOG_PATH)
    scenario = load_scenario(SCENARIO_PATH, catalog)
    tiers = {op.tier.value for op in scenario.operations}
    assert "legit" in tiers
    assert "abnormal" in tiers


def test_end_to_end_dataset_is_consistent(tmp_path):
    catalog = load_catalog(CATALOG_PATH)
    scenario = load_scenario(SCENARIO_PATH, catalog)
    adapter = load_modbus_adapter()
    root = build_dataset(scenario, adapter, tmp_path / "ds", name=scenario.name)

    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["counts"]["legit"] >= 2
    assert manifest["counts"]["abnormal"] >= 1

    for entry in manifest["artifacts"]:
        frame = root / entry["tier"] / f"{entry['protocol']}_{entry['transport']}" / "frames" / f"{entry['id']}.bin"
        assert frame.exists(), f"缺少帧文件 {frame}"
        assert frame.stat().st_size == entry["len"]


def test_generated_pcap_is_parseable(tmp_path):
    catalog = load_catalog(CATALOG_PATH)
    scenario = load_scenario(SCENARIO_PATH, catalog)
    adapter = load_modbus_adapter()
    root = build_dataset(scenario, adapter, tmp_path / "ds", name=scenario.name)

    pcap = root / "legit" / "modbus_tcp" / "session.pcap"
    assert pcap.exists()
    packets = rdpcap(str(pcap))
    assert len(packets) >= 2
    # 请求与响应方向相反：响应由服务端发回客户端
    assert packets[0][IP].src == packets[1][IP].dst
    assert packets[0][IP].dst == packets[1][IP].src


def test_session_pairs_requests_with_responses(tmp_path):
    """一次操作在会话里是连续的请求与响应两包，响应帧也单独落盘。"""
    catalog = load_catalog(CATALOG_PATH)
    scenario = load_scenario(SCENARIO_PATH, catalog)
    adapter = load_modbus_adapter()
    root = build_dataset(scenario, adapter, tmp_path / "ds", name=scenario.name)

    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    # 示例场景里没有畸形帧，每条操作都有响应
    for entry in manifest["artifacts"]:
        assert entry["pcap_resp_index"] == entry["pcap_index"] + 1
        assert entry["resp_len"] > 0
        frames = root / entry["tier"] / f"{entry['protocol']}_{entry['transport']}" / "frames"
        assert (frames / f"{entry['id']}.resp.bin").exists()


def test_operation_type_count_meets_floor():
    """覆盖条目数不得低于下限（CI 防退化）。"""
    catalog = load_catalog(CATALOG_PATH)
    assert catalog.coverage_count() >= 90, f"覆盖条目数 {catalog.coverage_count()} 低于下限 90"
```

- [ ] **Step 2: 运行测试确认失败**

Run: `python3 -m pytest tests/test_e2e.py -v`
Expected: FAIL —— `FileNotFoundError: scenarios/modbus_demo.yaml`

- [ ] **Step 3: 写最小实现**

创建 `scenarios/modbus_demo.yaml`：

```yaml
name: modbus_demo
description: Modbus 读写混合演示场景，覆盖合法、边界与异常语义
transport:
  kind: tcp
  src_ip: 192.168.1.10
  dst_ip: 192.168.1.20
  dport: 502
operations:
  # 合法读
  - op: modbus.read_holding_registers
    params: {start_addr: 0, quantity: 3}
    variant: normal
  # 合法写
  - op: modbus.write_multiple_registers
    params: {start_addr: 100, quantity: 2, values: [57005, 48879]}
    variant: normal
  # 合法读回
  - op: modbus.read_holding_registers
    params: {start_addr: 100, quantity: 2}
    variant: normal
  # 边界：数量取上界
  - op: modbus.read_holding_registers
    params: {start_addr: 0, quantity: 125}
    variant: boundary
  # 异常：协议异常响应
  - op: modbus.read_holding_registers
    params: {start_addr: 0, quantity: 3}
    variant: exception
  # 异常：非法功能码（功能码取 catalog 条目声明的保留值 99）
  - op: modbus.illegal_function_code
    params: {quantity: 1}
    variant: illegal_fc
```

创建 `README.md`：

````markdown
# icsgen —— ICS 工控协议流量生成器

用开源工控模拟工具生成多协议的操作流量数据包，用于协议开发验证与测试。

## 安装

```bash
python -m pip install -e ".[dev]"
```

## 快速开始

```bash
# 校验场景
icsgen validate scenarios/modbus_demo.yaml

# 生成数据集（pcap + bin + hex + manifest）
icsgen generate scenarios/modbus_demo.yaml -o datasets/demo

# 生成变异数据集
icsgen mutate datasets/demo -o datasets/fuzz --rules all --seed 42

# 查看操作类型目录
icsgen catalog --protocol modbus --count
icsgen ops list --protocol modbus
```

## 产物布局

```
datasets/demo/
├── manifest.json              # 每条产物的 sha256、长度、语义元数据与 pcap 位置
├── legit/modbus_tcp/
│   ├── session.pcap           # 该层下的完整会话，可直接用 Wireshark 打开
│   └── frames/<op>#<n>.bin   # 请求帧（纯协议帧，不含 IP/TCP 头）
│   └── frames/<op>#<n>.hex   # 同上，空格分隔十六进制
│   └── frames/<op>#<n>.resp.bin  # 响应帧
├── abnormal/modbus_tcp/...
└── mutated/modbus_tcp/...     # 带 parent_id 与 mutation 溯源
```

- **`.bin` 是纯协议帧**，不含 IP/TCP 头，便于单元测试逐字节断言。
- **`.pcap` 是完整链路帧**，请求与响应成对连续，保留会话连贯性，便于人工分析与规则引擎回放。
- **一次操作 = 一个 Artifact**：请求与响应同属一条记录，manifest 记 `pcap_index` 与 `pcap_resp_index`。
- **`legit` / `abnormal` / `mutated` 三层互不污染**，manifest 记录每条产物的 tier。

## 语义层与变体

同一操作的不同语义形态用 `variant` 表达，而不是拆成不同的操作名：

| 变体 | 语义层 | 说明 |
|---|---|---|
| `normal` | `legit` | 规范内正常值 |
| `boundary` | `legit` | 参数取上界等边界值 |
| `exception` | `abnormal` | 协议异常响应 |
| `illegal_fc` | `abnormal` | 非法或保留功能码 |
| `malformed` | `abnormal` | 长度字段与实际内容不符 |

## PLC 服务端模拟

```bash
# 被动应答，模拟被读取的 PLC
icsgen serve --protocol modbus --transport tcp --port 5020 --role plc

# 主动请求，产出成对的请求/响应会话
icsgen serve --protocol modbus --transport tcp --port 5020 --role client
```

## 扩展新的操作类型

操作类型目录（catalog）是唯一事实源，新增操作不修改框架代码：

1. 在 `icsgen/protocols/modbus/layouts.py` 中声明字段布局
2. 在 `icsgen/protocols/modbus/catalog.yaml` 中登记操作名、布局引用与参数 schema

## 后续阶段

P1 已交付 Modbus TCP/RTU。后续按 P2（EtherNet/IP + CIP）、P3（S7comm）、
P4（Profinet / OPC UA / IEC104）推进，核心抽象不变。
````

- [ ] **Step 4: 运行全部测试确认通过**

Run: `python3 -m pytest tests/ -v`
Expected: PASS —— 全部通过

- [ ] **Step 5: 提交**

```bash
git add scenarios/modbus_demo.yaml tests/test_e2e.py README.md
git commit -m "$(cat <<'EOF'
feat: 端到端集成、示例场景与文档

示例场景覆盖合法、边界与异常三类语义，端到端测试校验 manifest
与帧文件一致性，pcap 可被 Scapy 正常解析。

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Self-Review

**Spec 覆盖核对**

| Spec 章节 | 对应任务 |
|---|---|
| §4.4 字段表驱动内核 | Task 2 |
| §5.2 三条解耦边界 | Task 2（协议/传输分离）、Task 7（链路层不含协议语义）、Task 9（写盘层不理解协议） |
| §6 核心数据模型 | Task 1（Operation/Scenario）、Task 9（Artifact） |
| §7 适配器契约 | Task 11 |
| §8 catalog 与变体 | Task 3、Task 4、Task 5 |
| §9 场景格式 | Task 3 |
| §10 传输封装 | Task 7 |
| §11 产出层 | Task 8、Task 9、Task 11（请求+响应连续：Task 7 反向链路、Task 9 `Artifact.response`、Task 11 `build_response`） |
| §12 变异引擎 | Task 10 |
| §13 PLC 服务端 | Task 13 |
| §14 CLI | Task 12 |
| §15 丰富度指标 | Task 4（catalog 计数断言）、Task 14（数量下限断言）、Task 12（`catalog --count`） |
| §16 测试策略 | Task 2/3/4/6/7/8/9/10/11/12/13/14 |
| §17 依赖 | Task 1（pyproject.toml） |
| §18 风险缓解 | Task 7（校验和由 Scapy 填充）、Task 10（变异不改原数据） |

**跨任务接口一致性**：本计划中 `Operation.tier` 为 `Tier | None`（Task 1 定义，Task 3 透传，Task 11 用 `op.tier.value`）；`Artifact.tier` 为 `str`（Task 9 定义，Task 11 传入 `op.tier.value`）；`plan_variant` 返回 `VariantPlan`（Task 5 定义，Task 11 调用）；`build_dataset(scenario, adapter, root, name)` 的参数顺序在 Task 11 定义，Task 12 与 Task 14 调用一致。请求与响应路径：`TransportSpec.reversed()`（Task 7 定义，Task 11 调用）→ `Artifact.response` 与 `DatasetBuilder.add_linked_packets`（Task 9 定义，Task 11 调用）→ `ProtocolAdapter.build_response`（Task 11 定义，Task 14 端到端断言）。

**编写过程中发现并已修正的问题**：

1. `duplicate_replay` 与 `interleave_frames` 需要成对输入，单帧时返回 `None`；原测试断言"每条规则都产生变异"对这两条不成立 —— 已在 Task 10 的测试中把它们排除并单独断言空结果。
2. `ModbusTcpServer` 没有 `start()` 方法，只有 `serve_forever()` 与 `shutdown()`；原先用线程包裹 `StartTcpServer` 的写法停止不可靠 —— 已改为 `ModbusTcpServer` + `shutdown()`。
3. 响应数组的长度无法从请求字段直接推导（FC03 响应的 values 会算成 0 个元素）—— 已给 `Field` 增加 `len_from_request` 声明，并把 `_build_response` 改为两遍处理（先数组、后长度字段）。
4. **请求内数组的长度必须跟随同帧的计数标量** —— FC0F/FC10/FC17 的请求数组与长度字段互为环状引用，唯一不自相矛盾的依据是同帧的计数标量（`quantity` / `write_quantity`）。布局用 `len_from_request` 声明这条协议结构关系，变体层把数组对齐到计数标量推出的长度（不足补零、超出截断）。**字节布局不变** —— 编解码内核不读这两个字段。
5. **计划原本只产请求帧，没有响应帧** —— 与 spec §7「异常响应作为独立 variant 生成」、§11.1「请求+响应连续」、§16「验证请求-响应成对」矛盾，且 Task 9 的文档字符串已宣称「保持会话内请求/响应连续」。已补上响应路径：Task 7 的 `TransportSpec.reversed()`、Task 9 的 `Artifact.response` 与 `pcap_resp_index`、Task 11 的 `ModbusAdapter.build_response`。**一次操作仍 = 一个 Artifact**，覆盖度计数不变。

**遗留说明**：`duplicate_replay` 与 `interleave_frames` 在 P1 保持"单帧不适用"，成对帧的变异留待 P2 起引入多帧场景后实现；届时需同步更新 Task 10 的测试与 `icsgen.mutate` 的输入接口（当前只接受单帧字节）。


