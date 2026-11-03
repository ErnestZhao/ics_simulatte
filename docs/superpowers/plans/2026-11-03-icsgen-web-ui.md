# icsgen Web 交互界面 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 icsgen 增加 Web 交互界面：选协议 → 选操作类型 → 填参数与交互数量 → 保存配置 → 生成（带进度）→ 预览与下载数据包。

**Architecture:** 五层单向依赖（场景描述 → 协议适配 → 传输封装 → 产出），Web 层是库之上的薄壳，生成仍走 `build_dataset`，网页产出的字节与 CLI 逐字节一致。HTTP 层（FastAPI）→ 服务层（不 import FastAPI）→ 库层；存储层是两个 append-only 账本（配置记录 + 生成事件流），记录天然不可删改。

**Tech Stack:** Python 3.11+ / FastAPI 0.115 / Starlette 0.41 / Uvicorn 0.34 / Jinja2 3.1 / 原生 JS（无前端构建链）/ pytest 9

**Spec:** `docs/superpowers/specs/2026-11-03-icsgen-web-ui-design.md`（权威，冲突以 spec 为准）

## Global Constraints

- **spec 是权威，plan 是对 spec 的论证** —— 冲突时以 spec 为准
- **依赖只增不改**：不降级、不替换现有依赖；新增依赖只能进 `[project.optional-dependencies].web`
- **Web 层不得复制业务逻辑**：生成必须走 `icsgen.generator.build_dataset`，校验必须走 `icsgen.spec.loader.validate_operations`
- **服务层不得 import FastAPI**：`icsgen/web/service.py` 与 `icsgen/web/store.py` 只依赖 pydantic 与标准库
- **记录只读**：不提供任何删除或修改记录的路由与函数
- **交互数量上限**：单操作 ≤ 1000，单次生成总量 ≤ 5000（spec §10.1）
- **全项目纯 Python 依赖**，不引入 npm / 前端构建链 / SPA 框架
- **测试命令**：`python3 -m pytest -q -W error`（`-W error` 下不得有警告）
- **提交粒度**：每个任务至少一次提交，提交信息用中文，格式 `feat: …` / `fix: …` / `docs: …` / `test: …`
- **分支**：`feature/web-ui`（不直接在 `main` 上实施）

---

## 文件结构

| 文件 | 责任 |
|---|---|
| `icsgen/protocols/registry.py`（新建） | 协议名 → catalog 与适配器工厂的唯一映射 |
| `icsgen/protocols/base.py`（改） | 加 `FrameField` / `FrameView`，扩充 `ProtocolAdapter.inspect` 契约 |
| `icsgen/protocols/modbus/inspect.py`（新建） | Modbus 帧的协议级解析 |
| `icsgen/protocols/modbus/adapter.py`（改） | 实现 `inspect` |
| `icsgen/spec/loader.py`（改） | 抽出 `validate_operations`，`load_scenario` 改为调用它 |
| `icsgen/generator.py`（改） | `transaction_id` 取模；新增 `on_progress` 回调 |
| `icsgen/cli.py`（改） | `_catalog_for` 改用注册表；新增 `web` 命令 |
| `icsgen/web/__init__.py`（新建） | 包入口，导出 `create_app` |
| `icsgen/web/store.py`（新建） | append-only 账本：配置记录、生成事件流 |
| `icsgen/web/service.py`（新建） | 协议查询、配置保存、生成调度、产物读取与预览 |
| `icsgen/web/models.py`（新建） | pydantic 请求体模型（只依赖 pydantic） |
| `icsgen/web/app.py`（新建） | FastAPI 应用工厂、路由、错误映射 |
| `icsgen/web/templates/base.html`（新建） | 页面骨架与导航 |
| `icsgen/web/templates/index.html`（新建） | 工作台 |
| `icsgen/web/templates/records.html`（新建） | 记录页 |
| `icsgen/web/templates/generation.html`（新建） | 生成详情（进度 / 产物清单 / 预览） |
| `icsgen/web/static/app.js`（新建） | 工作台表单与进度轮询 |
| `icsgen/web/static/app.css`（新建） | 页面样式 |
| `pyproject.toml`（改） | 新增 `web` 可选依赖组 |

---

### Task 1: 协议注册表

CLI 现在把协议名硬编码在 `icsgen/cli.py:29`，Web 层无法枚举协议。新增注册表作为「协议名 → (catalog, 适配器工厂)」的唯一映射，CLI 与 Web 共用。

**Files:**
- Create: `icsgen/protocols/registry.py`
- Modify: `icsgen/cli.py:1-32`（`_catalog_for`）
- Test: `tests/test_registry.py`

**Interfaces:**
- Consumes: `icsgen.spec.catalog.load_catalog(path) -> Catalog`、`icsgen.protocols.base.ProtocolAdapter`、`icsgen.protocols.modbus.adapter.load_modbus_adapter() -> ModbusAdapter`、`icsgen.protocols.modbus.adapter.CATALOG_PATH -> Path`
- Produces:
  - `ProtocolInfo(name: str, summary: str, transports: tuple[str, ...], catalog_path: Path, adapter_factory: Callable[[], ProtocolAdapter])`（frozen dataclass）
  - `available_protocols() -> list[ProtocolInfo]` —— 按名称排序
  - `get_protocol(name: str) -> ProtocolInfo` —— 未注册抛 `KeyError`
  - `get_catalog(name: str) -> Catalog`
  - `get_adapter(name: str) -> ProtocolAdapter`
  - `transport_kind(catalog_transport: str) -> str` —— `tcp → "tcp"`、`rtu → "serial"`；未知抛 `KeyError`

- [ ] **Step 1: 写失败的测试**

创建 `tests/test_registry.py`：

```python
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
```

- [ ] **Step 2: 跑测试确认失败**

Run: `python3 -m pytest tests/test_registry.py -q`
Expected: FAIL —— `ModuleNotFoundError: No module named 'icsgen.protocols.registry'`

- [ ] **Step 3: 实现注册表**

创建 `icsgen/protocols/registry.py`：

```python
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
```

修改 `icsgen/cli.py` 的导入与 `_catalog_for`：

```python
from .protocols.registry import get_catalog
```

```python
def _catalog_for(protocol: str) -> Catalog:
    try:
        return get_catalog(protocol)
    except KeyError as exc:
        raise typer.BadParameter(str(exc)) from exc
```

- [ ] **Step 4: 跑测试确认通过**

Run: `python3 -m pytest tests/test_registry.py -q`
Expected: 7 passed

- [ ] **Step 5: 跑全量测试确认没有回归**

Run: `python3 -m pytest -q -W error`
Expected: 全部通过（原先 169 passed + 新增 7）

- [ ] **Step 6: 提交**

```bash
git add icsgen/protocols/registry.py icsgen/cli.py tests/test_registry.py
git commit -m "feat: 新增协议注册表，CLI 与 Web 共用协议映射"
```

---

### Task 2: 操作校验复用

`load_scenario()` 只吃 YAML 文件路径，Web 手上是表单数据。抽出 `validate_operations`，让两条路径走同一套校验与同一套错误文案。

**Files:**
- Modify: `icsgen/spec/loader.py`
- Test: `tests/test_catalog.py`（追加用例）

**Interfaces:**
- Consumes: `icsgen.spec.catalog.Catalog`、`icsgen.spec.model.Operation`
- Produces:
  - `validate_operations(catalog: Catalog, items: Sequence[ScenarioOperationModel], context: str | None = None) -> tuple[Operation, ...]` —— 失败抛 `ScenarioError`
  - `load_scenario(path: Path, catalog: Catalog) -> Scenario` —— 行为与错误文案不变

- [ ] **Step 1: 写失败的测试**

在 `tests/test_catalog.py` 末尾追加：

```python
def test_validate_operations_reports_unknown_op():
    cat_path = _write(tmp_path, "catalog.yaml", CATALOG)
    catalog = load_catalog(cat_path)
    items = [ScenarioOperationModel(op="demo.unknown")]
    with pytest.raises(ScenarioError, match="不存在操作"):
        validate_operations(catalog, items)


def test_validate_operations_reports_bad_param():
    cat_path = _write(tmp_path, "catalog.yaml", CATALOG)
    catalog = load_catalog(cat_path)
    items = [ScenarioOperationModel(op="demo.read_holding", params={"quantity": 500})]
    with pytest.raises(ScenarioError, match="参数校验失败"):
        validate_operations(catalog, items)


def test_validate_operations_rejects_unsupported_variant():
    cat_path = _write(tmp_path, "catalog.yaml", CATALOG)
    catalog = load_catalog(cat_path)
    items = [ScenarioOperationModel(op="demo.read_holding", variant=Variant.EXCEPTION)]
    with pytest.raises(ScenarioError, match="不支持的变体"):
        validate_operations(catalog, items)


def test_validate_operations_rejects_tier_variant_conflict():
    cat_path = _write(tmp_path, "catalog.yaml", CATALOG)
    catalog = load_catalog(cat_path)
    items = [
        ScenarioOperationModel(op="demo.read_holding", variant=Variant.BOUNDARY, tier=Tier.ABNORMAL)
    ]
    with pytest.raises(ScenarioError, match="冲突"):
        validate_operations(catalog, items)


def test_validate_operations_returns_operations():
    cat_path = _write(tmp_path, "catalog.yaml", CATALOG)
    catalog = load_catalog(cat_path)
    items = [ScenarioOperationModel(op="demo.read_holding", params={"quantity": 3})]
    operations = validate_operations(catalog, items)
    assert len(operations) == 1
    assert operations[0].params == {"quantity": 3}
    assert operations[0].tier is Tier.LEGIT


def test_validate_operations_context_appears_in_message():
    cat_path = _write(tmp_path, "catalog.yaml", CATALOG)
    catalog = load_catalog(cat_path)
    items = [ScenarioOperationModel(op="demo.unknown")]
    with pytest.raises(ScenarioError, match="提交的操作"):
        validate_operations(catalog, items, context="提交的操作")
```

同步修改 `tests/test_catalog.py` 的导入：

```python
from icsgen.spec.loader import (
    ScenarioError,
    ScenarioOperationModel,
    load_scenario,
    validate_operations,
)
```

- [ ] **Step 2: 跑测试确认失败**

Run: `python3 -m pytest tests/test_catalog.py -q`
Expected: FAIL —— `ImportError: cannot import name 'validate_operations'`

- [ ] **Step 3: 实现**

改写 `icsgen/spec/loader.py` 的校验部分：

```python
"""场景 YAML 的加载与校验。

加载链路：YAML → pydantic 校验结构 → 逐个操作查 catalog → 用 catalog 声明的
参数 schema 校验参数 → 构造 Operation 列表。

Web 表单提交走同一条校验路径（validate_operations），因此参数 schema、
变体合法性、tier/variant 冲突的判定与错误文案在两条路径上完全一致。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Sequence

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


def _operation_label(context: str | None, index: int, name: str) -> str:
    """生成「第 N 条操作 <名字>」的定位串，context 为空时省略前缀。"""
    prefix = f"{context} " if context else ""
    return f"{prefix}第 {index} 条操作 {name!r}"


def _validate_params(entry: OperationEntry, params: dict[str, Any], label: str) -> None:
    """用 catalog 声明的参数 schema 校验操作参数。"""
    if not entry.params:
        if params:
            raise ScenarioError(f"{label}不接受参数，但给出了 {params}")
        return
    validator = Draft202012Validator(_object_schema(entry))
    errors = sorted(validator.iter_errors(params), key=lambda e: list(e.path))
    if errors:
        details = "; ".join(f"{list(e.path) or '<根>'}: {e.message}" for e in errors)
        raise ScenarioError(f"{label}参数校验失败：{details}")


def validate_operations(
    catalog: Catalog,
    items: Sequence[ScenarioOperationModel],
    context: str | None = None,
) -> tuple[Operation, ...]:
    """按 catalog 校验一组操作声明，返回构造好的 Operation 列表。

    context 是可选的定位前缀（如 "场景 <路径>" 或 "提交的操作"），
    只影响错误文案，不影响判定。
    """
    operations: list[Operation] = []
    for index, item in enumerate(items):
        try:
            entry = catalog.get(item.op)
        except KeyError as exc:
            raise ScenarioError(
                f"{_operation_label(context, index, item.op)}："
                f"catalog {catalog.protocol!r} 中不存在操作"
            ) from exc
        if item.variant.value not in entry.variants:
            raise ScenarioError(
                f"{_operation_label(context, index, entry.name)}不支持的变体 "
                f"{item.variant.value!r}，可用变体：{entry.variants}"
            )
        _validate_params(entry, item.params, _operation_label(context, index, entry.name))
        try:
            operation = Operation(
                op=item.op,
                params=item.params,
                variant=item.variant,
                tier=item.tier,
                expect_response=item.expect_response,
            )
        except ValueError as exc:
            raise ScenarioError(
                f"{_operation_label(context, index, entry.name)}的语义层与变体冲突：{exc}"
            ) from exc
        operations.append(operation)
    return tuple(operations)


def load_scenario(path: Path, catalog: Catalog) -> Scenario:
    """加载并校验场景文件，返回 Scenario。"""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    try:
        model = ScenarioModel.model_validate(raw)
    except ValidationError as exc:
        raise ScenarioError(f"场景 {path} 结构不合法：{exc}") from exc
    operations = validate_operations(catalog, model.operations, context=f"场景 {path}")
    return Scenario(
        name=model.name,
        description=model.description,
        transport=model.transport,
        operations=operations,
    )
```

- [ ] **Step 4: 跑测试确认通过**

Run: `python3 -m pytest tests/test_catalog.py -q`
Expected: 全部通过（含原有 13 个用例）

- [ ] **Step 5: 跑全量测试**

Run: `python3 -m pytest -q -W error`
Expected: 全部通过

- [ ] **Step 6: 提交**

```bash
git add icsgen/spec/loader.py tests/test_catalog.py
git commit -m "refactor: 抽出 validate_operations，场景与表单共用同一套校验"
```

---

### Task 3: 帧解析契约（FrameView 与 Modbus inspect）

预览要解出「事务 id / 单元 id / 功能码 / 异常码 / 各字段值」，这是协议知识，必须放在协议层。

**Files:**
- Modify: `icsgen/protocols/base.py`
- Create: `icsgen/protocols/modbus/inspect.py`
- Modify: `icsgen/protocols/modbus/adapter.py`
- Test: `tests/test_modbus_inspect.py`

**Interfaces:**
- Consumes: `icsgen.codec.decoder.decode(fields, data, offset=0) -> dict`、`icsgen.codec.decoder.DecodeError`、`icsgen.codec.fields.Layout`、`icsgen.protocols.modbus.framing.parse_mbap/parse_rtu`、`icsgen.protocols.modbus.layouts.get_layout(name) -> Layout`
- Produces:
  - `icsgen.protocols.base.FrameField(name: str, value: str)`（frozen dataclass）
  - `icsgen.protocols.base.FrameView(summary: str, fields: tuple[FrameField, ...] = (), is_exception: bool = False, exception_code: int | None = None)`（frozen dataclass）
  - `icsgen.protocols.base.ProtocolAdapter.inspect(op: str, payload: bytes, ctx: BuildContext, direction: str) -> FrameView`
  - `icsgen.protocols.modbus.inspect.inspect_frame(layout: Layout, payload: bytes, ctx: BuildContext, direction: str) -> FrameView`

- [ ] **Step 1: 写失败的测试**

创建 `tests/test_modbus_inspect.py`：

```python
"""Modbus 帧的协议级解析。"""

from icsgen.protocols.base import BuildContext
from icsgen.protocols.modbus.adapter import load_modbus_adapter
from icsgen.protocols.modbus.framing import build_mbap, build_pdu, build_rtu
from icsgen.protocols.modbus.inspect import inspect_frame
from icsgen.protocols.modbus.layouts import get_layout
from icsgen.spec.model import Operation


def _field_map(view):
    return {field.name: field.value for field in view.fields}


def test_inspect_tcp_request_reports_mbap_fields():
    pdu = build_pdu(3, b"\x00\x00\x00\x03")
    frame = build_mbap(1, 0xFF, pdu)
    layout = get_layout("fc03")
    view = inspect_frame(layout, frame, BuildContext(transport="tcp"), "request")
    fields = _field_map(view)
    assert fields["事务 id"] == "1"
    assert fields["单元 id"] == "255"
    assert fields["功能码"] == "0x03"
    assert fields["start_addr"] == "0"
    assert fields["quantity"] == "3"
    assert view.is_exception is False


def test_inspect_tcp_response_decodes_layout_fields():
    pdu = build_pdu(3, b"\x06\x00\x01\x00\x02\x00\x03")
    frame = build_mbap(1, 0xFF, pdu)
    layout = get_layout("fc03")
    view = inspect_frame(layout, frame, BuildContext(transport="tcp"), "response")
    fields = _field_map(view)
    assert fields["byte_count"] == "6"
    assert fields["values"] == "1, 2, 3"


def test_inspect_detects_exception_response():
    pdu = build_pdu(0x83, b"\x02")
    frame = build_mbap(1, 0xFF, pdu)
    layout = get_layout("fc03")
    view = inspect_frame(layout, frame, BuildContext(transport="tcp"), "response")
    assert view.is_exception is True
    assert view.exception_code == 2
    assert "0x03" in view.summary


def test_inspect_rtu_frame_reports_unit_id():
    pdu = build_pdu(3, b"\x00\x00\x00\x03")
    frame = build_rtu(0x11, pdu)
    layout = get_layout("fc03")
    view = inspect_frame(layout, frame, BuildContext(transport="rtu"), "request")
    assert _field_map(view)["从站地址"] == "17"


def test_inspect_bad_crc_degrades_without_raising():
    """畸形帧也是数据集的一部分，解析失败不能抛异常。"""
    frame = b"\x11\x03\x00\x00\x00\x03\x00\x00"
    layout = get_layout("fc03")
    view = inspect_frame(layout, frame, BuildContext(transport="rtu"), "request")
    assert "解析失败" in view.summary
    assert view.fields == ()


def test_inspect_truncated_frame_degrades_without_raising():
    layout = get_layout("fc03")
    view = inspect_frame(layout, b"\x00\x01", BuildContext(transport="tcp"), "request")
    assert "解析失败" in view.summary


def test_adapter_inspect_resolves_layout_by_operation_name():
    """布局按操作名定位 —— 诊断子功能共享 fc08，按功能码反查会取错布局。"""
    adapter = load_modbus_adapter()
    pdu = build_pdu(3, b"\x00\x00\x00\x03")
    frame = build_mbap(1, 0xFF, pdu)
    view = adapter.inspect(
        "modbus.read_holding_registers", frame, BuildContext(transport="tcp"), "request"
    )
    assert _field_map(view)["quantity"] == "3"


def test_inspect_covers_every_catalog_layout():
    """验收指标 5：Modbus 全部 19 个布局的请求与响应字段都要解得出来。"""
    adapter = load_modbus_adapter()
    layouts = set()
    for name in adapter.catalog.operations:
        entry = adapter.catalog.get(name)
        layouts.add(entry.layout)
        operation = Operation(op=name, params={})
        ctx = BuildContext(transaction_id=1, unit_id=0xFF, transport="tcp", seed=0)

        request = adapter.build(operation, ctx)
        request_view = adapter.inspect(name, request.payload, ctx, "request")
        assert "解析失败" not in request_view.summary, name
        assert request_view.fields, name

        response = adapter.build_response(operation, ctx)
        if response is None:
            continue
        response_view = adapter.inspect(name, response.payload, ctx, "response")
        assert "解析失败" not in response_view.summary, name
        assert response_view.fields, name
    assert len(layouts) == 19
```

- [ ] **Step 2: 跑测试确认失败**

Run: `python3 -m pytest tests/test_modbus_inspect.py -q`
Expected: FAIL —— `ModuleNotFoundError: No module named 'icsgen.protocols.modbus.inspect'`

- [ ] **Step 3: 扩充适配器契约**

在 `icsgen/protocols/base.py` 的 `ProtocolFrame` 之后追加：

```python
@dataclass(frozen=True)
class FrameField:
    """帧的一个字段及其显示值。"""

    name: str
    value: str


@dataclass(frozen=True)
class FrameView:
    """一帧的协议级解析结果。

    summary 是一行摘要，fields 是逐字段的解析结果。解析失败时只给摘要，
    fields 为空 —— 畸形帧本就是数据集的一部分，预览不该因此失败。
    """

    summary: str
    fields: tuple[FrameField, ...] = ()
    is_exception: bool = False
    exception_code: int | None = None
```

并把 `ProtocolAdapter` 改为：

```python
class ProtocolAdapter(Protocol):
    """协议适配器契约。"""

    name: str
    operations: Mapping[str, OperationSpec]

    def build(self, op: Operation, ctx: BuildContext) -> ProtocolFrame: ...

    def build_response(self, op: Operation, ctx: BuildContext) -> ProtocolFrame | None: ...

    def inspect(self, op: str, payload: bytes, ctx: BuildContext, direction: str) -> FrameView:
        """解析一帧，direction 取 "request" 或 "response"。

        op 是操作名，用于定位字段布局 —— 不能按功能码反查布局：catalog 中
        多个操作共享功能码（21 个诊断子功能共享 fc08）。
        """
        ...
```

- [ ] **Step 4: 实现 Modbus 解析**

创建 `icsgen/protocols/modbus/inspect.py`：

```python
"""Modbus 帧的协议级解析：把裸帧拆成头、功能码与字段。

预览页要展示「事务 id / 单元 id / 功能码 / 异常码 / 各字段值」，
这些是协议知识，留在协议层而不是 Web 层。
"""

from __future__ import annotations

from typing import Any

from ...codec.decoder import DecodeError, decode
from ...codec.fields import Layout
from ..base import BuildContext, FrameField, FrameView
from . import framing


def _format(value: Any) -> str:
    """把解码出的取值格式化成显示用的一行。"""
    if isinstance(value, bytes):
        return value.hex(" ")
    if isinstance(value, list):
        return ", ".join(_format(item) for item in value)
    return str(value)


def _decode_fields(
    layout: Layout, data: bytes, direction: str
) -> tuple[list[FrameField], str | None]:
    """按布局解字段；解不出时返回空列表与失败原因。"""
    fields = layout.request if direction == "request" else layout.response
    try:
        values = decode(fields, data)
    except DecodeError as exc:
        return [], str(exc)
    return [FrameField(name=name, value=_format(value)) for name, value in values.items()], None


def inspect_frame(
    layout: Layout, payload: bytes, ctx: BuildContext, direction: str
) -> FrameView:
    """解析一帧 Modbus 请求或响应。

    解析失败（帧过短、CRC 不符）不抛错，返回只含失败原因的 FrameView。
    """
    try:
        if ctx.transport == "rtu":
            parsed = framing.parse_rtu(payload)
            header = [FrameField("从站地址", str(parsed["unit_id"]))]
        else:
            parsed = framing.parse_mbap(payload)
            header = [
                FrameField("事务 id", str(parsed["transaction_id"])),
                FrameField("协议 id", str(parsed["protocol_id"])),
                FrameField("长度", str(parsed["length"])),
                FrameField("单元 id", str(parsed["unit_id"])),
            ]
        pdu = parsed["pdu"]
    except ValueError as exc:
        return FrameView(summary=f"解析失败：{exc}")

    if not pdu:
        return FrameView(summary="空 PDU")

    func_code = pdu[0]
    if func_code & 0x80:
        code = pdu[1] if len(pdu) > 1 else None
        fields = [
            *header,
            FrameField("功能码", f"0x{func_code:02X}"),
            FrameField("异常码", str(code)),
        ]
        return FrameView(
            summary=f"Modbus 异常响应，功能码 0x{func_code & 0x7F:02X}，异常码 {code}",
            fields=tuple(fields),
            is_exception=True,
            exception_code=code,
        )

    decoded, error = _decode_fields(layout, pdu[1:], direction)
    fields = [*header, FrameField("功能码", f"0x{func_code:02X}"), *decoded]
    summary = f"Modbus 功能码 0x{func_code:02X}"
    if error:
        summary = f"{summary}（字段解析失败：{error}）"
    return FrameView(summary=summary, fields=tuple(fields))
```

在 `icsgen/protocols/modbus/adapter.py` 中实现 `inspect`：

```python
from .inspect import inspect_frame
```

```python
    def inspect(self, op: str, payload: bytes, ctx: BuildContext, direction: str) -> FrameView:
        """解析一帧请求或响应，布局按操作名定位。"""
        entry = self.catalog.get(op)
        layout = get_layout(entry.layout)
        return inspect_frame(layout, payload, ctx, direction)
```

并补上 `FrameView` 的导入：

```python
from ..base import BuildContext, FrameView, OperationSpec, ProtocolFrame
```

- [ ] **Step 5: 跑测试确认通过**

Run: `python3 -m pytest tests/test_modbus_inspect.py -q`
Expected: 8 passed

- [ ] **Step 6: 跑全量测试**

Run: `python3 -m pytest -q -W error`
Expected: 全部通过

- [ ] **Step 7: 提交**

```bash
git add icsgen/protocols/base.py icsgen/protocols/modbus/inspect.py icsgen/protocols/modbus/adapter.py tests/test_modbus_inspect.py
git commit -m "feat: 适配器新增 inspect 契约，Modbus 帧可解出字段"
```

---

### Task 4: 生成器 —— transaction_id 修复与进度回调

`icsgen/generator.py:37` 用场景下标当 Modbus 事务 id，而 MBAP 的事务 id 只有 2 字节。交互数量放开到数千后下标必然越过 65535，`to_bytes(2, "big")` 会抛 `OverflowError` 直接崩溃。

**Files:**
- Modify: `icsgen/generator.py`
- Test: `tests/test_generator.py`（追加用例）

**Interfaces:**
- Consumes: `icsgen.emit.dataset.DatasetBuilder`、`icsgen.transport.link.encapsulate`
- Produces:
  - `build_dataset(scenario: Scenario, adapter: ProtocolAdapter, root: Path, name: str | None = None, on_progress: Callable[[int, int], None] | None = None) -> Path`
  - `on_progress(done, total)` 在每条交互的帧构建完成后调用一次，`done` 从 1 递增到 `total`

- [ ] **Step 1: 写失败的测试**

在 `tests/test_generator.py` 末尾追加：

```python
def test_progress_callback_reports_every_interaction(tmp_path):
    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    scenario = Scenario(
        name="demo",
        transport={"kind": "tcp"},
        operations=(
            Operation(op="modbus.read_holding_registers", params={"quantity": 3}),
            Operation(op="modbus.write_multiple_registers", params={"quantity": 2}),
        ),
    )
    seen = []
    build_dataset(
        scenario, adapter, tmp_path / "ds", name="demo",
        on_progress=lambda done, total: seen.append((done, total)),
    )
    assert seen == [(1, 2), (2, 2)]


def test_transaction_id_wraps_after_65536(tmp_path):
    """交互数量放开后事务 id 会越过 2 字节，必须取模而不是崩掉。"""
    from icsgen.spec.model import Operation

    adapter = load_modbus_adapter()
    operations = tuple(
        Operation(op="modbus.read_holding_registers", params={"quantity": 1})
        for _ in range(65538)
    )
    scenario = Scenario(name="demo", transport={"kind": "tcp"}, operations=operations)
    root = build_dataset(scenario, adapter, tmp_path / "ds", name="demo")
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert len(manifest["artifacts"]) == 65538
    # 第 65536 次交互的事务 id 回到 0
    assert manifest["artifacts"][65536]["id"].endswith("#65537")
```

**注**：第二个用例会生成 65538 次交互（约 26 万个文件），CI 上偏重。实施时若明显拖慢测试，可改为直接对 `build_dataset` 传一个自定义 adapter 验证事务 id 取模行为 —— 保留同样的断言强度：

```python
def test_transaction_id_wraps_after_65536(tmp_path):
    """交互数量放开后事务 id 会越过 2 字节，必须取模而不是崩掉。"""
    from icsgen.protocols.base import BuildContext, ProtocolFrame
    from icsgen.spec.model import Operation

    captured = []

    class RecordingAdapter:
        name = "modbus"

        def build(self, op, ctx):
            captured.append(ctx.transaction_id)
            return ProtocolFrame(payload=b"\x00\x01")

        def build_response(self, op, ctx):
            return None

    scenario = Scenario(
        name="demo",
        transport={"kind": "tcp"},
        operations=tuple(
            Operation(op="modbus.read_holding_registers", params={"quantity": 1})
            for _ in range(65538)
        ),
    )
    build_dataset(scenario, RecordingAdapter(), tmp_path / "ds", name="demo")
    assert len(captured) == 65538
    assert captured[65536] == 0
    assert captured[65537] == 1
    assert max(captured) <= 0xFFFF
```

**以第二个版本为准**（用记录型 adapter 验证事务 id，避免生成 26 万个文件）。

- [ ] **Step 2: 跑测试确认失败**

Run: `python3 -m pytest tests/test_generator.py -q`
Expected: FAIL —— `TypeError: build_dataset() got an unexpected keyword argument 'on_progress'`

- [ ] **Step 3: 实现**

改写 `icsgen/generator.py`：

```python
"""生成流水线：把场景变成分层数据集。

流程：场景 → 逐条操作构建请求帧与响应帧 → 封装链路 → 登记为产物 → 写盘。
请求与响应连续进入同一会话的 pcap，保持会话内可配对。
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from .emit.dataset import Artifact, DatasetBuilder
from .protocols.base import BuildContext, ProtocolAdapter
from .spec.model import Scenario
from .transport.link import encapsulate
from .transport.spec import TransportSpec

#: Modbus MBAP 的事务 id 占 2 字节，越界要回绕而不是崩掉
_TRANSACTION_ID_MODULO = 0x10000
#: TCP 序列号占 4 字节
_SEQUENCE_MODULO = 2**32


def _transport_spec(scenario: Scenario) -> TransportSpec:
    raw = dict(scenario.transport)
    kind = raw.pop("kind", "tcp")
    return TransportSpec(kind=kind, **raw)


def build_dataset(
    scenario: Scenario,
    adapter: ProtocolAdapter,
    root: Path,
    name: str | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> Path:
    """按场景生成数据集，返回数据集根路径。

    on_progress(done, total) 在每条交互的帧构建完成后调用一次，用于向
    使用者反馈生成进度；不传则不报告。
    """
    spec = _transport_spec(scenario)
    builder = DatasetBuilder(name or scenario.name, root, transport=spec.to_dict())
    total = len(scenario.operations)

    for index, op in enumerate(scenario.operations):
        ctx = BuildContext(
            transaction_id=index % _TRANSACTION_ID_MODULO,
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
        seq = (index * 10) % _SEQUENCE_MODULO
        packets = [encapsulate(frame.payload, spec, seq=seq, ack=seq)]
        if response_frame is not None:
            packets.append(
                encapsulate(
                    response_frame.payload,
                    spec.reversed(),
                    seq=(seq + len(frame.payload)) % _SEQUENCE_MODULO,
                    ack=(seq + len(frame.payload)) % _SEQUENCE_MODULO,
                )
            )
        builder.add_linked_packets(artifact.id, packets)
        if on_progress is not None:
            on_progress(index + 1, total)

    return builder.write()
```

- [ ] **Step 4: 跑测试确认通过**

Run: `python3 -m pytest tests/test_generator.py -q`
Expected: 全部通过

- [ ] **Step 5: 跑全量测试**

Run: `python3 -m pytest -q -W error`
Expected: 全部通过

- [ ] **Step 6: 提交**

```bash
git add icsgen/generator.py tests/test_generator.py
git commit -m "fix: 事务 id 与序列号取模，并给生成流程加进度回调"
```

---

### Task 5: Web 存储层（append-only 账本）

配置记录与生成事件流都只追加、不修改 —— 记录因此天然不可删改，不需要额外的权限逻辑。

**Files:**
- Create: `icsgen/web/__init__.py`
- Create: `icsgen/web/store.py`
- Test: `tests/test_web_store.py`

**Interfaces:**
- Consumes: 无（只用标准库）
- Produces:
  - `icsgen.web.store.Ledger(path: Path)` —— `append(record: dict) -> dict`、`read_all() -> list[dict]`
  - `icsgen.web.store.WebStore(root: Path)`：
    - `save_config(record: dict) -> dict`
    - `list_configs() -> list[dict]`
    - `get_config(config_id: str) -> dict | None`
    - `append_event(event: dict) -> dict`
    - `list_events() -> list[dict]`
    - `list_generations() -> list[dict]` —— 由事件流折叠，按创建顺序倒序
    - `generation_for_config(config_id: str) -> str | None`
    - `generations_by_config() -> dict[str, str]`
    - `generation_dir(generation_id: str) -> Path`

- [ ] **Step 1: 写失败的测试**

创建 `tests/test_web_store.py`：

```python
"""Web 层的 append-only 账本。"""

import json

from icsgen.web.store import Ledger, WebStore


def test_ledger_appends_and_reads_back(tmp_path):
    ledger = Ledger(tmp_path / "records.jsonl")
    ledger.append({"id": "a"})
    ledger.append({"id": "b"})
    assert [record["id"] for record in ledger.read_all()] == ["a", "b"]


def test_ledger_never_modifies_existing_lines(tmp_path):
    path = tmp_path / "records.jsonl"
    ledger = Ledger(path)
    ledger.append({"id": "a", "value": 1})
    first = path.read_text(encoding="utf-8")
    ledger.append({"id": "b", "value": 2})
    assert path.read_text(encoding="utf-8").startswith(first)


def test_ledger_skips_corrupted_lines(tmp_path):
    path = tmp_path / "records.jsonl"
    path.write_text('{"id": "a"}\n\n{坏掉的行\n{"id": "b"}\n', encoding="utf-8")
    assert [record["id"] for record in Ledger(path).read_all()] == ["a", "b"]


def test_ledger_read_all_on_missing_file(tmp_path):
    assert Ledger(tmp_path / "nope.jsonl").read_all() == []


def test_store_saves_and_fetches_config(tmp_path):
    store = WebStore(tmp_path)
    record = store.save_config({"id": "cfg_1", "name": "配置"})
    assert record["id"] == "cfg_1"
    assert store.get_config("cfg_1")["name"] == "配置"
    assert store.get_config("cfg_missing") is None


def test_store_lists_generations_from_events(tmp_path):
    store = WebStore(tmp_path)
    store.append_event({
        "type": "generation_started", "generation_id": "gen_1",
        "config_id": "cfg_1", "config_name": "配置", "created_at": "t0",
    })
    store.append_event({
        "type": "generation_succeeded", "generation_id": "gen_1",
        "artifact_count": 3, "packet_count": 6, "duration_ms": 12,
    })
    generations = store.list_generations()
    assert len(generations) == 1
    assert generations[0]["status"] == "succeeded"
    assert generations[0]["artifact_count"] == 3


def test_store_marks_running_generation(tmp_path):
    store = WebStore(tmp_path)
    store.append_event({
        "type": "generation_started", "generation_id": "gen_1",
        "config_id": "cfg_1", "config_name": "配置", "created_at": "t0",
    })
    assert store.list_generations()[0]["status"] == "running"


def test_store_finds_generation_for_config(tmp_path):
    store = WebStore(tmp_path)
    store.append_event({
        "type": "generation_started", "generation_id": "gen_1",
        "config_id": "cfg_1", "config_name": "配置", "created_at": "t0",
    })
    assert store.generation_for_config("cfg_1") == "gen_1"
    assert store.generation_for_config("cfg_other") is None
    assert store.generations_by_config() == {"cfg_1": "gen_1"}


def test_store_generation_dir_is_under_root(tmp_path):
    store = WebStore(tmp_path)
    assert store.generation_dir("gen_1") == tmp_path / "generations" / "gen_1"
```

- [ ] **Step 2: 跑测试确认失败**

Run: `python3 -m pytest tests/test_web_store.py -q`
Expected: FAIL —— `ModuleNotFoundError: No module named 'icsgen.web'`

- [ ] **Step 3: 实现**

创建 `icsgen/web/__init__.py`：

```python
"""Web 交互界面：把流量生成流水线暴露成 HTTP 页面与 JSON API。"""
```

创建 `icsgen/web/store.py`：

```python
"""append-only 账本：配置记录与生成事件。

两份账本都只追加，不修改既有行 —— 配置记录与生成记录因此天然不可删改。
写入用进程内锁与文件锁串行化；读取时跳过损坏行，避免单行问题拖垮整个页面。
"""

from __future__ import annotations

import fcntl
import json
import os
import threading
from pathlib import Path
from typing import Any


class Ledger:
    """一个只追加的 JSONL 账本。"""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        """追加一条记录并落盘，返回它。"""
        line = json.dumps(record, ensure_ascii=False)
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    handle.write(line + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        return record

    def read_all(self) -> list[dict[str, Any]]:
        """读出全部记录；空行与解析失败的行被跳过。"""
        if not self.path.exists():
            return []
        records: list[dict[str, Any]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return records


class WebStore:
    """Web 层的持久化入口：两个账本 + 生成目录。"""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self._configs = Ledger(self.root / "configs.jsonl")
        self._events = Ledger(self.root / "events.jsonl")

    # ---- 配置记录 ----
    def save_config(self, record: dict[str, Any]) -> dict[str, Any]:
        """追加一条配置记录。记录落盘后不可修改、不可删除。"""
        return self._configs.append(record)

    def list_configs(self) -> list[dict[str, Any]]:
        return self._configs.read_all()

    def get_config(self, config_id: str) -> dict[str, Any] | None:
        for record in reversed(self._configs.read_all()):
            if record.get("id") == config_id:
                return record
        return None

    # ---- 生成事件 ----
    def append_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """追加一条生成事件。"""
        return self._events.append(event)

    def list_events(self) -> list[dict[str, Any]]:
        return self._events.read_all()

    def list_generations(self) -> list[dict[str, Any]]:
        """把事件流折叠成生成记录列表，最新的在前。"""
        generations: dict[str, dict[str, Any]] = {}
        order: list[str] = []
        for event in self.list_events():
            generation_id = event.get("generation_id")
            if not generation_id:
                continue
            if generation_id not in generations:
                generations[generation_id] = {
                    "id": generation_id,
                    "config_id": event.get("config_id"),
                    "config_name": event.get("config_name"),
                    "output_dir": event.get("output_dir"),
                    "status": "running",
                    "created_at": event.get("created_at"),
                    "finished_at": None,
                    "artifact_count": None,
                    "packet_count": None,
                    "duration_ms": None,
                    "error": None,
                }
                order.append(generation_id)
            kind = event.get("type")
            if kind == "generation_succeeded":
                generations[generation_id].update(
                    status="succeeded",
                    artifact_count=event.get("artifact_count"),
                    packet_count=event.get("packet_count"),
                    duration_ms=event.get("duration_ms"),
                    finished_at=event.get("finished_at"),
                )
            elif kind == "generation_failed":
                generations[generation_id].update(
                    status="failed",
                    error=event.get("error"),
                    finished_at=event.get("finished_at"),
                )
        return [generations[gid] for gid in reversed(order)]

    def generation_for_config(self, config_id: str) -> str | None:
        """返回该配置已发起的生成 id；未发起过返回 None。"""
        for event in self.list_events():
            if (
                event.get("type") == "generation_started"
                and event.get("config_id") == config_id
            ):
                return event.get("generation_id")
        return None

    def generations_by_config(self) -> dict[str, str]:
        """配置 id → 已发起的生成 id。"""
        mapping: dict[str, str] = {}
        for event in self.list_events():
            if event.get("type") == "generation_started":
                mapping[event.get("config_id")] = event.get("generation_id")
        return mapping

    def generation_dir(self, generation_id: str) -> Path:
        """一个生成任务的数据集目录。"""
        return self.root / "generations" / generation_id
```

- [ ] **Step 4: 跑测试确认通过**

Run: `python3 -m pytest tests/test_web_store.py -q`
Expected: 10 passed

- [ ] **Step 5: 提交**

```bash
git add icsgen/web/__init__.py icsgen/web/store.py tests/test_web_store.py
git commit -m "feat: 新增 Web 存储层，配置记录与生成事件只追加"
```

---

### Task 6: Web 服务层

服务层承载全部业务逻辑，不 import FastAPI，因此可以脱离 HTTP 单独测试。

**Files:**
- Create: `icsgen/web/models.py`
- Create: `icsgen/web/service.py`
- Test: `tests/test_web_service.py`

**Interfaces:**
- Consumes: `icsgen.protocols.registry.available_protocols/get_catalog/get_adapter`、`icsgen.spec.loader.validate_operations/ScenarioOperationModel/ScenarioError`、`icsgen.spec.model.Operation/Scenario/Variant`、`icsgen.generator.build_dataset`、`icsgen.protocols.base.BuildContext`、Task 5 的 `icsgen.web.store.WebStore`
- Produces:
  - `icsgen.web.models.OperationInput(op: str, variant: str = "normal", params: dict = {}, count: int = 1)`
  - `icsgen.web.models.ConfigPayload(name: str, protocol: str = "modbus", transport: dict = {}, operations: list[OperationInput])`
  - `icsgen.web.models.GenerationPayload(config_id: str)`
  - `icsgen.web.service.WebError(ValueError)`、`NotFound(WebError)`、`AlreadyGenerated(WebError)`
  - `MAX_COUNT_PER_OPERATION = 1000`、`MAX_TOTAL_COUNT = 5000`
  - `list_protocols() -> list[dict]`
  - `list_operations(protocol: str) -> list[dict]`
  - `save_config(store: WebStore, payload: ConfigPayload) -> dict`
  - `build_scenario(config: dict) -> Scenario`
  - `GenerationService(store: WebStore)` —— `start(config_id: str) -> dict`、`state(generation_id: str) -> dict | None`
  - `generation_detail(store: WebStore, service: GenerationService, generation_id: str) -> dict`
  - `artifact_detail(store: WebStore, generation_id: str, artifact_id: str) -> dict`
  - `read_manifest(store: WebStore, generation_id: str) -> dict | None`

- [ ] **Step 1: 写失败的测试**

创建 `tests/test_web_service.py`：

```python
"""Web 服务层：协议查询、配置保存、生成调度与产物预览。"""

import time

import pytest

from icsgen.web.models import ConfigPayload, GenerationPayload, OperationInput
from icsgen.web.service import (
    AlreadyGenerated,
    MAX_COUNT_PER_OPERATION,
    MAX_TOTAL_COUNT,
    NotFound,
    WebError,
    GenerationService,
    artifact_detail,
    build_scenario,
    generation_detail,
    list_operations,
    list_protocols,
    save_config,
)
from icsgen.web.store import WebStore


def _payload(count=1, op="modbus.read_holding_registers"):
    return ConfigPayload(
        name="测试配置",
        protocol="modbus",
        transport={"kind": "tcp"},
        operations=[
            OperationInput(op=op, variant="normal", params={"start_addr": 0, "quantity": 3}, count=count)
        ],
    )


def _wait(generation_id, service, timeout=20.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        detail = generation_detail(service.store, service, generation_id)
        if detail["status"] != "running":
            return detail
        time.sleep(0.05)
    raise AssertionError("生成超时")


def test_list_protocols_reports_catalog_stats():
    protocols = list_protocols()
    assert protocols[0]["name"] == "modbus"
    assert protocols[0]["operation_count"] == 41
    assert protocols[0]["coverage_count"] == 192


def test_list_operations_exposes_params_schema():
    operations = list_operations("modbus")
    assert len(operations) == 41
    entry = next(o for o in operations if o["name"] == "modbus.read_holding_registers")
    assert entry["func_code"] == 3
    assert entry["variants"] == ["normal", "boundary", "exception"]
    assert entry["params"]["quantity"]["maximum"] == 125


def test_list_operations_unknown_protocol_raises():
    with pytest.raises(KeyError):
        list_operations("cip")


def test_save_config_records_selection(tmp_path):
    store = WebStore(tmp_path)
    record = save_config(store, _payload(count=5))
    assert record["id"].startswith("cfg_")
    assert record["operations"][0]["count"] == 5
    assert store.get_config(record["id"])["name"] == "测试配置"


def test_save_config_rejects_unknown_operation(tmp_path):
    store = WebStore(tmp_path)
    with pytest.raises(Exception) as info:
        save_config(store, _payload(op="modbus.nope"))
    assert "不存在操作" in str(info.value)


def test_save_config_rejects_bad_param(tmp_path):
    store = WebStore(tmp_path)
    payload = ConfigPayload(
        name="坏参数",
        protocol="modbus",
        transport={"kind": "tcp"},
        operations=[OperationInput(op="modbus.read_holding_registers", params={"quantity": 9999})],
    )
    with pytest.raises(Exception) as info:
        save_config(store, payload)
    assert "参数校验失败" in str(info.value)


def test_save_config_rejects_count_over_limit(tmp_path):
    store = WebStore(tmp_path)
    with pytest.raises(WebError, match="超过单操作上限"):
        save_config(store, _payload(count=MAX_COUNT_PER_OPERATION + 1))


def test_save_config_rejects_total_over_limit(tmp_path):
    store = WebStore(tmp_path)
    payload = ConfigPayload(
        name="太多",
        protocol="modbus",
        transport={"kind": "tcp"},
        operations=[
            OperationInput(op="modbus.read_holding_registers", count=MAX_COUNT_PER_OPERATION)
            for _ in range(MAX_TOTAL_COUNT // MAX_COUNT_PER_OPERATION + 1)
        ],
    )
    with pytest.raises(WebError, match="超过总量上限"):
        save_config(store, payload)


def test_build_scenario_expands_count(tmp_path):
    scenario = build_scenario(
        {
            "name": "x",
            "transport": {"kind": "tcp"},
            "operations": [{"op": "modbus.read_holding_registers", "count": 3}],
        }
    )
    assert len(scenario.operations) == 3
    assert all(op.op == "modbus.read_holding_registers" for op in scenario.operations)


def test_generation_produces_artifacts(tmp_path):
    store = WebStore(tmp_path)
    service = GenerationService(store)
    config = save_config(store, _payload(count=3))
    started = service.start(config["id"])
    detail = _wait(started["generation_id"], service)
    assert detail["status"] == "succeeded"
    assert detail["artifact_count"] == 3
    assert len(detail["artifacts"]) == 3
    assert detail["percent"] == 100.0


def test_generation_cannot_run_twice_for_same_config(tmp_path):
    store = WebStore(tmp_path)
    service = GenerationService(store)
    config = save_config(store, _payload())
    started = service.start(config["id"])
    _wait(started["generation_id"], service)
    with pytest.raises(AlreadyGenerated):
        service.start(config["id"])


def test_generation_of_unknown_config_raises(tmp_path):
    service = GenerationService(WebStore(tmp_path))
    with pytest.raises(NotFound):
        service.start("cfg_nope")


def test_artifact_detail_decodes_request_and_response(tmp_path):
    store = WebStore(tmp_path)
    service = GenerationService(store)
    config = save_config(store, _payload())
    started = service.start(config["id"])
    detail = _wait(started["generation_id"], service)
    artifact_id = detail["artifacts"][0]["id"]
    info = artifact_detail(store, started["generation_id"], artifact_id)
    assert info["request"]["hex"].startswith("00 01")
    assert info["response"] is not None
    assert info["request"]["view"]["fields"]


def test_artifact_detail_unknown_artifact_raises(tmp_path):
    store = WebStore(tmp_path)
    service = GenerationService(store)
    config = save_config(store, _payload())
    started = service.start(config["id"])
    _wait(started["generation_id"], service)
    with pytest.raises(NotFound):
        artifact_detail(store, started["generation_id"], "nope")
```

- [ ] **Step 2: 跑测试确认失败**

Run: `python3 -m pytest tests/test_web_service.py -q`
Expected: FAIL —— `ModuleNotFoundError: No module named 'icsgen.web.models'`

- [ ] **Step 3: 实现请求模型**

创建 `icsgen/web/models.py`：

```python
"""Web 层的请求体模型。

只依赖 pydantic —— 服务层要用它们，HTTP 层也要用它们。
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class OperationInput(BaseModel):
    """表单里的一条操作选择。"""

    op: str
    variant: str = "normal"
    params: dict[str, Any] = Field(default_factory=dict)
    count: int = 1


class ConfigPayload(BaseModel):
    """保存配置的请求体。"""

    name: str
    protocol: str = "modbus"
    transport: dict[str, Any] = Field(default_factory=dict)
    operations: list[OperationInput]


class GenerationPayload(BaseModel):
    """发起生成的请求体。"""

    config_id: str
```

- [ ] **Step 4: 实现服务层**

创建 `icsgen/web/service.py`：

```python
"""Web 层的服务逻辑：协议查询、配置保存、生成调度、产物读取与预览。

这一层不 import FastAPI —— 业务逻辑可以脱离 HTTP 单独测试。
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..generator import build_dataset
from ..protocols.base import BuildContext
from ..protocols.registry import available_protocols, get_adapter, get_catalog
from ..spec.loader import ScenarioOperationModel, validate_operations
from ..spec.model import Operation, Scenario, Variant
from .models import ConfigPayload, OperationInput
from .store import WebStore

#: 单个操作的交互数量上限
MAX_COUNT_PER_OPERATION = 1000
#: 一次生成的总交互数量上限
MAX_TOTAL_COUNT = 5000


class WebError(ValueError):
    """Web 层请求不合法。"""


class NotFound(WebError):
    """目标不存在。"""


class AlreadyGenerated(WebError):
    """该配置已生成过。"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def list_protocols() -> list[dict[str, Any]]:
    """协议列表：名称、说明、传输、操作类型数与覆盖条目数。"""
    items = []
    for info in available_protocols():
        catalog = get_catalog(info.name)
        items.append(
            {
                "name": info.name,
                "summary": info.summary,
                "transports": list(info.transports),
                "operation_count": catalog.count(),
                "coverage_count": catalog.coverage_count(),
            }
        )
    return items


def list_operations(protocol: str) -> list[dict[str, Any]]:
    """操作类型列表：名称、说明、功能码、可用变体与参数 schema。"""
    catalog = get_catalog(protocol)
    return [
        {
            "name": entry.name,
            "summary": entry.summary,
            "layout": entry.layout,
            "func_code": entry.func_code,
            "variants": list(entry.variants),
            "params": entry.params,
        }
        for entry in catalog.operations.values()
    ]


def _check_counts(operations: list[OperationInput]) -> None:
    """校验交互数量：单操作与总量各有上限。"""
    total = 0
    for index, item in enumerate(operations):
        if item.count < 1:
            raise WebError(f"第 {index} 条操作的交互数量必须不小于 1")
        if item.count > MAX_COUNT_PER_OPERATION:
            raise WebError(
                f"第 {index} 条操作的交互数量 {item.count} 超过单操作上限 "
                f"{MAX_COUNT_PER_OPERATION}"
            )
        total += item.count
    if total > MAX_TOTAL_COUNT:
        raise WebError(f"交互总数 {total} 超过总量上限 {MAX_TOTAL_COUNT}")


def save_config(store: WebStore, payload: ConfigPayload) -> dict[str, Any]:
    """保存一条配置记录。记录落盘后不可修改、不可删除。"""
    if not payload.operations:
        raise WebError("至少要选择一条操作")
    catalog = get_catalog(payload.protocol)
    items = []
    for index, item in enumerate(payload.operations):
        try:
            variant = Variant(item.variant)
        except ValueError as exc:
            raise WebError(f"第 {index} 条操作的变体 {item.variant!r} 不合法") from exc
        items.append(
            ScenarioOperationModel(op=item.op, params=item.params, variant=variant)
        )
    validate_operations(catalog, items, context="提交的操作")
    _check_counts(payload.operations)
    record = {
        "id": f"cfg_{uuid.uuid4().hex[:12]}",
        "name": payload.name,
        # 本期没有用户维度，字段位先占住，将来加用户不用改存储格式（spec §17）
        "owner": None,
        "protocol": payload.protocol,
        "transport": payload.transport,
        "operations": [item.model_dump() for item in payload.operations],
        "created_at": _now(),
    }
    return store.save_config(record)


def build_scenario(config: dict[str, Any]) -> Scenario:
    """把一条配置记录展开成场景：每个操作按 count 重复。"""
    operations: list[Operation] = []
    for item in config.get("operations", []):
        operation = Operation(
            op=item["op"],
            params=item.get("params", {}),
            variant=Variant(item.get("variant", "normal")),
        )
        for _ in range(int(item.get("count", 1))):
            operations.append(operation)
    return Scenario(
        name=config.get("name", "web"),
        transport=config.get("transport", {}),
        operations=tuple(operations),
    )


class GenerationService:
    """发起生成任务并跟踪进度。"""

    def __init__(self, store: WebStore) -> None:
        self.store = store
        self._jobs: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def start(self, config_id: str) -> dict[str, Any]:
        """发起一次生成。同一配置只能生成一次。"""
        config = self.store.get_config(config_id)
        if config is None:
            raise NotFound(f"配置记录 {config_id!r} 不存在")
        existing = self.store.generation_for_config(config_id)
        if existing is not None:
            raise AlreadyGenerated(f"该配置已生成过（{existing}），不能重复生成")
        generation_id = f"gen_{uuid.uuid4().hex[:12]}"
        output_dir = self.store.generation_dir(generation_id)
        self.store.append_event(
            {
                "type": "generation_started",
                "generation_id": generation_id,
                "config_id": config_id,
                "config_name": config.get("name"),
                "output_dir": str(output_dir),
                "created_at": _now(),
            }
        )
        job = {
            "generation_id": generation_id,
            "done": 0,
            "total": 0,
            "phase": "building",
            "error": None,
        }
        with self._lock:
            self._jobs[generation_id] = job
        thread = threading.Thread(
            target=self._run, args=(config, generation_id, output_dir, job), daemon=True
        )
        thread.start()
        return {"generation_id": generation_id, "status": "running"}

    def _run(
        self,
        config: dict[str, Any],
        generation_id: str,
        output_dir: Path,
        job: dict[str, Any],
    ) -> None:
        started = time.monotonic()
        try:
            scenario = build_scenario(config)
            adapter = get_adapter(config["protocol"])

            def on_progress(done: int, total: int) -> None:
                job["done"] = done
                job["total"] = total
                if done >= total:
                    job["phase"] = "writing"

            build_dataset(
                scenario, adapter, output_dir, name=generation_id, on_progress=on_progress
            )
            manifest = json.loads(
                (output_dir / "manifest.json").read_text(encoding="utf-8")
            )
            packet_count = sum(
                entry.get("pcap_frame_count", 0) for entry in manifest["artifacts"]
            )
            self.store.append_event(
                {
                    "type": "generation_succeeded",
                    "generation_id": generation_id,
                    "artifact_count": len(manifest["artifacts"]),
                    "packet_count": packet_count,
                    "duration_ms": int((time.monotonic() - started) * 1000),
                    "finished_at": _now(),
                }
            )
            job["phase"] = "done"
        except Exception as exc:  # 生成失败要落成事件，不能让线程静默死掉
            job["error"] = str(exc)
            job["phase"] = "failed"
            self.store.append_event(
                {
                    "type": "generation_failed",
                    "generation_id": generation_id,
                    "error": str(exc),
                    "finished_at": _now(),
                }
            )

    def state(self, generation_id: str) -> dict[str, Any] | None:
        """进行中任务的内存状态；已完成的任务返回 None。"""
        with self._lock:
            job = self._jobs.get(generation_id)
            return dict(job) if job else None


def read_manifest(store: WebStore, generation_id: str) -> dict[str, Any] | None:
    """读生成目录的 manifest；数据集尚未写完或不存在时返回 None。"""
    path = store.generation_dir(generation_id) / "manifest.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _artifact_summaries(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """产物清单：页面上要显示的字段。"""
    return [
        {
            "id": entry["id"],
            "op": entry["op"],
            "variant": entry["variant"],
            "tier": entry["tier"],
            "protocol": entry["protocol"],
            "transport": entry["transport"],
            "len": entry["len"],
            "sha256": entry["sha256"],
            "has_response": "resp_len" in entry,
            "pcap_file": entry.get("pcap_file"),
            "pcap_index": entry.get("pcap_index"),
        }
        for entry in manifest["artifacts"]
    ]


def _percent(done: int, total: int, phase: str) -> float:
    """两阶段进度：生成帧占 0–85，写盘占 85–100。"""
    if phase == "done":
        return 100.0
    if total <= 0:
        return 0.0
    if phase == "writing":
        return 85.0
    return round(done / total * 85, 1)


def generation_detail(
    store: WebStore, service: GenerationService, generation_id: str
) -> dict[str, Any]:
    """生成任务的完整状态：事件折叠出的状态 + 内存进度 + 产物清单。"""
    record = next(
        (item for item in store.list_generations() if item["id"] == generation_id), None
    )
    if record is None:
        raise NotFound(f"生成记录 {generation_id!r} 不存在")
    detail = dict(record)
    job = service.state(generation_id)
    detail["done"] = job["done"] if job else 0
    detail["total"] = job["total"] if job else 0
    detail["phase"] = job["phase"] if job else "done"
    detail["percent"] = _percent(detail["done"], detail["total"], detail["phase"])
    manifest = read_manifest(store, generation_id)
    detail["artifacts"] = _artifact_summaries(manifest) if manifest else []
    return detail


def _view_dict(view: Any) -> dict[str, Any]:
    return {
        "summary": view.summary,
        "fields": [{"name": field.name, "value": field.value} for field in view.fields],
        "is_exception": view.is_exception,
        "exception_code": view.exception_code,
    }


def artifact_detail(
    store: WebStore, generation_id: str, artifact_id: str
) -> dict[str, Any]:
    """一条产物的请求/响应帧 hex 与协议级解析结果。"""
    manifest = read_manifest(store, generation_id)
    if manifest is None:
        raise NotFound(f"生成记录 {generation_id!r} 的数据集不存在")
    entry = next(
        (item for item in manifest["artifacts"] if item["id"] == artifact_id), None
    )
    if entry is None:
        raise NotFound(f"产物 {artifact_id!r} 不存在")
    frames_dir = (
        store.generation_dir(generation_id)
        / entry["tier"]
        / f"{entry['protocol']}_{entry['transport']}"
        / "frames"
    )
    request_path = frames_dir / f"{artifact_id}.bin"
    if not request_path.exists():
        raise NotFound(f"产物 {artifact_id!r} 的请求帧文件不存在")
    request = request_path.read_bytes()
    response_path = frames_dir / f"{artifact_id}.resp.bin"
    response = response_path.read_bytes() if response_path.exists() else None
    adapter = get_adapter(entry["protocol"])
    ctx = BuildContext(transport=entry["transport"], unit_id=0xFF)
    request_view = adapter.inspect(entry["op"], request, ctx, "request")
    response_view = (
        adapter.inspect(entry["op"], response, ctx, "response") if response else None
    )
    return {
        "id": artifact_id,
        "op": entry["op"],
        "variant": entry["variant"],
        "tier": entry["tier"],
        "request": {"hex": request.hex(" "), "view": _view_dict(request_view)},
        "response": (
            {"hex": response.hex(" "), "view": _view_dict(response_view)}
            if response
            else None
        ),
    }
```

- [ ] **Step 5: 跑测试确认通过**

Run: `python3 -m pytest tests/test_web_service.py -q`
Expected: 全部通过（16 个用例）

- [ ] **Step 6: 跑全量测试**

Run: `python3 -m pytest -q -W error`
Expected: 全部通过

- [ ] **Step 7: 提交**

```bash
git add icsgen/web/models.py icsgen/web/service.py tests/test_web_service.py
git commit -m "feat: 新增 Web 服务层，配置保存、生成调度与产物预览"
```

---

### Task 7: HTTP 层（应用工厂与 JSON API）

**Files:**
- Create: `icsgen/web/app.py`
- Test: `tests/test_web_api.py`

**Interfaces:**
- Consumes: Task 5 的 `WebStore`、Task 6 的服务层函数与异常类
- Produces:
  - `icsgen.web.app.create_app(root: Path | None = None) -> FastAPI`
  - 路由：`GET /api/protocols`、`GET /api/protocols/{protocol}/operations`、`GET /api/configs`、`POST /api/configs`、`GET /api/generations`、`POST /api/generations`、`GET /api/generations/{id}`、`GET /api/generations/{id}/artifacts/{artifact_id}`、`GET /api/generations/{id}/download/{file_path:path}`、`GET /api/generations/{id}/archive.zip`
  - 页面路由：`GET /`、`GET /records`、`GET /generations/{id}`（模板在 Task 8 落地，本任务先返回占位模板）

- [ ] **Step 1: 写失败的测试**

创建 `tests/test_web_api.py`：

```python
"""HTTP 层：JSON API 与页面路由。"""

import pytest
from fastapi.testclient import TestClient

from icsgen.web.app import create_app


@pytest.fixture()
def client(tmp_path):
    return TestClient(create_app(tmp_path))


def test_api_protocols(client):
    response = client.get("/api/protocols")
    assert response.status_code == 200
    data = response.json()
    assert data[0]["name"] == "modbus"
    assert data[0]["operation_count"] == 41
    assert data[0]["coverage_count"] == 192


def test_api_operations(client):
    response = client.get("/api/protocols/modbus/operations")
    assert response.status_code == 200
    operations = response.json()
    assert len(operations) == 41
    entry = next(o for o in operations if o["name"] == "modbus.read_holding_registers")
    assert entry["params"]["quantity"]["default"] == 3


def test_api_operations_unknown_protocol(client):
    assert client.get("/api/protocols/cip/operations").status_code == 404


def test_api_save_and_list_configs(client):
    payload = {
        "name": "接口配置",
        "protocol": "modbus",
        "transport": {"kind": "tcp"},
        "operations": [
            {
                "op": "modbus.read_holding_registers",
                "variant": "normal",
                "params": {"start_addr": 0, "quantity": 3},
                "count": 2,
            }
        ],
    }
    response = client.post("/api/configs", json=payload)
    assert response.status_code == 201
    config_id = response.json()["id"]
    listing = client.get("/api/configs").json()
    assert any(item["id"] == config_id for item in listing)


def test_api_save_config_rejects_bad_param(client):
    payload = {
        "name": "坏参数",
        "protocol": "modbus",
        "transport": {"kind": "tcp"},
        "operations": [
            {
                "op": "modbus.read_holding_registers",
                "variant": "normal",
                "params": {"quantity": 9999},
                "count": 1,
            }
        ],
    }
    response = client.post("/api/configs", json=payload)
    assert response.status_code == 422
    assert "参数校验失败" in response.json()["detail"]


def test_api_generation_lifecycle(client):
    payload = {
        "name": "生成配置",
        "protocol": "modbus",
        "transport": {"kind": "tcp"},
        "operations": [
            {
                "op": "modbus.read_holding_registers",
                "variant": "normal",
                "params": {"start_addr": 0, "quantity": 3},
                "count": 2,
            }
        ],
    }
    config_id = client.post("/api/configs", json=payload).json()["id"]
    started = client.post("/api/generations", json={"config_id": config_id})
    assert started.status_code == 201
    generation_id = started.json()["generation_id"]

    import time

    deadline = time.monotonic() + 20
    detail = {}
    while time.monotonic() < deadline:
        detail = client.get(f"/api/generations/{generation_id}").json()
        if detail["status"] != "running":
            break
        time.sleep(0.05)
    assert detail["status"] == "succeeded"
    assert detail["artifact_count"] == 2
    assert len(detail["artifacts"]) == 2
    assert detail["percent"] == 100.0

    artifact_id = detail["artifacts"][0]["id"]
    preview = client.get(f"/api/generations/{generation_id}/artifacts/{artifact_id}").json()
    assert preview["request"]["hex"]
    assert preview["request"]["view"]["fields"]

    listing = client.get("/api/generations").json()
    assert any(item["id"] == generation_id for item in listing)


def test_api_generation_twice_returns_conflict(client):
    payload = {
        "name": "只能一次",
        "protocol": "modbus",
        "transport": {"kind": "tcp"},
        "operations": [
            {
                "op": "modbus.read_holding_registers",
                "variant": "normal",
                "params": {"quantity": 3},
                "count": 1,
            }
        ],
    }
    config_id = client.post("/api/configs", json=payload).json()["id"]
    assert client.post("/api/generations", json={"config_id": config_id}).status_code == 201
    conflict = client.post("/api/generations", json={"config_id": config_id})
    assert conflict.status_code == 409


def test_api_generation_unknown_config_returns_404(client):
    assert client.post("/api/generations", json={"config_id": "cfg_nope"}).status_code == 404


def test_api_has_no_delete_or_update_routes(client):
    """记录不可删改 —— 不存在任何删除或修改记录的路由。"""
    paths = {route.path for route in client.app.routes}
    for path in paths:
        assert "configs" not in path or path == "/api/configs"
    methods = {
        (route.path, method)
        for route in client.app.routes
        for method in getattr(route, "methods", set())
    }
    assert ("/api/configs", "DELETE") not in methods
    assert ("/api/configs", "PUT") not in methods
    assert ("/api/configs", "PATCH") not in methods
    assert ("/api/generations", "DELETE") not in methods


def test_api_download_returns_file(client):
    payload = {
        "name": "下载配置",
        "protocol": "modbus",
        "transport": {"kind": "tcp"},
        "operations": [
            {
                "op": "modbus.read_holding_registers",
                "variant": "normal",
                "params": {"quantity": 3},
                "count": 1,
            }
        ],
    }
    config_id = client.post("/api/configs", json=payload).json()["id"]
    generation_id = client.post("/api/generations", json={"config_id": config_id}).json()[
        "generation_id"
    ]
    import time

    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        detail = client.get(f"/api/generations/{generation_id}").json()
        if detail["status"] != "running":
            break
        time.sleep(0.05)
    artifact = detail["artifacts"][0]
    response = client.get(
        f"/api/generations/{generation_id}/download/"
        f"{artifact['tier']}/{artifact['protocol']}_{artifact['transport']}/frames/"
        f"{artifact['id']}.bin"
    )
    assert response.status_code == 200
    assert response.content.startswith(b"\x00\x01")


def test_api_archive_downloads_zip(client):
    payload = {
        "name": "打包配置",
        "protocol": "modbus",
        "transport": {"kind": "tcp"},
        "operations": [
            {
                "op": "modbus.read_holding_registers",
                "variant": "normal",
                "params": {"quantity": 3},
                "count": 1,
            }
        ],
    }
    config_id = client.post("/api/configs", json=payload).json()["id"]
    generation_id = client.post("/api/generations", json={"config_id": config_id}).json()[
        "generation_id"
    ]
    import time

    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        detail = client.get(f"/api/generations/{generation_id}").json()
        if detail["status"] != "running":
            break
        time.sleep(0.05)
    response = client.get(f"/api/generations/{generation_id}/archive.zip")
    assert response.status_code == 200
    assert response.content[:2] == b"PK"


def test_pages_render(client):
    assert client.get("/").status_code == 200
    assert client.get("/records").status_code == 200
```

- [ ] **Step 2: 跑测试确认失败**

Run: `python3 -m pytest tests/test_web_api.py -q`
Expected: FAIL —— `ModuleNotFoundError: No module named 'icsgen.web.app'`

- [ ] **Step 3: 实现应用工厂**

创建 `icsgen/web/app.py`：

```python
"""FastAPI 应用：JSON API 与页面路由。

路由层只做参数解析、结果呈现与错误映射，业务逻辑在 service.py。
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..paths import DATASETS_DIR
from ..spec.loader import ScenarioError
from .models import ConfigPayload, GenerationPayload
from .service import (
    AlreadyGenerated,
    GenerationService,
    NotFound,
    WebError,
    artifact_detail,
    generation_detail,
    list_operations,
    list_protocols,
    read_manifest,
    save_config,
)
from .store import WebStore

#: 模板与静态资源目录
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"


def default_root() -> Path:
    """账本与生成目录的默认位置。"""
    return DATASETS_DIR / "web"


def create_app(root: Path | None = None) -> FastAPI:
    """构造 Web 应用。root 是账本与生成目录的存放位置。"""
    store = WebStore(Path(root) if root is not None else default_root())
    service = GenerationService(store)
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    app = FastAPI(title="icsgen Web 交互界面", version="0.1.0")
    app.state.store = store
    app.state.service = service
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    def _fail(exc: Exception) -> HTTPException:
        """把服务层异常映射成 HTTP 状态码。"""
        if isinstance(exc, NotFound):
            return HTTPException(status_code=404, detail=str(exc))
        if isinstance(exc, AlreadyGenerated):
            return HTTPException(status_code=409, detail=str(exc))
        if isinstance(exc, (WebError, ScenarioError)):
            return HTTPException(status_code=422, detail=str(exc))
        return HTTPException(status_code=500, detail=str(exc))

    # ---- JSON API ----
    @app.get("/api/protocols")
    def api_protocols() -> list[dict[str, Any]]:
        return list_protocols()

    @app.get("/api/protocols/{protocol}/operations")
    def api_operations(protocol: str) -> list[dict[str, Any]]:
        try:
            return list_operations(protocol)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/configs")
    def api_configs() -> list[dict[str, Any]]:
        return store.list_configs()

    @app.post("/api/configs", status_code=201)
    def api_save_config(payload: ConfigPayload) -> dict[str, Any]:
        try:
            return save_config(store, payload)
        except (WebError, ScenarioError) as exc:
            raise _fail(exc) from exc

    @app.get("/api/generations")
    def api_generations() -> list[dict[str, Any]]:
        return store.list_generations()

    @app.post("/api/generations", status_code=201)
    def api_start_generation(payload: GenerationPayload) -> dict[str, Any]:
        try:
            return service.start(payload.config_id)
        except WebError as exc:
            raise _fail(exc) from exc

    @app.get("/api/generations/{generation_id}")
    def api_generation(generation_id: str) -> dict[str, Any]:
        try:
            return generation_detail(store, service, generation_id)
        except WebError as exc:
            raise _fail(exc) from exc

    @app.get("/api/generations/{generation_id}/artifacts/{artifact_id}")
    def api_artifact(generation_id: str, artifact_id: str) -> dict[str, Any]:
        try:
            return artifact_detail(store, generation_id, artifact_id)
        except WebError as exc:
            raise _fail(exc) from exc

    @app.get("/api/generations/{generation_id}/download/{file_path:path}")
    def api_download(generation_id: str, file_path: str) -> FileResponse:
        base = store.generation_dir(generation_id).resolve()
        target = (base / file_path).resolve()
        if not target.is_relative_to(base) or not target.is_file():
            raise HTTPException(status_code=404, detail="文件不存在")
        return FileResponse(target, filename=target.name)

    @app.get("/api/generations/{generation_id}/archive.zip")
    def api_archive(generation_id: str) -> FileResponse:
        base = store.generation_dir(generation_id)
        if not (base / "manifest.json").exists():
            raise HTTPException(status_code=404, detail="数据集不存在")
        archive = base.parent / f"{generation_id}.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
            for path in sorted(base.rglob("*")):
                if path.is_file():
                    bundle.write(path, Path(generation_id) / path.relative_to(base))
        return FileResponse(archive, filename=f"{generation_id}.zip")

    # ---- 页面 ----
    @app.get("/")
    def page_index(request: Request):
        return templates.TemplateResponse(
            request, "index.html", {"protocols": list_protocols()}
        )

    @app.get("/records")
    def page_records(request: Request):
        generations = store.list_generations()
        by_config = store.generations_by_config()
        configs = [
            {**config, "generation_id": by_config.get(config.get("id"))}
            for config in store.list_configs()
        ]
        return templates.TemplateResponse(
            request, "records.html", {"configs": configs, "generations": generations}
        )

    @app.get("/generations/{generation_id}")
    def page_generation(request: Request, generation_id: str):
        try:
            detail = generation_detail(store, service, generation_id)
        except WebError as exc:
            raise _fail(exc) from exc
        return templates.TemplateResponse(
            request, "generation.html", {"generation": detail}
        )

    return app
```

**注意**：`read_manifest` 导入后在 `api_download` 里没用到 —— 从导入列表里删掉它，避免 lint 抱怨。

**注意**：Task 8 之前还没有模板，本任务的 `test_pages_render` 会因模板缺失而失败。**先创建三个占位模板**，Task 8 再替换为正式模板：

`icsgen/web/templates/index.html`：

```html
<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>工作台</title></head>
<body><h1>工作台</h1><p>模板待实现</p></body></html>
```

`icsgen/web/templates/records.html`：

```html
<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>记录</title></head>
<body><h1>记录</h1><p>模板待实现</p></body></html>
```

`icsgen/web/templates/generation.html`：

```html
<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>生成详情</title></head>
<body><h1>生成详情</h1><p>模板待实现</p></body></html>
```

并创建 `icsgen/web/static/` 目录与一个空占位 `app.css`（`StaticFiles` 要求目录存在）：

```css
/* 样式待实现 */
```

- [ ] **Step 4: 跑测试确认通过**

Run: `python3 -m pytest tests/test_web_api.py -q`
Expected: 全部通过（13 个用例）

- [ ] **Step 5: 跑全量测试**

Run: `python3 -m pytest -q -W error`
Expected: 全部通过

- [ ] **Step 6: 提交**

```bash
git add icsgen/web/app.py icsgen/web/templates icsgen/web/static tests/test_web_api.py
git commit -m "feat: 新增 Web HTTP 层，暴露协议查询、配置与生成的 JSON API"
```

---

### Task 8: 页面模板与静态资源

**Files:**
- Create: `icsgen/web/templates/base.html`（替换占位）
- Modify: `icsgen/web/templates/index.html`、`records.html`、`generation.html`
- Create: `icsgen/web/static/app.js`
- Modify: `icsgen/web/static/app.css`
- Test: `tests/test_web_pages.py`

**Interfaces:**
- Consumes: Task 6/7 的 JSON API（`/api/protocols`、`/api/protocols/{p}/operations`、`/api/configs`、`/api/generations`、`/api/generations/{id}/artifacts/{aid}`）
- Produces: 页面 `GET /`、`GET /records`、`GET /generations/{id}` 的正式渲染

- [ ] **Step 1: 写失败的测试**

创建 `tests/test_web_pages.py`：

```python
"""页面渲染：工作台、记录页与生成详情。"""

import time

from fastapi.testclient import TestClient

from icsgen.web.app import create_app


def _client(tmp_path):
    return TestClient(create_app(tmp_path))


def _generate(client, count=1):
    payload = {
        "name": "页面配置",
        "protocol": "modbus",
        "transport": {"kind": "tcp"},
        "operations": [
            {
                "op": "modbus.read_holding_registers",
                "variant": "normal",
                "params": {"start_addr": 0, "quantity": 3},
                "count": count,
            }
        ],
    }
    config_id = client.post("/api/configs", json=payload).json()["id"]
    generation_id = client.post("/api/generations", json={"config_id": config_id}).json()[
        "generation_id"
    ]
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        detail = client.get(f"/api/generations/{generation_id}").json()
        if detail["status"] != "running":
            break
        time.sleep(0.05)
    return generation_id


def test_workbench_lists_protocol_and_operations(tmp_path):
    client = _client(tmp_path)
    body = client.get("/").text
    assert "modbus" in body
    assert "41" in body
    assert "/static/app.js" in body


def test_records_page_shows_saved_config(tmp_path):
    client = _client(tmp_path)
    payload = {
        "name": "记录里的配置",
        "protocol": "modbus",
        "transport": {"kind": "tcp"},
        "operations": [
            {
                "op": "modbus.read_holding_registers",
                "variant": "normal",
                "params": {"quantity": 3},
                "count": 4,
            }
        ],
    }
    client.post("/api/configs", json=payload)
    body = client.get("/records").text
    assert "记录里的配置" in body
    assert "不可修改" in body


def test_generation_page_shows_artifacts_and_download_links(tmp_path):
    client = _client(tmp_path)
    generation_id = _generate(client)
    body = client.get(f"/generations/{generation_id}").text
    assert "modbus.read_holding_registers" in body
    assert "archive.zip" in body
    assert ".bin" in body


def test_generation_page_shows_progress_while_running(tmp_path):
    client = _client(tmp_path)
    payload = {
        "name": "进度",
        "protocol": "modbus",
        "transport": {"kind": "tcp"},
        "operations": [
            {
                "op": "modbus.read_holding_registers",
                "variant": "normal",
                "params": {"quantity": 3},
                "count": 1,
            }
        ],
    }
    config_id = client.post("/api/configs", json=payload).json()["id"]
    generation_id = client.post("/api/generations", json={"config_id": config_id}).json()[
        "generation_id"
    ]
    body = client.get(f"/generations/{generation_id}").text
    assert "progress" in body or "进度" in body
```

- [ ] **Step 2: 跑测试确认失败**

Run: `python3 -m pytest tests/test_web_pages.py -q`
Expected: FAIL —— 占位模板不含协议名与产物信息

- [ ] **Step 3: 实现 base.html**

创建 `icsgen/web/templates/base.html`：

```html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{% block title %}icsgen 工控流量生成器{% endblock %}</title>
  <link rel="stylesheet" href="/static/app.css">
</head>
<body>
<header class="topbar">
  <span class="brand">icsgen</span>
  <nav>
    <a href="/">工作台</a>
    <a href="/records">记录</a>
  </nav>
</header>
<main>
{% block content %}{% endblock %}
</main>
<script src="/static/app.js"></script>
</body>
</html>
```

- [ ] **Step 4: 实现 index.html（工作台）**

创建 `icsgen/web/templates/index.html`：

```html
{% extends "base.html" %}
{% block title %}工作台 — icsgen{% endblock %}
{% block content %}
<h1>工作台</h1>

<section class="panel">
  <h2>协议与传输</h2>
  <label class="field">
    <span>协议</span>
    <select id="protocol">
      {% for protocol in protocols %}
      <option value="{{ protocol.name }}">
        {{ protocol.name }} — {{ protocol.summary }}（{{ protocol.operation_count }} 个操作类型 / {{ protocol.coverage_count }} 条覆盖条目）
      </option>
      {% endfor %}
    </select>
  </label>
  <label class="field">
    <span>传输</span>
    <select id="transport"></select>
  </label>
</section>

<section class="panel">
  <h2>操作类型</h2>
  <input id="op-filter" type="search" placeholder="按名称或说明过滤">
  <div id="op-list" class="op-list"></div>
</section>

<section class="panel">
  <h2>已选操作</h2>
  <div id="selected"></div>
</section>

<section class="panel">
  <h2>保存与生成</h2>
  <label class="field">
    <span>配置名称</span>
    <input id="config-name" type="text" placeholder="例如：读保持寄存器压测">
  </label>
  <div class="actions">
    <button type="button" id="save">保存配置</button>
    <button type="button" id="generate" class="primary">保存并生成数据包</button>
  </div>
  <p id="message" class="message"></p>
</section>
{% endblock %}
```

- [ ] **Step 5: 实现 records.html（记录页）**

创建 `icsgen/web/templates/records.html`：

```html
{% extends "base.html" %}
{% block title %}记录 — icsgen{% endblock %}
{% block content %}
<h1>记录</h1>
<p class="note">配置记录与生成记录都是只读的：保存后不可修改，也不可删除。</p>

<h2>配置记录</h2>
<table>
  <thead>
    <tr><th>名称</th><th>协议</th><th>操作数</th><th>交互总数</th><th>保存时间</th><th>生成</th></tr>
  </thead>
  <tbody>
  {% for config in configs %}
    <tr>
      <td>{{ config.name }}</td>
      <td>{{ config.protocol }}</td>
      <td>{{ config.operations | length }}</td>
      <td>{{ config.operations | sum(attribute='count') }}</td>
      <td>{{ config.created_at }}</td>
      <td>
        {% if config.generation_id %}
        <a href="/generations/{{ config.generation_id }}">{{ config.generation_id }}</a>
        {% else %}
        未生成
        {% endif %}
      </td>
    </tr>
  {% else %}
    <tr><td colspan="6">还没有保存过配置。</td></tr>
  {% endfor %}
  </tbody>
</table>

<h2>生成记录</h2>
<table>
  <thead>
    <tr><th>生成</th><th>配置</th><th>状态</th><th>产物数</th><th>包数</th><th>耗时</th><th>开始时间</th></tr>
  </thead>
  <tbody>
  {% for generation in generations %}
    <tr>
      <td><a href="/generations/{{ generation.id }}">{{ generation.id }}</a></td>
      <td>{{ generation.config_name }}</td>
      <td>
        {{ generation.status }}
        {% if generation.error %}<span class="error">— {{ generation.error }}</span>{% endif %}
      </td>
      <td>{{ generation.artifact_count if generation.artifact_count is not none else "-" }}</td>
      <td>{{ generation.packet_count if generation.packet_count is not none else "-" }}</td>
      <td>{{ generation.duration_ms if generation.duration_ms is not none else "-" }}</td>
      <td>{{ generation.created_at }}</td>
    </tr>
  {% else %}
    <tr><td colspan="7">还没有生成记录。</td></tr>
  {% endfor %}
  </tbody>
</table>
{% endblock %}
```

- [ ] **Step 6: 实现 generation.html（生成详情）**

创建 `icsgen/web/templates/generation.html`：

```html
{% extends "base.html" %}
{% block title %}生成 {{ generation.id }} — icsgen{% endblock %}
{% block content %}
<h1>生成 {{ generation.id }}</h1>
<p class="note">配置：{{ generation.config_name }}（{{ generation.config_id }}）</p>

<div id="generation" data-generation-id="{{ generation.id }}" data-status="{{ generation.status }}">
{% if generation.status == "running" %}
  <div class="progress"><div id="bar" class="bar" style="width: {{ generation.percent }}%"></div></div>
  <p id="progress-label">{{ generation.done }} / {{ generation.total }}（{{ generation.percent }}%）</p>
{% else %}
  <p>状态：{{ generation.status }}{% if generation.error %} — <span class="error">{{ generation.error }}</span>{% endif %}</p>
{% endif %}
</div>

{% if generation.status == "succeeded" %}
<section class="panel">
  <h2>产物（{{ generation.artifacts | length }} 条）</h2>
  <p>
    <a href="/api/generations/{{ generation.id }}/archive.zip">下载整个数据集（zip）</a>
  </p>
  <table>
    <thead>
      <tr><th>操作</th><th>变体</th><th>层</th><th>长度</th><th>pcap 位置</th><th>下载</th></tr>
    </thead>
    <tbody>
    {% for item in generation.artifacts %}
      <tr data-artifact="{{ item.id }}">
        <td>{{ item.op }}</td>
        <td>{{ item.variant }}</td>
        <td>{{ item.tier }}</td>
        <td>{{ item.len }}</td>
        <td>{{ item.pcap_file }} #{{ item.pcap_index }}</td>
        <td>
          <a href="/api/generations/{{ generation.id }}/download/{{ item.tier }}/{{ item.protocol }}_{{ item.transport }}/frames/{{ item.id }}.bin">.bin</a>
          <a href="/api/generations/{{ generation.id }}/download/{{ item.tier }}/{{ item.protocol }}_{{ item.transport }}/frames/{{ item.id }}.hex">.hex</a>
        </td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
</section>

<section class="panel">
  <h2>帧预览</h2>
  <p class="note">点击上面任意一行查看该次交互的请求与响应帧。</p>
  <div id="detail"></div>
</section>
{% endif %}
{% endblock %}
```

- [ ] **Step 7: 实现 app.js**

创建 `icsgen/web/static/app.js`：

```javascript
/* 工作台表单与进度轮询。无框架，直接用 fetch 与 DOM API。 */

(function () {
  "use strict";

  const workbench = document.getElementById("workbench");

  if (workbench) {
    initWorkbench();
  }

  const generation = document.getElementById("generation");

  if (generation) {
    initGeneration(generation);
  }

  function initWorkbench() {
    const protocolSelect = document.getElementById("protocol");
    const transportSelect = document.getElementById("transport");
    const opList = document.getElementById("op-list");
    const opFilter = document.getElementById("op-filter");
    const selectedBox = document.getElementById("selected");
    const nameInput = document.getElementById("config-name");
    const message = document.getElementById("message");

    let operations = [];
    const selected = new Map();

    protocolSelect.addEventListener("change", load);
    opFilter.addEventListener("input", renderOperations);
    document.getElementById("save").addEventListener("click", saveConfig);
    document.getElementById("generate").addEventListener("click", generate);

    async function load() {
      const response = await fetch(
        "/api/protocols/" + protocolSelect.value + "/operations"
      );
      operations = await response.json();
      selected.clear();
      renderTransports();
      renderOperations();
      renderSelected();
    }

    function renderTransports() {
      const protocol = protocolSelect.value;
      transportSelect.innerHTML = "";
      const kinds = protocol === "modbus" ? ["tcp", "serial"] : ["tcp"];
      for (const kind of kinds) {
        const option = document.createElement("option");
        option.value = kind;
        option.textContent = kind === "serial" ? "serial（Modbus RTU）" : "tcp（Modbus TCP）";
        transportSelect.append(option);
      }
    }

    function renderOperations() {
      const keyword = opFilter.value.trim().toLowerCase();
      opList.innerHTML = "";
      for (const op of operations) {
        const haystack = (op.name + " " + op.summary).toLowerCase();
        if (keyword && haystack.indexOf(keyword) === -1) {
          continue;
        }
        const row = document.createElement("label");
        row.className = "op-row";
        const box = document.createElement("input");
        box.type = "checkbox";
        box.checked = selected.has(op.name);
        box.addEventListener("change", function () {
          if (box.checked) {
            selected.set(op.name, {
              op: op.name,
              variant: op.variants[0],
              params: defaultsOf(op),
              count: 1
            });
          } else {
            selected.delete(op.name);
          }
          renderSelected();
        });
        const text = document.createElement("span");
        const fc = op.func_code === null ? "" : " / FC" + op.func_code;
        text.textContent = op.summary + "（" + op.name + fc + "）";
        row.append(box, text);
        opList.append(row);
      }
    }

    function defaultsOf(op) {
      const params = {};
      const schema = op.params || {};
      for (const name of Object.keys(schema)) {
        if (schema[name].default !== undefined) {
          params[name] = schema[name].default;
        }
      }
      return params;
    }

    function renderSelected() {
      selectedBox.innerHTML = "";
      for (const [name, item] of selected) {
        const op = operations.find(function (candidate) {
          return candidate.name === name;
        });
        const block = document.createElement("div");
        block.className = "selected-op";

        const title = document.createElement("h3");
        title.textContent = op.summary + "（" + name + "）";
        block.append(title);

        const variant = document.createElement("select");
        for (const value of op.variants) {
          const option = document.createElement("option");
          option.value = value;
          option.textContent = value;
          option.selected = value === item.variant;
          variant.append(option);
        }
        variant.addEventListener("change", function () {
          item.variant = variant.value;
        });
        block.append(field("变体", variant));

        const schema = op.params || {};
        for (const param of Object.keys(schema)) {
          const spec = schema[param];
          const input = document.createElement("input");
          input.dataset.param = param;
          if (spec.type === "integer") {
            input.type = "number";
            input.step = 1;
            if (spec.minimum !== undefined) input.min = spec.minimum;
            if (spec.maximum !== undefined) input.max = spec.maximum;
          } else {
            input.type = "text";
            if (spec.type === "array") input.placeholder = "逗号分隔的整数";
          }
          input.value = formatValue(item.params[param], spec);
          input.addEventListener("change", function () {
            const parsed = parseValue(input.value, spec);
            if (parsed === undefined) {
              delete item.params[param];
            } else {
              item.params[param] = parsed;
            }
          });
          block.append(field(param, input));
        }

        const count = document.createElement("input");
        count.type = "number";
        count.min = 1;
        count.max = 1000;
        count.value = item.count;
        count.addEventListener("change", function () {
          item.count = Number(count.value) || 1;
        });
        block.append(field("交互数量", count));

        const remove = document.createElement("button");
        remove.type = "button";
        remove.textContent = "移除";
        remove.addEventListener("click", function () {
          selected.delete(name);
          renderOperations();
          renderSelected();
        });
        block.append(remove);

        selectedBox.append(block);
      }
    }

    function field(text, control) {
      const wrap = document.createElement("label");
      wrap.className = "field";
      const span = document.createElement("span");
      span.textContent = text;
      wrap.append(span, control);
      return wrap;
    }

    function formatValue(value, spec) {
      if (value === undefined || value === null) {
        return "";
      }
      if (spec.type === "array") {
        return Array.isArray(value) ? value.join(",") : String(value);
      }
      return String(value);
    }

    function parseValue(text, spec) {
      if (text === "") {
        return undefined;
      }
      if (spec.type === "array") {
        return text
          .split(",")
          .map(function (part) { return part.trim(); })
          .filter(function (part) { return part !== ""; })
          .map(Number);
      }
      if (spec.type === "integer") {
        return Number(text);
      }
      return text;
    }

    async function collect() {
      const operations = [];
      for (const item of selected.values()) {
        const params = {};
        for (const key of Object.keys(item.params)) {
          params[key] = item.params[key];
        }
        operations.push({
          op: item.op,
          variant: item.variant,
          params: params,
          count: item.count
        });
      }
      return {
        name: nameInput.value.trim() || "未命名配置",
        protocol: protocolSelect.value,
        transport: { kind: transportSelect.value },
        operations: operations
      };
    }

    async function saveConfig() {
      const response = await fetch("/api/configs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(await collect())
      });
      const data = await response.json();
      if (!response.ok) {
        message.textContent = data.detail || "保存失败";
        return null;
      }
      message.textContent = "已保存配置 " + data.id;
      return data;
    }

    async function generate() {
      const config = await saveConfig();
      if (!config) {
        return;
      }
      const response = await fetch("/api/generations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ config_id: config.id })
      });
      const data = await response.json();
      if (!response.ok) {
        message.textContent = data.detail || "生成失败";
        return;
      }
      window.location.href = "/generations/" + data.generation_id;
    }

    load();
  }

  function initGeneration(root) {
    const id = root.dataset.generationId;
    const bar = document.getElementById("bar");
    const label = document.getElementById("progress-label");
    const detail = document.getElementById("detail");
    const phases = { building: "生成帧", writing: "写盘", done: "完成", failed: "失败" };

    if (root.dataset.status === "running") {
      poll();
    }

    async function poll() {
      const response = await fetch("/api/generations/" + id);
      if (!response.ok) {
        return;
      }
      const data = await response.json();
      if (bar) {
        bar.style.width = data.percent + "%";
      }
      if (label) {
        label.textContent =
          (phases[data.phase] || data.phase) +
          " " + data.done + " / " + data.total +
          "（" + data.percent + "%）";
      }
      if (data.status === "running") {
        setTimeout(poll, 500);
      } else {
        window.location.reload();
      }
    }

    document.querySelectorAll("[data-artifact]").forEach(function (row) {
      row.addEventListener("click", async function () {
        const response = await fetch(
          "/api/generations/" + id + "/artifacts/" + row.dataset.artifact
        );
        if (!response.ok || !detail) {
          return;
        }
        const artifact = await response.json();
        detail.innerHTML = "";
        detail.append(frameBlock("请求帧", artifact.request));
        if (artifact.response) {
          detail.append(frameBlock("响应帧", artifact.response));
        }
      });
    });

    function frameBlock(title, frame) {
      const box = document.createElement("div");
      const heading = document.createElement("h3");
      heading.textContent = title + " — " + frame.view.summary;
      const hex = document.createElement("pre");
      hex.className = "hex";
      hex.textContent = frame.hex;
      const table = document.createElement("table");
      for (const field of frame.view.fields) {
        const row = document.createElement("tr");
        const name = document.createElement("th");
        name.textContent = field.name;
        const value = document.createElement("td");
        value.textContent = field.value;
        row.append(name, value);
        table.append(row);
      }
      box.append(heading, hex, table);
      return box;
    }
  }
})();
```

**注意**：`initWorkbench` 引用的元素 id 必须在 index.html 里存在 —— 给 index.html 的 `<body>` 加上 `id="workbench"`。修改 `base.html` 的 body 标签为：

```html
<body{% block bodyattrs %}{% endblock %}>
```

并在 index.html 顶部加：

```html
{% block bodyattrs %} id="workbench"{% endblock %}
```

- [ ] **Step 8: 实现 app.css**

创建 `icsgen/web/static/app.css`：

```css
/* icsgen Web 界面样式。 */

:root {
  --bg: #f6f7f9;
  --panel: #ffffff;
  --ink: #1d2129;
  --muted: #6b7280;
  --line: #e3e6ea;
  --accent: #2f6feb;
}

* { box-sizing: border-box; }

body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font: 14px/1.6 -apple-system, "Segoe UI", "Noto Sans CJK SC", sans-serif;
}

.topbar {
  display: flex;
  align-items: center;
  gap: 24px;
  padding: 12px 24px;
  background: var(--panel);
  border-bottom: 1px solid var(--line);
}

.brand { font-weight: 700; letter-spacing: 0.5px; }
.topbar a { color: var(--muted); text-decoration: none; margin-right: 16px; }
.topbar a:hover { color: var(--accent); }

main { max-width: 1080px; margin: 24px auto; padding: 0 24px; }

h1 { font-size: 22px; margin: 0 0 16px; }
h2 { font-size: 16px; margin: 0 0 12px; }
h3 { font-size: 14px; margin: 0 0 8px; }

.panel {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 16px 20px;
  margin-bottom: 16px;
}

.note { color: var(--muted); }

.field { display: inline-flex; align-items: center; gap: 8px; margin: 0 16px 8px 0; }
.field > span { color: var(--muted); min-width: 64px; }

input, select {
  padding: 5px 8px;
  border: 1px solid var(--line);
  border-radius: 4px;
  font: inherit;
  background: #fff;
}

button {
  padding: 6px 14px;
  border: 1px solid var(--line);
  border-radius: 4px;
  background: #fff;
  font: inherit;
  cursor: pointer;
}

button.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
.actions { margin-top: 12px; }

.op-list { max-height: 320px; overflow: auto; border: 1px solid var(--line); border-radius: 4px; }
.op-row { display: block; padding: 5px 10px; border-bottom: 1px solid var(--line); cursor: pointer; }
.op-row:last-child { border-bottom: none; }
.op-row:hover { background: #f0f5ff; }

.selected-op { border-top: 1px solid var(--line); padding-top: 12px; margin-top: 12px; }
.selected-op:first-child { border-top: none; padding-top: 0; margin-top: 0; }

table { width: 100%; border-collapse: collapse; background: var(--panel); }
th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 600; }
tr[data-artifact] { cursor: pointer; }
tr[data-artifact]:hover { background: #f0f5ff; }

.progress { height: 10px; background: var(--line); border-radius: 5px; overflow: hidden; }
.bar { height: 100%; background: var(--accent); transition: width 0.2s; }

.hex {
  background: #10151c;
  color: #d7e0ea;
  padding: 10px 12px;
  border-radius: 4px;
  overflow: auto;
  font-family: ui-monospace, Menlo, Consolas, monospace;
  font-size: 12px;
}

.message { color: var(--muted); min-height: 20px; }
.error { color: #c0392b; }
```

- [ ] **Step 9: 跑测试确认通过**

Run: `python3 -m pytest tests/test_web_pages.py -q`
Expected: 4 passed

- [ ] **Step 10: 跑全量测试**

Run: `python3 -m pytest -q -W error`
Expected: 全部通过

- [ ] **Step 11: 提交**

```bash
git add icsgen/web/templates icsgen/web/static tests/test_web_pages.py
git commit -m "feat: 实现 Web 页面模板、工作台表单与进度轮询"
```

---

### Task 9: CLI 入口与依赖声明

**Files:**
- Modify: `icsgen/cli.py`
- Modify: `pyproject.toml`
- Test: `tests/test_cli.py`（追加用例）

**Interfaces:**
- Consumes: `icsgen.web.app.create_app(root: Path | None) -> FastAPI`
- Produces: CLI 命令 `icsgen web --host --port --output`

- [ ] **Step 1: 写失败的测试**

在 `tests/test_cli.py` 末尾追加：

```python
def test_web_command_is_registered():
    result = CliRunner().invoke(app, ["web", "--help"])
    assert result.exit_code == 0
    assert "监听" in result.output
```

- [ ] **Step 2: 跑测试确认失败**

Run: `python3 -m pytest tests/test_cli.py -q`
Expected: FAIL —— `No such command 'web'`

- [ ] **Step 3: 实现 CLI 命令**

在 `icsgen/cli.py` 末尾追加：

```python
@app.command("web")
def web(
    host: str = typer.Option("127.0.0.1", "--host", help="监听地址"),
    port: int = typer.Option(8080, "--port", help="监听端口"),
    output: Path = typer.Option(None, "--output", help="账本与生成目录的存放位置"),
) -> None:
    """启动 Web 交互界面。"""
    import uvicorn

    from .web.app import create_app, default_root

    root = output if output is not None else default_root()
    typer.echo(f"Web 界面: http://{host}:{port}（数据目录 {root}）")
    uvicorn.run(create_app(root), host=host, port=port)
```

- [ ] **Step 4: 声明依赖**

修改 `pyproject.toml`：

```toml
[project.optional-dependencies]
dev = ["pytest>=8.0"]
web = ["fastapi>=0.115", "uvicorn>=0.34", "jinja2>=3.1"]
```

- [ ] **Step 5: 跑测试确认通过**

Run: `python3 -m pytest tests/test_cli.py -q`
Expected: 全部通过

- [ ] **Step 6: 跑全量测试**

Run: `python3 -m pytest -q -W error`
Expected: 全部通过

- [ ] **Step 7: 提交**

```bash
git add icsgen/cli.py pyproject.toml tests/test_cli.py
git commit -m "feat: 新增 icsgen web 命令与 web 可选依赖组"
```

---

### Task 10: 端到端一致性测试与文档

**Files:**
- Create: `tests/test_e2e_web.py`
- Modify: `README.md`

**Interfaces:**
- Consumes: 全部前序任务的产出
- Produces: 无新接口

- [ ] **Step 1: 写失败的测试**

创建 `tests/test_e2e_web.py`：

```python
"""端到端：网页路径与 CLI 路径产出同一份字节。"""

import io
import json
import time
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

from icsgen.generator import build_dataset
from icsgen.protocols.modbus.adapter import load_modbus_adapter
from icsgen.spec.model import Operation, Scenario, Variant
from icsgen.web.app import create_app


def _wait(client, generation_id, timeout=20.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        detail = client.get(f"/api/generations/{generation_id}").json()
        if detail["status"] != "running":
            return detail
        time.sleep(0.05)
    raise AssertionError("生成超时")


def test_web_output_matches_cli_output_byte_for_byte(tmp_path):
    """同一组操作，网页路径与 CLI 路径生成的帧必须逐字节相同。"""
    payload = {
        "name": "一致性",
        "protocol": "modbus",
        "transport": {"kind": "tcp"},
        "operations": [
            {
                "op": "modbus.read_holding_registers",
                "variant": "normal",
                "params": {"start_addr": 0, "quantity": 3},
                "count": 2,
            },
            {
                "op": "modbus.write_multiple_registers",
                "variant": "exception",
                "params": {"start_addr": 100, "quantity": 2, "values": [1, 2]},
                "count": 1,
            },
        ],
    }
    client = TestClient(create_app(tmp_path / "web"))
    config_id = client.post("/api/configs", json=payload).json()["id"]
    generation_id = client.post("/api/generations", json={"config_id": config_id}).json()[
        "generation_id"
    ]
    detail = _wait(client, generation_id)

    scenario = Scenario(
        name="一致性",
        transport={"kind": "tcp"},
        operations=(
            Operation(op="modbus.read_holding_registers", params={"start_addr": 0, "quantity": 3}),
            Operation(op="modbus.read_holding_registers", params={"start_addr": 0, "quantity": 3}),
            Operation(
                op="modbus.write_multiple_registers",
                params={"start_addr": 100, "quantity": 2, "values": [1, 2]},
                variant=Variant.EXCEPTION,
            ),
        ),
    )
    cli_root = build_dataset(
        scenario, load_modbus_adapter(), tmp_path / "cli", name="一致性"
    )
    web_root = tmp_path / "web" / "generations" / generation_id

    web_manifest = json.loads((web_root / "manifest.json").read_text(encoding="utf-8"))
    cli_manifest = json.loads((cli_root / "manifest.json").read_text(encoding="utf-8"))
    assert [e["id"] for e in web_manifest["artifacts"]] == [
        e["id"] for e in cli_manifest["artifacts"]
    ]
    assert len(web_manifest["artifacts"]) == 3

    for entry in web_manifest["artifacts"]:
        rel = (
            Path(entry["tier"])
            / f"{entry['protocol']}_{entry['transport']}"
            / "frames"
            / f"{entry['id']}.bin"
        )
        assert (web_root / rel).read_bytes() == (cli_root / rel).read_bytes(), entry["id"]


def test_config_and_generation_records_are_immutable(tmp_path):
    """配置与生成记录没有删除/修改入口（验收指标 6）。"""
    client = TestClient(create_app(tmp_path / "web"))
    payload = {
        "name": "只读",
        "protocol": "modbus",
        "transport": {"kind": "tcp"},
        "operations": [
            {
                "op": "modbus.read_holding_registers",
                "variant": "normal",
                "params": {"start_addr": 0, "quantity": 3},
                "count": 1,
            }
        ],
    }
    config_id = client.post("/api/configs", json=payload).json()["id"]
    generation_id = client.post("/api/generations", json={"config_id": config_id}).json()[
        "generation_id"
    ]
    _wait(client, generation_id)

    for method in ("delete", "put", "patch"):
        for path in (f"/api/configs/{config_id}", f"/api/generations/{generation_id}"):
            response = getattr(client, method)(path, json={"name": "改过了"})
            assert response.status_code in (404, 405), (method, path)


def test_generation_cannot_run_twice(tmp_path):
    """同一配置只能生成一次，二次生成返回 409（验收指标 6）。"""
    client = TestClient(create_app(tmp_path / "web"))
    payload = {
        "name": "只生成一次",
        "protocol": "modbus",
        "transport": {"kind": "tcp"},
        "operations": [
            {
                "op": "modbus.read_holding_registers",
                "variant": "normal",
                "params": {"start_addr": 0, "quantity": 3},
                "count": 1,
            }
        ],
    }
    config_id = client.post("/api/configs", json=payload).json()["id"]
    first = client.post("/api/generations", json={"config_id": config_id})
    assert first.status_code == 201
    _wait(client, first.json()["generation_id"])

    second = client.post("/api/generations", json={"config_id": config_id})
    assert second.status_code == 409


def test_generation_outputs_are_downloadable(tmp_path):
    """生成完成后可下载单帧文件与整包归档（验收指标 2）。"""
    client = TestClient(create_app(tmp_path / "web"))
    payload = {
        "name": "下载",
        "protocol": "modbus",
        "transport": {"kind": "tcp"},
        "operations": [
            {
                "op": "modbus.read_holding_registers",
                "variant": "normal",
                "params": {"start_addr": 0, "quantity": 3},
                "count": 1,
            }
        ],
    }
    config_id = client.post("/api/configs", json=payload).json()["id"]
    generation_id = client.post("/api/generations", json={"config_id": config_id}).json()[
        "generation_id"
    ]
    detail = _wait(client, generation_id)
    artifact = detail["artifacts"][0]

    rel = (
        f"{artifact['tier']}/{artifact['protocol']}_{artifact['transport']}"
        f"/frames/{artifact['id']}.bin"
    )
    single = client.get(f"/api/generations/{generation_id}/download/{rel}")
    assert single.status_code == 200
    # MBAP 头：事务 id 0、协议 id 0、长度 6、单元 id 0xFF、功能码 0x03
    assert single.content.startswith(b"\x00\x00\x00\x00\x00\x06\xff\x03")

    archive = client.get(f"/api/generations/{generation_id}/archive.zip")
    assert archive.status_code == 200
    with zipfile.ZipFile(io.BytesIO(archive.content)) as bundle:
        names = bundle.namelist()
    assert f"{generation_id}/manifest.json" in names
    assert any(name.endswith(".bin") for name in names)


def test_generation_artifact_count_matches_sum_of_counts(tmp_path):
    """交互数量生效：产物条数 == Σ count（验收指标 3）。"""
    client = TestClient(create_app(tmp_path / "web"))
    payload = {
        "name": "数量",
        "protocol": "modbus",
        "transport": {"kind": "tcp"},
        "operations": [
            {
                "op": "modbus.read_holding_registers",
                "variant": "normal",
                "params": {"start_addr": 0, "quantity": 3},
                "count": 3,
            },
            {
                "op": "modbus.read_coils",
                "variant": "normal",
                "params": {"start_addr": 0, "quantity": 8},
                "count": 2,
            },
        ],
    }
    config_id = client.post("/api/configs", json=payload).json()["id"]
    generation_id = client.post("/api/generations", json={"config_id": config_id}).json()[
        "generation_id"
    ]
    detail = _wait(client, generation_id)
    assert detail["status"] == "succeeded"
    assert len(detail["artifacts"]) == 5
```

- [ ] **Step 2: 跑测试确认失败**

Run: `python3 -m pytest tests/test_e2e_web.py -q`
Expected: FAIL —— `ERROR: file or directory not found: tests/test_e2e_web.py`

这是一个纯测试任务，RED 形态是「文件还不存在」。真正有价值的是 GREEN 阶段：
这些用例横跨前 9 个任务，只要任何一层契约漂移（生成路径、产物 id、下载路由、
状态折叠）就会在这里红。

- [ ] **Step 3: 补 README 的 Web 章节**

在 `README.md` 的「## PLC 服务端模拟」之后、「## 扩展新的操作类型」之前插入：

````markdown
## Web 交互界面

```bash
python -m pip install -e ".[web]"
icsgen web --host 127.0.0.1 --port 8080
```

浏览器打开 `http://127.0.0.1:8080`，走「选协议 → 选操作 → 填参数与交互数量 → 保存配置 → 生成 → 进度 → 预览 → 下载」全链路：

- **选协议与操作**：协议来自注册表，操作类型来自该协议的 catalog（Modbus 当前 41 个操作类型 / 192 条覆盖条目），参数表单按 catalog 的参数 schema 在浏览器端动态生成。
- **交互数量**：每条操作可单独设置重复次数，生成的产物条数 == Σ 数量。
- **配置记录**：保存后**不可修改、不可删除**；每条配置**只能生成一次**，二次生成返回 409。
- **进度**：分「构建帧」与「写盘」两个阶段，完成后可预览每条产物的 hex 与协议字段解析结果。
- **下载**：可下载单个 `.bin` 帧文件，也可打包下载整个数据集 `archive.zip`。

Web 层是库之上的薄壳：生成走 `icsgen.generator.build_dataset`，校验走 `icsgen.spec.loader.validate_operations`，网页产出的字节与 CLI 逐字节一致。记录页 `/records` 列出全部配置与生成记录。
````

- [ ] **Step 4: 跑测试确认通过**

Run: `python3 -m pytest tests/test_e2e_web.py -q`
Expected: 5 passed

- [ ] **Step 5: 跑全量测试**

Run: `python3 -m pytest -q -W error`
Expected: 全部通过

- [ ] **Step 6: 提交**

```bash
git add tests/test_e2e_web.py README.md
git commit -m "test: 端到端校验网页与 CLI 产出一致，补 Web 使用文档"
```

---

## Self-Review

### 1. 规格覆盖

| Spec 章节 | 落地任务 |
|---|---|
| §2 范围（无多用户、只读记录） | Task 5（append-only 账本）+ Task 6（记录里预留 `owner` 字段位） |
| §4 用户流程 | Task 8（页面模板）+ Task 7（页面路由） |
| §5 总体架构（存储 / 服务 / HTTP 三层） | Task 5 → Task 6 → Task 7 |
| §6.1 配置记录 | Task 5 `save_config` / `list_configs` / `get_config` + Task 6 `save_config` |
| §6.2 事件流 | Task 5 `append_event` / `list_events` |
| §6.3 由事件推导的状态 | Task 5 `list_generations` / `generation_for_config` / `generations_by_config` |
| §6.4 落盘布局 | Task 5 `WebStore`（`configs.jsonl` / `events.jsonl` / `generations/<id>/`） |
| §7 协议注册表 | Task 1 `icsgen/protocols/registry.py` |
| §8 操作校验复用 | Task 2 `validate_operations`（从 `load_scenario` 里抽出来） |
| §9 帧预览契约 | Task 3 `FrameView` / `inspect_frame` / `ProtocolAdapter.inspect` |
| §10.1 交互数量展开 | Task 6 `build_scenario` + Task 6 `_check_counts`（上限 1000/5000） |
| §10.2 进度（两阶段） | Task 4 `on_progress` 回调 + Task 6 `_percent` |
| §10.3 异步执行 | Task 6 `GenerationService`（后台线程 + 内存 job 状态） |
| §10.4 transaction_id 溢出修复 | Task 4 `_TRANSACTION_ID_MODULO` |
| §11 HTTP 接口 | Task 7（10 条 JSON 路由 + 3 条页面路由） |
| §12 错误处理 | Task 7 `_fail`（404 / 409 / 422 / 500 的映射） |
| §13 存储与并发 | Task 5 `Ledger`（`threading.Lock` + `fcntl.flock` + fsync，损坏行跳过） |
| §14 测试策略 | 各任务自带测试文件 + Task 10 跨路径一致性用例 |
| §15 依赖与入口 | Task 9（`icsgen web` 命令 + `web` 可选依赖组） |
| §16 验收指标 | 见下表 |
| §17 未决问题 | 多用户 → `owner` 字段位；记录编辑 → 明确不做；大 N 性能 → 写盘阶段停在 85%；P2 接入 → 注册表加一行 + 实现 `inspect` |

**验收指标逐条对照**

| # | 指标 | 落点 |
|---|---|---|
| 1 | 1 协议 / 41 操作 / 192 覆盖条目 | Task 1 `list_protocols` + Task 7 `GET /api/protocols` |
| 2 | 全链路可用 | Task 8（页面）+ Task 10（端到端下载用例） |
| 3 | 产物条数 == Σ count | Task 10 `test_generation_artifact_count_matches_sum_of_counts` |
| 4 | Web 与 CLI 逐字节相同 | Task 10 `test_web_output_matches_cli_output_byte_for_byte` |
| 5 | 19 个布局的请求与响应字段可解 | Task 3 `test_inspect_covers_every_catalog_layout` |
| 6 | 记录不可删改 + 二次生成 409 | Task 10 `test_config_and_generation_records_are_immutable` + `test_generation_cannot_run_twice` |
| 7 | transaction_id 不溢出 | Task 4 回归用例 |
| 8 | `pytest -q -W error` 全绿 | 每个任务的「跑全量测试」步 |

**spec §14 的测试文件划分与本计划的差异**：spec 建议 `tests/test_spec_validate_operations.py`、
`tests/test_web_progress.py`、`tests/test_generator_transaction_id.py` 三个独立文件，本计划把用例并入
既有的 `tests/test_catalog.py`、`tests/test_generator.py`、`tests/test_web_service.py`。
覆盖面不变，只是避免同一主题散在多个文件；评审时以「用例是否覆盖」为准，而非文件名。

### 2. 占位符扫描

全文无 TBD / TODO / 「类似 Task N」/「补充错误处理」这类空步骤。每个代码步骤都给出可直接粘贴的完整代码；
每个任务都写明跑哪个测试命令、期望什么输出、提交哪几个文件。

### 3. 类型一致性

- `ProtocolAdapter.inspect(op, payload, ctx, direction)` —— Task 3 定义，Task 6 `artifact_detail` 按同序调用。
- `validate_operations(catalog, items, context=None)` —— Task 2 定义，Task 6 `save_config` 以 `context=` 关键字调用。
- `build_dataset(..., on_progress=None)` —— Task 4 定义，Task 6 `GenerationService._run` 以关键字调用。
- `WebStore.generation_dir(generation_id)` —— Task 5 定义，Task 6 / Task 7 一致使用。
- `save_config(store, payload)` —— Task 6 定义，Task 7 以同序调用；返回值是配置记录（含 `id`）。
- `GenerationService.start(config_id)` 返回 `{"generation_id": ..., "status": "running"}` —— Task 6 定义，Task 7 / Task 10 一致使用。
- `generation_detail` 返回的产物摘要有 `id` / `tier` / `protocol` / `transport` 字段 —— Task 6 定义，Task 8 页面与 Task 10 下载用例据此拼下载路径。
- 任务号顺序：每个任务引用的符号都在被引用之前的任务里产出（1→2→3→4→5→6→7→8→9→10 无逆向依赖）。

---

## 执行方式

Plan complete and saved to `docs/superpowers/plans/2026-11-03-icsgen-web-ui.md`. Two execution options:

**1. Subagent-Driven（推荐）** —— 每个任务派一个全新的实施子代理，任务之间做两阶段审查，迭代快、不吃上下文

**2. Inline Execution** —— 在当前会话里按 executing-plans 批量执行，到检查点再一起复核

**选哪个？**
