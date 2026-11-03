# icsgen Web 交互界面 — 设计规格

日期：2026-11-03
状态：待评审
关联规格：`2026-10-30-ics-traffic-generator-design.md`（P1 流量生成器，本文只冻结 Web 层，不修改其核心抽象）

---

## 1. 背景与目标

P1 已交付 Modbus TCP/RTU 的流量生成流水线（场景 YAML → 分层数据集 → pcap/bin/hex/manifest）。目前它只有命令行入口，使用者必须手写 YAML 才能拿到一组样本。

目标：提供一条 **HTTP 页面路径**，让使用者在浏览器里完成

1. 选择工控协议种类；
2. 在该协议下选择操作类型；
3. 为每个操作指定语义变体、参数与**交互数量**；
4. **保存配置**（一条不可变记录）；
5. 发起生成，**观察进度**；
6. 生成完成后**预览**与**下载**数据包。

核心约束（来自需求方）：

- 初步不做多用户管理，只提供 HTTP 页面访问；
- 配置记录与生成记录**只读**：可查看、可列出，**不支持删除与修改**；
- 一条配置记录**只能生成一次**。

## 2. 范围

### 2.1 本期交付

| 项 | 内容 |
|---|---|
| 协议 | Modbus TCP + Modbus RTU（经协议注册表枚举，当前 1 个协议） |
| 操作类型 | 41 个（catalog 全量，含 21 个诊断子功能） |
| 页面 | 工作台 `/`、记录页 `/records`、生成详情 `/generations/{id}` |
| API | 与页面同构的 JSON API（§11.2） |
| 存储 | 两个 append-only JSONL 账本 + 生成产物目录 |
| 交互数量 | 每个操作独立重复 N 次，总量上限见 §10.1 |
| 进度 | 两阶段进度条（生成帧 → 写盘），页面轮询 |

### 2.2 非目标

- 用户体系、认证、权限（"初步不做"；记录模型预留 `owner` 字段位）
- 配置记录的编辑、复制、删除；生成记录的删除
- 生成目录的自动回收（与"记录不可删"语义一致，见 §13.3）
- 协议的 P2+ 实现（只保证新增协议时 Web 层不改代码，见 §7）
- 前端构建链、CDN 依赖、SPA 框架（全项目保持纯 Python 依赖）

## 3. 术语

| 术语 | 含义 |
|---|---|
| 配置记录（config） | 用户保存的一次选择快照：协议、传输、每个操作的变体/参数/交互数量 |
| 生成记录（generation） | 一次基于配置记录的生成任务，生命周期以事件追加记录 |
| 事件（event） | 追加写入账本的一行事实，描述生成任务的状态迁移 |
| 交互数量（count） | 单个操作类型重复生成的次数；总量 = 各操作 count 之和 |
| 帧视图（FrameView） | 协议级解析结果：摘要 + 逐字段名值，供页面渲染预览 |

## 4. 用户流程

```
工作台 /                     记录页 /records
┌───────────────────────┐    ┌──────────────────────┐
│ 协议 ▼  [modbus]       │    │ 配置记录（只读）      │
│ 传输 ▼ [tcp|serial]    │    │  cfg_x 名称 操作数 …  │
│ 操作类型多选（41 项）  │    │  …（无删除/修改）      │
│  ├ 操作A 变体▼ 参数 数量│    ├──────────────────────┤
│  └ 操作B 变体▼ 参数 数量│    │ 生成记录（只读）      │
│ [保存配置]  → 命名      │    │  gen_y 状态 数量 …   │
│ [生成数据包]（需已保存）│    │  …（无删除/修改）      │
└───────────────────────┘    └──────────────────────┘
          │                              │
          │ 生成                          ▼
          ▼                    生成详情 /generations/{id}
┌───────────────────────┐    ┌──────────────────────┐
│ 阶段：生成帧 ▓▓▓░░ 62% │    │ 产物清单（41 条）      │
│ 已完成 186 / 300        │    │  操作 变体 层 长度 …   │
│ 阶段：写盘 ▓▓▓▓▓ 85%   │    │  ├ 请求帧 hex + 字段   │
│ ✔ 完成                  │    │  ├ 响应帧 hex + 字段   │
│ [下载 pcap] [下载 zip] │    │  └ 下载 .bin/.hex      │
└───────────────────────┘    └──────────────────────┘
```

## 5. 总体架构

### 5.1 分层与依赖方向

```
        HTTP 层  icsgen/web/app.py        （唯一 import FastAPI 的文件）
             │  路由、模板渲染、文件下载
        服务层  icsgen/web/service.py      （不 import FastAPI）
             │  协议查询、配置保存、生成任务、产物读取
   ┌─────────┴──────────┬───────────────┬───────────────┐
 库层                 存储层          传输层           编解码层
 icsgen/protocols/    web/store.py    icsgen/transport/ icsgen/codec/
 icsgen/spec/         （append-only） icsgen/emit/     icsgen/mutate/
 icsgen/generator.py
```

依赖方向单向向下：HTTP → 服务 → 库；服务 → 存储。库层**不感知 Web 的存在**。

### 5.2 组件划分

| 文件 | 职责 |
|---|---|
| `icsgen/web/__init__.py` | 包入口，导出 `create_app` |
| `icsgen/web/app.py` | FastAPI 应用工厂、路由、Jinja2 模板装配 |
| `icsgen/web/service.py` | 服务层：协议/操作查询、配置保存、生成任务调度、产物读取与预览 |
| `icsgen/web/store.py` | append-only 账本读写（配置记录、事件流） |
| `icsgen/web/models.py` | pydantic 请求/响应模型 |
| `icsgen/web/templates/` | `base.html`、`index.html`、`records.html`、`generation.html` |
| `icsgen/web/static/app.css` | 页面样式（无 JS 框架） |
| `icsgen/protocols/registry.py` | 协议注册表（§7） |
| `icsgen/protocols/modbus/inspect.py` | Modbus 帧的协议级解析（§9） |

**服务层不 import FastAPI**：全部业务逻辑可在没有 HTTP 的情况下单测。

## 6. 数据模型

### 6.1 配置记录

落盘于 `datasets/web/configs.jsonl`，一行一条，**追加写入后不再修改**。

```json
{
  "id": "cfg_3f9a2c1d0e7b",
  "name": "读保持寄存器压测",
  "protocol": "modbus",
  "transport": {"kind": "tcp", "src_ip": "192.168.1.10", "dst_ip": "192.168.1.20", "dport": 502},
  "operations": [
    {"op": "modbus.read_holding_registers", "variant": "normal",
     "params": {"start_addr": 0, "quantity": 3}, "count": 100}
  ],
  "created_at": "2026-11-03T02:10:00+00:00"
}
```

- `id` 形如 `cfg_` + 12 位十六进制（uuid4 前缀），全局唯一
- `operations` 的顺序即生成顺序
- `count` 为该操作的交互数量，默认 1
- `variant` 必须落在该操作在 catalog 中声明的变体集合内

### 6.2 事件流

落盘于 `datasets/web/events.jsonl`，**只追加**。生成任务的生命周期由事件序列表达，不修改既有行。

```json
{"type": "generation_started",  "generation_id": "gen_7c1d...", "config_id": "cfg_3f9a...",
 "config_name": "读保持寄存器压测", "output_dir": "datasets/web/generations/gen_7c1d...",
 "created_at": "2026-11-03T02:11:00+00:00"}
{"type": "generation_succeeded", "generation_id": "gen_7c1d...", "artifact_count": 300,
 "packet_count": 600, "duration_ms": 1840, "finished_at": "2026-11-03T02:11:01+00:00"}
{"type": "generation_failed",    "generation_id": "gen_7c1d...", "error": "…",
 "finished_at": "2026-11-03T02:11:01+00:00"}
```

事件类型恰有三种：`generation_started` / `generation_succeeded` / `generation_failed`。
一个生成任务**恰好**对应一个 `generation_started` 与至多一个终态事件。

### 6.3 由事件推导的状态

任务的**状态**不额外存，全部从事件流折叠得出：

| 状态 | 判定 |
|---|---|
| `running` | 有 `generation_started`，无终态事件 |
| `succeeded` | 有 `generation_succeeded` |
| `failed` | 有 `generation_failed` |

而**进度数值**（`done` / `total` / `percent`）只存在于进行中任务的内存状态里（§10.3），因为它随每条交互变化，写进账本没有意义。

「配置只能生成一次」= 事件流中存在同 `config_id` 的 `generation_started` 即拒绝再次发起（HTTP 409）。

### 6.4 落盘布局

```
datasets/web/
├── configs.jsonl              # 配置记录（append-only）
├── events.jsonl               # 事件流（append-only）
└── generations/
    └── gen_7c1d.../           # 一个生成任务一个目录
        ├── manifest.json
        ├── legit/modbus_tcp/
        │   ├── session.pcap
        │   └── frames/*.bin  frames/*.hex
        └── abnormal/modbus_tcp/...
```

生成目录内的结构与 CLI 产出的数据集**完全一致** —— Web 复用 `build_dataset`，不另写一套写出逻辑。

## 7. 协议注册表

现状 `icsgen/cli.py:29` 的 `_catalog_for()` 硬编码 `modbus`，Web 无法枚举协议，也无法在新增协议时零改动。新增注册表作为**协议名 → (catalog, 适配器工厂)** 的唯一映射：

```python
@dataclass(frozen=True)
class ProtocolInfo:
    name: str
    summary: str
    transports: tuple[str, ...]          # catalog 声明的传输名，如 ("tcp", "rtu")
    catalog_path: Path
    adapter_factory: Callable[[], ProtocolAdapter]

def available_protocols() -> list[ProtocolInfo]: ...
def get_protocol(name: str) -> ProtocolInfo: ...
def get_catalog(name: str) -> Catalog: ...
def get_adapter(name: str) -> ProtocolAdapter: ...
```

- 注册表当前只登记 `modbus`；P2 接入 CIP 时**只加注册表一行** + 实现该协议的 `inspect`（§9），Web 层不改
- `icsgen/cli.py` 的 `_catalog_for()` 改为调用 `get_protocol()`，CLI 与 Web 共用同一映射
- 传输名映射：catalog 用 `tcp` / `rtu`，`TransportSpec.kind` 用 `tcp` / `serial`。注册表提供 `transport_kind(catalog_transport) -> str`：`tcp → "tcp"`，`rtu → "serial"`

## 8. 操作校验复用

现状 `load_scenario()` 只接受 YAML 文件路径，Web 手上是表单数据，无法复用校验。从 `icsgen/spec/loader.py` 抽出公共函数：

```python
def validate_operations(catalog: Catalog, items: Sequence[ScenarioOperationModel]) -> tuple[Operation, ...]
```

- `load_scenario()` 改为构造 `ScenarioModel` 后调用它，行为与错误文案不变
- Web 侧把表单数据构造成 `ScenarioOperationModel` 列表，再调用同一函数 → **参数 schema 校验、变体合法性校验、tier/variant 冲突校验三条路径完全一致**
- 校验失败统一抛 `ScenarioError`，HTTP 层转成 422 并带上字段级错误列表

`count` 的上下限不在此函数内校验（它不是协议参数），由 Web 层单独校验。

## 9. 帧预览：协议级解析契约

预览要能解出「事务 id / 单元 id / 功能码 / 异常码 / 各字段值」，这些是协议知识，**不能放在 Web 层**。在 `icsgen/protocols/base.py` 扩充适配器契约：

```python
@dataclass(frozen=True)
class FrameField:
    name: str
    value: str            # 已格式化的显示值

@dataclass(frozen=True)
class FrameView:
    summary: str                        # 一行摘要
    fields: tuple[FrameField, ...]       # 逐字段
    is_exception: bool = False
    exception_code: int | None = None

class ProtocolAdapter(Protocol):
    …
    def inspect(self, op: str, payload: bytes, ctx: BuildContext, direction: str) -> FrameView: ...
```

- `direction` ∈ `{"request", "response"}`，决定用布局的哪一侧解字段
- `op` 是操作名，用于定位字段布局 —— **不能按功能码反查布局**：catalog 中多个操作共享功能码（21 个诊断子功能共享 fc08，FC2B 有两个条目），按功能码反查会取到错误的布局
- `ModbusAdapter.inspect` 实现（置于 `icsgen/protocols/modbus/inspect.py`）：
  - TCP：`parse_mbap()` 拆出事务 id / 协议 id / 长度 / 单元 id，余下是 PDU
  - RTU：`parse_rtu()` 拆出单元 id 与 PDU（并校验 CRC）
  - PDU 首字节为功能码；`fc & 0x80` → 异常响应，异常码取 `pdu[1]`
  - 正常帧按 catalog 条目的布局，用 `decode()` 解请求或响应字段
  - **降级策略**：解析失败（如畸形变体、CRC 不符）时不抛错，返回只含原始字节的 `FrameView`，摘要里写明失败原因 —— 畸形帧本就是数据集的一部分，预览页不应因此 500

## 10. 生成流水线与进度

### 10.1 交互数量的展开

配置里每个操作带 `count`，展开为 `Operation` 序列：按配置顺序，每个操作重复 `count` 次，共享同一份 `params` 与 `variant`。生成的 `Scenario.operations` 长度 = Σ count。

上限（超出表单报错 422）：

| 限制 | 值 | 理由 |
|---|---|---|
| 单操作 count | ≤ 1000 | 每次交互产出 4 个文件（req bin/hex + resp bin/hex），单操作过多会让文件数失控 |
| Σ count | ≤ 5000 | 总量 5000 次交互 → 最多 20000 个文件、单 pcap 最多 10000 个包，仍在可接受范围 |

> 早期草案写的是 10000/100000，核算文件数后下调：每次交互产生 4 个文件，10 万次交互意味着 40 万个文件，会让文件系统与浏览器目录 listing 都难以承受。

### 10.2 进度

`build_dataset()` 增加可选回调，不改现有调用方：

```python
def build_dataset(scenario, adapter, root, name=None,
                  on_progress: Callable[[int, int], None] | None = None) -> Path
```

- `on_progress(done, total)` 在**每条交互的帧构建完成后**调用一次，`done` 从 1 递增到 `total`
- 写盘阶段是一次批量调用，中途无法给出细粒度

因此进度口径为两阶段：

| 阶段 | percent |
|---|---|
| `building` | `done / total × 85` |
| `writing` | 固定 85 |
| `done` | 100 |

写盘完成才置 100 —— 不谎报进度。

阶段切换点是**最后一条交互构建完成时**（回调收到 `done == total`）：此刻帧已全部构建、即将写盘，之后 percent 停在 85 直到写盘结束。

### 10.3 异步执行

生成在**后台线程**（`threading.Thread(daemon=True)`）中执行，HTTP 请求立即返回 `generation_id`。页面用 `GET /api/generations/{id}` 轮询（间隔 500ms）刷新进度。

- 进程内存中保留进行中任务的状态（`JobStore`：done / total / phase），用于轮询
- 任务结束时向事件流追加终态事件
- 线程内异常被捕获，转成 `generation_failed` 事件，页面显示错误文本而不是 500

**进程重启后的孤儿任务**：启动时扫描事件流，凡有 `generation_started` 而无终态事件的，追加一条 `generation_failed`（error 写明"服务重启导致生成中断"）。这仍是追加写入，不修改既有历史行。

### 10.4 `transaction_id` 溢出修复

`icsgen/generator.py:37` 用场景下标 `index` 当 Modbus 事务 id，而 MBAP 的事务 id 只有 2 字节。交互数量放开到数千后下标必然越过 65535，`to_bytes(2, "big")` 会抛 `OverflowError` 直接崩溃。

修复：事务 id 取 `index % 0x10000`；TCP 序列号 `seq = index * 10` 同理取模 2³²。

## 11. HTTP 接口

### 11.1 页面路由

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/` | 工作台：协议/操作选择、参数、交互数量、保存与生成 |
| GET | `/records` | 记录页：配置记录 + 生成记录（只读） |
| GET | `/generations/{generation_id}` | 生成详情：运行中显示进度，完成后显示产物清单与预览 |

静态资源 `/static/app.css`。

### 11.2 JSON API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/protocols` | 协议列表（含操作类型数与覆盖条目数） |
| GET | `/api/protocols/{protocol}/operations` | 操作类型列表（含 summary、功能码、变体、参数 schema） |
| GET | `/api/configs` | 配置记录列表 |
| POST | `/api/configs` | 保存配置 → 201，返回 `{"id", "name", "created_at"}` |
| GET | `/api/generations` | 生成记录列表 |
| POST | `/api/generations` | 发起生成（body `{"config_id"}`）→ 201，返回 `{"generation_id", "status"}` |
| GET | `/api/generations/{id}` | 生成状态与产物清单 |
| GET | `/api/generations/{id}/artifacts/{artifact_id}` | 产物详情：请求/响应帧 hex + 字段解析 |
| GET | `/api/generations/{id}/download/{path}` | 下载单个产物文件 |
| GET | `/api/generations/{id}/archive.zip` | 整个数据集打包下载 |

### 11.3 请求与响应模型

`POST /api/configs` 请求体：

```json
{
  "name": "读保持寄存器压测",
  "protocol": "modbus",
  "transport": {"kind": "tcp", "src_ip": "192.168.1.10", "dst_ip": "192.168.1.20", "dport": 502},
  "operations": [
    {"op": "modbus.read_holding_registers", "variant": "normal",
     "params": {"start_addr": 0, "quantity": 3}, "count": 100}
  ]
}
```

`POST /api/generations` 请求体：`{"config_id": "cfg_..."}`

`GET /api/generations/{id}` 响应体：

```json
{
  "id": "gen_7c1d...", "config_id": "cfg_3f9a...", "config_name": "读保持寄存器压测",
  "status": "running", "phase": "building",
  "done": 186, "total": 300, "percent": 52.7, "error": null,
  "output_dir": "datasets/web/generations/gen_7c1d...",
  "artifacts": [
    {"id": "modbus.read_holding_registers#001", "op": "modbus.read_holding_registers",
     "variant": "normal", "tier": "legit", "len": 12, "sha256": "…",
     "has_response": true, "pcap_file": "legit/modbus_tcp/session.pcap", "pcap_index": 0}
  ]
}
```

`GET /api/generations/{id}/artifacts/{artifact_id}` 响应体：

```json
{
  "id": "…", "op": "…", "variant": "…", "tier": "…",
  "request": {"hex": "00 01 00 00 00 06 01 03 00 00 00 03", "view": {"summary": "…", "fields": [{"name": "事务 id", "value": "1"}], "is_exception": false}},
  "response": {"hex": "…", "view": {"summary": "…", "fields": [], "is_exception": false}}
}
```

## 12. 错误处理

| 情形 | HTTP | 行为 |
|---|---|---|
| 协议未知 | 404 | 提示可用协议列表 |
| 操作名不在 catalog | 422 | 复用 `validate_operations` 的文案 |
| 参数违反 schema | 422 | 字段级错误列表（复用 `_validate_params` 的文案） |
| 变体不被该操作支持 | 422 | 列出该操作可用变体 |
| `count` 超上限 | 422 | 说明单操作与总量上限 |
| 同一配置重复生成 | 409 | "该配置已生成过，不能重复生成" |
| config / generation id 不存在 | 404 | — |
| 生成过程异常 | — | 任务状态置 `failed` + 错误文本，页面显示而非 500 |
| 下载路径越界 | 404 | 路径必须落在该生成目录内 |

## 13. 存储与并发

### 13.1 写入

两个账本均以「追加一行 JSON + flush + fsync」写入。写入时：

- 进程内用 `threading.Lock` 串行化同一文件的写
- 跨进程用 `fcntl.flock` 独占锁（Linux 平台，项目目标环境）

### 13.2 读取

读取时逐行解析，**跳过空行与解析失败的行** —— 单行损坏不应让整个页面 500。损坏行在服务日志里告警。

### 13.3 生成目录回收

本期**不回收**。需求明确"记录不支持删除和修改"，自动回收与该语义冲突；磁盘占用留待真实压力出现后再定策略（届时也应以"显式导出后由用户自行处理"的方式，而不是静默删除）。

## 14. 测试策略

| 测试文件 | 覆盖 |
|---|---|
| `tests/test_registry.py` | 注册表枚举：1 协议 / 41 操作类型 / 192 覆盖条目；未知协议报错 |
| `tests/test_spec_validate_operations.py` | 抽出 `validate_operations` 后的行为等价性：同样的输入、同样的错误 |
| `tests/test_web_store.py` | 账本追加语义：不可变、损坏行跳过、并发追加不交错 |
| `tests/test_web_service.py` | 保存配置、重复生成被拒、生成完成、产物清单、预览字段、下载 |
| `tests/test_web_api.py` | 路由契约（`TestClient`）：状态码与响应体形状 |
| `tests/test_web_progress.py` | `on_progress` 回调：done 从 1 到 total，进度换算 |
| `tests/test_generator_transaction_id.py` | 事务 id 在下标 > 65535 时不溢出（回归） |

一致性测试（跨路径等价）：同一操作列表，走 Web 服务层与走 CLI 路径生成的 `.bin` **逐字节相同**。

整体以 `pytest -q -W error` 运行，`-W error` 下不得有警告。

## 15. 依赖与入口

```toml
[project.optional-dependencies]
web = ["fastapi>=0.115", "uvicorn>=0.34", "jinja2>=3.1"]
```

- 新增 CLI 命令 `icsgen web --host 127.0.0.1 --port 8080 --output datasets/web`，内部起 uvicorn
- 页面与后端之间一律走 JSON API（`fetch`），不使用 HTML 表单提交 —— 操作类型的参数表单由 catalog 的参数 schema 在浏览器端动态生成，走 JSON 才不需要服务端再实现一套表单解析
- uvicorn 亦可直接指向 `icsgen.web.app:create_app --factory`
- 全项目仍是纯 Python 依赖，无前端构建链

## 16. 验收指标

1. 页面枚举出 **1 协议 / 41 操作类型 / 192 覆盖条目**，与 `icsgen catalog --count` 一致
2. 「选协议 → 选操作 → 填参数与数量 → 保存 → 生成 → 进度 → 预览 → 下载」全链路可用
3. 交互数量生效：生成的产物条数 == Σ count
4. 同一配置走 Web 与走 CLI 产出的 `.bin` **逐字节相同**
5. 预览能解出 Modbus 全部 19 个布局的请求与响应字段
6. 记录不可删改：不存在任何删除/修改路由；同一配置二次生成返回 409
7. 交互数量放开后 `transaction_id` 不溢出（>65536 次交互的回归用例通过）
8. `pytest -q -W error` 全绿

## 17. 未决问题与后续扩展

- **多用户**：本期无认证与用户维度。记录模型预留 `owner` 字段位，届时加用户时不需要改存储格式
- **记录的编辑**：明确不做。若日后放开，属于配置记录模型的语义变更，需要新的 spec
- **大 N 的性能**：5000 次交互下写盘阶段仍是单次批量调用，进度在写盘期间停在 85%。若实测写盘超过数秒，需要把 `write_dataset` 改造成流式并细化进度
- **P2 协议接入**：注册表加一行 + 实现该协议的 `inspect`，Web 层零改动；验收指标 1 的数字随协议增加而变化
