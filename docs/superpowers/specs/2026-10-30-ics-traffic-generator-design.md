# ICS 工控协议流量生成器 — 设计规格

日期：2026-10-30
状态：待评审

---

## 1. 背景与目标

工控协议栈（Modbus、S7comm、EtherNet/IP+CIP、Profinet、OPC UA、IEC 60870-5-104）的开发与验证需要大量**可复现、可断言**的协议流量样本。手工抓包受限于被测设备是否就绪、样本是否覆盖异常语义、能否精确断言字节。目标是提供一套基于开源工控模拟工具的流量生成器，**离线**产出：

- 标准 pcap（供 Wireshark 人工分析、规则引擎回放）
- 纯协议字节流 `.bin` / `.hex`（供单元测试精确断言）
- 分层数据集（合法 / 异常 / 变异），供协议栈健壮性测试

核心指标：**单协议操作类型数量足够丰富**，且该数量可被 CI 断言、不会随时间退化。

## 2. 范围

### 2.1 P1（本期交付）

| 项 | 内容 |
|---|---|
| 协议 | Modbus TCP + Modbus RTU |
| 产出 | pcap / bin / hex / manifest |
| 场景 | YAML 声明式描述 + Python 钩子扩展 |
| 变异 | 12 条规则的自研变异引擎，seed 可复现 |
| 服务端 | pymodbus 驱动的 PLC 模拟器（plc / client 双角色） |
| 操作条目 | ≥ 90（见 §15 指标） |

### 2.2 P2–P4（后续阶段，本 spec 只冻结接口与指标）

| 阶段 | 协议 | 操作条目下限 |
|---|---|---|
| P2 | EtherNet/IP + CIP 应用层 | ≥ 110 |
| P3 | S7comm | ≥ 60 |
| P4 | Profinet IO / OPC UA / IEC104 | ≥ 140 |

后续阶段的协议编解码与服务端选型见 §4.2，但**不改变**本 spec 冻结的核心抽象（§6、§7、§8）。

### 2.3 非目标

- 不做协议逆向与流量还原（那是 Netzob / Wireshark 的职责）
- 不做漏洞利用或攻击载荷生成（安全测试场景所需的畸形输入由"异常语义 + 变异引擎"提供，不提供武器化载荷）
- 不做实时高保真物理过程仿真（流量层的模拟，不涉及工艺模型）
- 不依赖真实 PLC 硬件

## 3. 术语

| 术语 | 含义 |
|---|---|
| 操作（operation） | 一次协议交互的抽象，如 `modbus.read_holding_registers` |
| 变体（variant） | 同一操作的语义形态：`normal` / `boundary` / `exception` / `illegal_fc` / `malformed` |
| 语义层（tier） | 数据集分层：`legit`（合法）/ `abnormal`（异常）/ `mutated`（变异） |
| 协议帧（frame） | 纯协议层字节，不含 IP/TCP/以太头 |
| 链路包（rendered packet） | 协议帧 + L2/L3/L4 封装后的完整字节 |

## 4. 关键技术调研结论（已实测验证）

### 4.1 开源底座可用性

| 工具 | 版本 | 实测结论 |
|---|---|---|
| Scapy | 2.7.0（本机已装） | contrib 层含 modbus / enipTCP / opc_da / pnio(+dcp,+rpc) / mqtt / scada-iec104 / ethercat / knx |
| pymodbus | 3.16.1 | 客户端+服务端双模，服务端可作 Modbus PLC 被测端 |
| python-snap7 | 3.3.1 | **自带 S7 服务端**（`snap7/server/`）；`snap7/s7protocol.py` 提供 S7 功能码、PDU 类型、用户数据组/子功能的权威枚举 |
| asyncua | 2.1.0 | OPC UA 客户端+服务端 |
| bacpypes | 0.19.0 | BACnet 协议栈（后续可选） |
| boofuzz | 0.4.2 | 通用 fuzz 框架；本项目自研轻量变异引擎，boofuzz 留作可选集成 |

### 4.2 关键缺口（决定了哪些必须自研）

1. **Scapy 无 CIP 应用层** —— contrib 只有 `enipTCP.py`（ENIP 封装，10 个命令类），CIP 服务路径/连接管理/显式消息/隐式消息全部缺失 → **P2 必须自研 CIP**。
2. **Scapy 无 S7comm** —— contrib 中完全没有 S7 层 → **P3 必须自研 S7**（以 snap7 的枚举为语义参照）。
3. **Scapy 的 IEC104 偏薄**（仅 8 个类）→ P4 需补 ASDU 类型。
4. **Scapy 的 Modbus 实现有缺陷且覆盖不全** —— 见下表。

### 4.3 Scapy Modbus 覆盖与缺陷（实测比对结果）

Scapy 类名中的功能码是**十六进制**（`ModbusPDU10` = FC 0x10 = 16），与 Modbus Application Protocol V1.1b3 规范**完全一致**，无编号错误；`0x12` 是保留空档，不存在该功能码（读文件记录是 `0x14`，写文件记录是 `0x15`）。

功能码层面 Scapy **覆盖全部 18 个规范功能码**（0x01–0x08、0x0B、0x0C、0x0F、0x10、0x11、0x14–0x18）加 MEI 0x2B。真正的缺口在别处：

| 缺口 | 具体表现 | 影响 |
|---|---|---|
| 诊断子功能不全 | 覆盖 15 个，规范全量 21 个，缺 0x05 Change Byte Count、0x06 Change Word Count、0x08 Get/Modify Modbus Plus Parameters、0x15 Get Clear Modbus Plus Request、0x17、0x18 | 诊断类操作类型覆盖不到一半 |
| 字节级缺陷 | FC0x18 响应的 `count_from` 指向 `byteCount` 而非 `FIFOCount`（源码自带 TODO）、FC0x0C 响应的事件日志被简化成固定 2 字节 | 这些功能码用 Scapy 生成的字节不可信 |
| 无法表达变体 | 无「任意功能码 + 异常码」「长度字段与实际不符」这类变体语义 | §8.3 的变体轴无法实现 |

Scapy 另提供 `ModbusPDUReservedFunctionCode*` 与 `ModbusPDUUserDefinedFunctionCode*`，可用于构造任意功能码，是"非法功能码"异常语义的参考。

**因此 Scapy 的定位是「独立交叉校验」而非「编解码事实源」**：对它实现正确的功能码做逐字节对照，事实源是 Modbus Application Protocol V1.1b3 与 pymodbus 源码。

### 4.4 关键设计决策：自研字段表驱动的编解码内核

Scapy 的 Modbus PDU 是**固定的 Packet 类**（每功能码一个类，字段写死在 `fields_desc` 中）。这带来两个后果：

1. 缺失的 6 个诊断子功能、Scapy 实现有缺陷的字节级布局（FC0x18、FC0x0C）**无法**通过 Scapy 表达
2. **catalog 无法驱动编码** —— 每个操作类型的参数布局都硬编码在 Scapy 类里，catalog 只能声明元数据。诊断子功能的 21 个子功能、Modbus 各功能码的参数差异，都得写成 Python 代码而非 YAML 声明

这与 §8「catalog 是操作类型的唯一事实源」直接冲突。若坚持 Scapy 基座，41 个操作类型就意味着 41 个硬编码构建函数，catalog 沦为文档。

**决策**：P1 自研一个**字段表驱动的二进制编解码内核**（`icsgen/codec/`，约 250 行），catalog 中的字段布局声明直接驱动编码与解码。

- 内核支持的字段类型：`uint8` `uint16` `uint32` `int16` `int32` `bytes` `array[T]` `bitfield`，以及 `count_of` / `count_from` / `adjust` 三个可组合的修饰符（覆盖 Modbus 的 byteCount 语义）
- Modbus 是该内核的第一个使用者；P2 的 CIP、P3 的 S7 复用同一内核
- 不引入 `construct` 等二进制 DSL 库 —— 所需字段类型有限，自研更可控且跨协议复用无绑定

### 4.5 Scapy 的保留职责

自研内核不替代 Scapy，Scapy 仍承担两块不可替代的价值：

- **链路封装**：Ethernet / IP / TCP / UDP（可靠且被广泛验证）
- **独立第三方解析器**：用于交叉验证自研内核的正确性 —— golden 测试中「自研编 → Scapy 解 → 断言语义等价」。同一份字节由两个独立实现解析并得出一致结论，这是比快照比对更强的正确性证据

对于 Scapy 无法正确解析的报文（诊断子功能、FC0x18、FC0x0C 等），交叉验证改用「自研解码器 + 规范逐字节对照」，并在测试中显式标注该报文未经第三方验证。

## 5. 总体架构

### 5.1 分层与依赖方向

```
   ①场景描述层  spec/
        │  (YAML → 校验 → Operation[])
        ▼
   ②协议适配层  protocols/          ← 只产出协议帧，不碰链路
        │  ProtocolFrame
        ▼
   ③传输封装层  transport/           ← 与协议无关
        │  RenderedPacket
        ▼
   ④产出层      emit/                ← pcap / bin / hex / manifest
        │
        ├──► ⑤变异层  mutate/        ← 就地改字节，产出第三层数据
        └──► ⑥服务端层 server/       ← 真实收发，产出成对会话
```

依赖方向严格单向向下，无回环。

### 5.2 三条关键边界

1. **协议层 ⟂ 传输层** —— 适配器只产出协议帧（Modbus ADU、CIP 报文、S7 PDU），完全不涉及 IP/TCP/以太。封装统一由 `transport/link.py` 落实。
   *收益*：Modbus TCP 与 RTU 复用同一套 PDU 构建器；S7 over TCP 与 S7 over ISO-on-TCP 同样可复用。
2. **产出层 ⟂ 生成层** —— 生成器只负责造字节；写盘（pcap/bin/hex/manifest）是独立环节。
   *收益*：同一份产物可同时供 Wireshark 分析与单元测试断言，互不污染。
3. **合法 ⟂ 异常 ⟂ 变异** —— 三者在**模型层**用 `Tier` 区分，异常由场景显式声明（`variant`），变异产物带 `parent_id` 与 `mutation` 溯源。不依赖文件名约定。

### 5.3 目录结构

```
ics/
├── pyproject.toml
├── README.md
├── icsgen/
│   ├── __init__.py
│   ├── cli.py                       # Typer/Click 命令面
│   ├── codec/                       # 字段表驱动的二进制编解码内核
│   │   ├── fields.py                # 字段类型与修饰符定义
│   │   ├── encoder.py               # 按字段表编码
│   │   └── decoder.py               # 按字段表解码
│   ├── spec/
│   │   ├── model.py                 # Scenario / Operation / Tier / Variant
│   │   ├── loader.py                # YAML → model，JSON Schema 校验
│   │   └── schema.py                # 由 catalog 反向生成 JSON Schema
│   ├── protocols/
│   │   ├── base.py                  # ProtocolAdapter / ProtocolFrame / OperationSpec
│   │   ├── registry.py              # op 名 → adapter 路由
│   │   └── modbus/
│   │       ├── adapter.py           # Modbus TCP / RTU 适配器
│   │       ├── layouts.py           # 功能码 → 字段布局（catalog 的数据来源）
│   │       ├── framing.py           # MBAP / RTU 组帧
│   │       ├── crc.py               # RTU CRC16
│   │       └── catalog.yaml         # 操作目录
│   ├── transport/
│   │   ├── spec.py                  # TransportSpec
│   │   ├── link.py                  # Ethernet/IP/TCP/UDP/串口 封装
│   │   └── pcap.py                  # pcap 写出
│   ├── emit/
│   │   ├── raw.py                   # .bin / .hex 纯协议帧导出
│   │   └── dataset.py               # 分层数据集组装 + manifest
│   ├── mutate/
│   │   ├── engine.py                # 变异引擎
│   │   └── rules.py                 # 12 条变异规则
│   ├── server/
│   │   ├── base.py                  # PlcServer 契约
│   │   └── modbus_server.py         # 基于 pymodbus
│   └── paths.py                     # 默认路径常量
├── scenarios/
│   └── modbus_demo.yaml
├── datasets/                        # 输出（.gitignore）
└── tests/
```

## 6. 核心数据模型

### 6.1 场景与操作

```python
class Tier(str, Enum):
    LEGIT = "legit"        # 规范允许的正常交互
    ABNORMAL = "abnormal"  # 协议级异常（非法功能码、越界、异常响应）
    MUTATED = "mutated"    # 变异引擎产物

class Variant(str, Enum):
    NORMAL = "normal"
    BOUNDARY = "boundary"      # 边界值（如 quantity 取上限）
    EXCEPTION = "exception"    # 协议异常响应
    ILLEGAL_FC = "illegal_fc"  # 非法功能码
    MALFORMED = "malformed"    # 结构损坏

@dataclass(frozen=True)
class Operation:
    op: str                              # "modbus.read_holding_registers"
    params: dict[str, Any]
    variant: Variant
    tier: Tier
    expect_response: bool = True
```

`expect_response` 用于区分"主动请求（应有响应）"与"主动请求（不应有响应，如广播写）"。

**variant → tier 的映射规则**（唯一来源，loader 与 adapter 均遵守）：

| variant | tier |
|---|---|
| `normal` | `legit` |
| `boundary` | `legit`（边界值本身仍是规范允许的合法请求） |
| `exception` | `abnormal` |
| `illegal_fc` | `abnormal` |
| `malformed` | `abnormal` |

场景中可显式覆盖 `tier`，但覆盖值必须与上表一致，否则 loader 报错 —— 避免 tier 与 variant 语义冲突。`mutated` tier 不由场景声明，只能由变异引擎产生。

### 6.2 帧与产物

```python
@dataclass(frozen=True)
class TransportSpec:
    kind: Literal["tcp", "udp", "serial"]
    dport: int = 502
    sport: int | None = None            # None 表示按流递增
    src_ip: str = "192.168.1.10"
    dst_ip: str = "192.168.1.20"
    mac_src: str = "02:00:00:00:00:01"
    mac_dst: str = "02:00:00:00:00:02"
    vlan_id: int | None = None

@dataclass(frozen=True)
class ProtocolFrame:
    payload: bytes                      # 纯协议帧
    transport: TransportSpec
    metadata: dict[str, Any]            # 语义元数据，如 fc=3, area="holding", addr=0, qty=3

@dataclass(frozen=True)
class RenderedPacket:
    bytes: bytes                       # 完整链路字节
    frame: bytes                       # 纯协议帧（冗余保存，便于导出 bin/hex）
    metadata: dict[str, Any]

@dataclass(frozen=True)
class Artifact:
    id: str                            # "<protocol>.<op>#<n>"
    protocol: str
    transport: str
    op: str
    variant: str
    tier: str
    payload: bytes
    metadata: dict[str, Any]
    parent_id: str | None = None        # 变异产物溯源
    mutation: dict[str, Any] | None = None
```

`metadata` 是一等公民：语义信息随帧走，后续按操作类型检索或用 tshark 按语义过滤时无需反解析。

## 7. 协议适配器契约

```python
# icsgen/protocols/base.py
@dataclass(frozen=True)
class OperationSpec:
    name: str                          # "modbus.read_holding_registers"
    params_schema: dict                # JSON Schema
    summary: str                       # 人类可读说明，进 `ops list` 输出
    variants: tuple[str, ...]          # 该操作支持的变体

class ProtocolAdapter(Protocol):
    name: str
    operations: Mapping[str, OperationSpec]

    def build(self, op: Operation, ctx: BuildContext) -> ProtocolFrame: ...
```

**适配器不自己造 catalog。** `catalog.yaml` 声明操作元数据，Python 构建函数实现行为，二者通过 op 名关联：

- `ops list` 的帮助输出直接来自 catalog，新增操作自动出现在 CLI
- 参数校验走统一 JSON Schema，参数写错（如 `count: "three"`）会明确报错，而非生成畸形包
- 同一操作通过 `variant` 参数区分语义，而非拆成不同 op 名 —— 保证 catalog 不膨胀，同时数据集仍可按 op 名聚合

**BuildContext** 携带场景级上下文（会话 id、传输参数、默认设备地址、随机数发生器），供构建函数生成如事务 id、序列号等字段。

### 7.1 Modbus 适配器要点

- PDU 编码由 §4.4 的**字段表驱动内核**完成，字段布局来自 `icsgen/protocols/modbus/layouts.py`（catalog 的数据来源）
- 补齐 Scapy 缺失的 FC0x0B / 0x0C / 0x0F / 0x14–0x18 与诊断子功能 0x05 / 0x06 / 0x08 / 0x15
- TCP：MBAP 头（事务 id、协议 id、长度、单元 id）+ PDU
- RTU：地址 + PDU + CRC16，CRC 实现自行核对（不依赖 Scapy 的 ADU 层细节）
- 语义元数据至少包含：`fc`、`unit_id`、`start_addr`、`quantity`、`values`
- 异常响应（FC | 0x80 + 异常码）作为独立 variant 生成

## 8. 操作目录（catalog）

### 8.1 格式

catalog 位于 `icsgen/protocols/<proto>/catalog.yaml`，声明**操作元数据与参数 schema**；**字段布局**位于同目录的 `layouts.py`，由 catalog 通过 `layout:` 字段名引用。布局放 Python 而非 YAML 的原因：诊断功能码的 21 个子功能共享同一字段布局、仅 `sub_function` 默认值不同，用 Python 可程序化批量生成，避免 YAML 里重复 21 遍。

```yaml
protocol: modbus
transports: [tcp, rtu]
operations:
  - name: modbus.read_holding_registers
    summary: 读保持寄存器 (FC03)
    layout: fc03
    variants: [normal, boundary, exception]
    params:
      start_addr:
        type: integer
        minimum: 0
        maximum: 65535
        default: 0
      quantity:
        type: integer
        minimum: 1
        maximum: 125
        default: 1
```

字段布局（`layouts.py` 中的等价声明）：

```python
LAYOUTS = {
    "fc03": Layout(
        request=[
            Field("start_addr", "uint16"),
            Field("quantity", "uint16"),
        ],
        response=[
            Field("byte_count", "uint8", count_of="values"),
            Field("values", "uint16", count_from="byte_count"),
        ],
    ),
}
```

新增操作类型 = 加一条 catalog YAML（+ 必要时一个布局），**不修改框架代码**。

catalog 条目**不声明 tier**：语义层由变体唯一决定（§5 的 variant → tier 映射表）。catalog 里再写一个 tier 就成了第二个事实源，对同时支持 `normal` 与 `exception` 的操作类型必然自相矛盾。加载期直接拒绝未知字段，写错的 catalog 在启动时就失败。

### 8.2 Modbus 首批条目（P1 目标 ≥ 90）

**操作类型构成**：

| 来源 | 说明 | 数量 |
|---|---|---|
| 规范功能码 | FC 0x01–0x08, 0x0B, 0x0C, 0x0F, 0x10, 0x11, 0x14–0x18 | 17 |
| MEI | FC 0x2B 子类型 0x0E Read Device Identification（basic / specific 两种访问方式） | 2 |
| 诊断子功能 | FC 0x08 的 21 个子功能各自独立成一个操作类型 | 21 |
| 协议级异常 | `modbus.illegal_function_code`（非法功能码由 catalog 条目的 `func_code` 声明） | 1 |
| **操作类型合计** | | **41** |

> `0x12` 是保留空档（`0x11` 与 `0x14` 之间），规范中不存在「读文件记录」功能码 —— 读文件记录是 `0x14`，写文件记录是 `0x15`。

**条目计数模型**：一条覆盖条目 = 一个 (操作类型, 变体, 传输) 组合。catalog 中每个操作类型声明自己的变体集合，catalog 顶层声明适用的传输集合，因此

**覆盖条目数 = Σ(每个操作类型的变体数) × 传输数**

| 变体 | 说明 | 适用性 |
|---|---|---|
| `normal` | 规范内正常值 | 全部操作类型 |
| `exception` | 协议异常响应（FC \| 0x80 + 异常码） | 全部操作类型 |
| `boundary` | 参数取边界/越界值 | 仅参数型操作类型 |

计数（41 个操作类型共 96 个 (操作类型, 变体) 组合，传输 TCP 与 RTU 各一份）：

| 传输 | 条目数 |
|---|---|
| TCP | 96 × 1 = 96 |
| RTU | 96 |
| **合计** | **192** |

192 ≥ 90，满足 §15 指标且留有余量。**覆盖条目数**是 §15 指标的唯一度量口径，由 `Catalog.coverage_count()` 计算（`Σ(len(entry.variants)) × len(transports)`），CI 断言与 `icsgen catalog --count` 共用这一口径。若个别操作类型的变体在实现中不适用（如 FC0x07 Read Exception Status 无参数，boundary 无意义），从 catalog 移除该变体并相应下调，**但总数不得低于 90**。

### 8.3 语义变体

| 变体 | 语义 | 示例 |
|---|---|---|
| `normal` | 规范内正常值 | `quantity=3` |
| `boundary` | 合法但取极值 | `quantity=125`（FC03 上限）/ `quantity=0` |
| `exception` | 协议异常响应 | funcCode = 原值 \| 0x80，exception_code=2（非法地址） |
| `illegal_fc` | 非法功能码 | 功能码取 catalog 条目声明的 `func_code`（如 `0x63` 保留值） |
| `malformed` | 结构损坏 | 长度字段与实际不符、字段截断 |

变体与参数的关系：catalog 声明该操作支持哪些变体；构建函数按 `variant` 施加对应的取值策略。**异常不是另写一套操作**，而是同一操作的可变体 —— 这样 catalog 规模可控，数据集仍能按 op 名聚合。

## 9. 场景文件格式

```yaml
name: modbus_demo
description: Modbus 读写混合演示场景
transport:
  kind: tcp
  src_ip: 192.168.1.10
  dst_ip: 192.168.1.20
  dport: 502
operations:
  - op: modbus.read_holding_registers
    params: {start_addr: 0, quantity: 3}
    variant: normal
  - op: modbus.write_multiple_registers
    params: {start_addr: 100, values: [0xDEAD, 0xBEEF]}
    variant: normal
  - op: modbus.read_holding_registers
    params: {start_addr: 0, quantity: 200}   # 越界
    variant: boundary
  - op: modbus.illegal_function_code
    variant: illegal_fc                      # 非法功能码，取 catalog 条目声明的 func_code
```

- `params` 经 JSON Schema 校验；未知键报错（参数集合以 catalog 条目声明为唯一事实源）
- `variant` 省略时取 catalog 声明的默认变体
- 顶层可声明 `repeat` 展开同一操作多次

## 10. 传输与封装层

`transport/link.py` 依据 `TransportSpec` 生成链路字节：

| kind | 封装 |
|---|---|
| `tcp` | Ethernet → IP(v4) → TCP（含正确 checksum）→ 协议帧 |
| `udp` | Ethernet → IP(v4) → UDP → 协议帧 |
| `serial` | 裸协议帧（RTU），无以太网封装；pcap 中以 Linux SLL 记录 |

TCP 流细节：

- 同一场景内端口与序列号按流递增，保证 pcap 中的会话连贯、可用 tshark 正确重组
- 事务 id（Modbus MBAP）由 BuildContext 的确定性发生器分配，同一场景可复现

## 11. 产出层

### 11.1 布局

```
datasets/<dataset_name>/
├── manifest.json
├── legit/
│   └── modbus_tcp/
│       ├── session.pcap                # 该 tier 下的会话（请求+响应连续）
│       └── frames/
│           ├── modbus.read_holding_registers#001.bin
│           ├── modbus.read_holding_registers#001.hex
│           └── ...
├── abnormal/modbus_tcp/...
└── mutated/modbus_tcp/...
```

- **一次操作 = 一个 Artifact**。
- **pcap 按 (tier, transport) 聚合**，而非按场景聚合。理由：分层数据集的核心诉求是合法与异常互不污染；若合法与异常混在同一个 pcap，分层在最终产物上就失效了。按 tier 拆分后，每个 pcap 内部仍是连贯的会话序列（Wireshark 中可完整追踪请求/响应配对），同时保持数据集分层干净。
- 一个场景中同一 tier 的多个操作，按场景中的声明顺序进入同一 pcap；跨 tier 不混排。
- **`.bin` 导出的是纯协议帧**，不含 IP/TCP 头。理由：协议栈单元测试要断言的是 ADU/PDU 字节，不应掺入 20 字节 TCP 头。pcap 则是完整链路帧。两种用途各自纯净。

### 11.2 manifest.json

```json
{
  "dataset": "modbus_demo",
  "generated_at": "2026-10-30T12:00:00Z",
  "protocols": ["modbus"],
  "counts": {"legit": 64, "abnormal": 32, "mutated": 0},
  "artifacts": [
    {
      "id": "modbus.read_holding_registers#001",
      "protocol": "modbus",
      "transport": "tcp",
      "op": "modbus.read_holding_registers",
      "variant": "normal",
      "tier": "legit",
      "len": 12,
      "sha256": "…",
      "pcap_file": "legit/modbus_tcp/session.pcap",
      "pcap_index": 0,
      "meta": {"fc": 3, "area": "holding", "start_addr": 0, "quantity": 3}
    }
  ]
}
```

`pcap_file` + `pcap_index` 标明该 artifact 所在 pcap 文件与包序号，便于测试直接定位。变异产物额外带 `parent_id` 与 `mutation` 字段。

## 12. 变异引擎

自研、规则驱动、**确定性可复现**（同 seed + 同输入 ⇒ 同输出）。

### 12.1 规则集（12 条）

| 规则 | 行为 |
|---|---|
| `bit_flip` | 翻转随机 bit |
| `byte_flip` | 随机字节取反 |
| `byte_set` | 随机字节替换为指定值 |
| `truncate` | 截断至任意长度 |
| `extend_garbage` | 追加随机垃圾字节 |
| `length_field_corrupt` | 篡改长度字段（Modbus MBAP length / S7 TPKT length 等，按协议映射） |
| `func_code_corrupt` | 篡改功能码 / 服务 ID |
| `address_corrupt` | 篡改地址字段 |
| `value_extreme` | 数值置极值（0x00 / 0xFF / 0x7FFF / 0x8000） |
| `crc_corrupt` | 破坏 CRC（RTU CRC16、PROFIsafe CRC 等） |
| `duplicate_replay` | 复制帧 / 重放 |
| `interleave_frames` | 两帧交错 |

每条规则可声明适用协议与字段白名单（如 `length_field_corrupt` 对 Modbus 改 MBAP length、对 S7 改 TPKT length）。

### 12.2 溯源

每个变异产物记录：`{rule, seed, offset, original_sha256}`，可反推原始合法样本与变异位置。变异产物的 `tier` 恒为 `mutated`。

## 13. PLC 服务端模拟

### 13.1 契约

```python
class PlcServer(Protocol):
    def start(self) -> None: ...
    def stop(self) -> None: ...
    @property
    def address(self) -> str: ...       # "tcp://0.0.0.0:5020"
```

### 13.2 P1 实现（Modbus）

基于 `pymodbus`，双角色：

| 角色 | 行为 | 流量价值 |
|---|---|---|
| `plc` | 被动应答，模拟真实 PLC 被读写 | 产出请求方向的服务端响应包 |
| `client` | 主动发起请求并接收响应 | **产出成对的请求/响应会话**，是最真实的流量来源 |

- TCP：`pymodbus` server 直连
- RTU：经 `pty` 伪终端注入真实串口帧（保留完整时序）
- 抓包：`tcpdump -i any` 抓取，或直接用 pymodbus 的报文钩子写入 pcap

### 13.3 后续阶段

| 阶段 | 方案 |
|---|---|
| P2 ENIP/CIP | 自研 ENIP server（RegisterSession / SendRRData / SendUnitData） |
| P3 S7 | `snap7.server`（python-snap7 自带服务端）+ 自研 S7 报文侧校验 |
| P4 OPC UA | `asyncua` server |

## 14. CLI

```
icsgen ops list    --protocol modbus [--variant abnormal] [--json]
icsgen ops show    modbus.read_holding_registers
icsgen validate   <scenario.yaml>
icsgen generate   <scenario.yaml> -o datasets/demo [--formats pcap,bin,hex] [--tier legit,abnormal]
icsgen mutate     datasets/demo -o datasets/fuzz --rules all --seed 42
icsgen serve      --protocol modbus --transport tcp --port 5020 --role client
icsgen catalog    --protocol modbus --count        # 统计覆盖条目数（CI 防退化用）
```

- `icsgen` 同时是可 `import` 的库（`import icsgen`），CLI 只是薄封装
- 所有命令支持 `--seed`（确定性）与 `--json`（机器可读输出）

## 15. 丰富度指标与防退化

操作类型数量是**可验收的硬指标**，写入 CI：

| 阶段 | 协议 | 操作条目数下限 | 检查命令 |
|---|---|---|---|
| P1 | Modbus TCP + RTU | 覆盖条目数 ≥ 90 | `icsgen catalog --protocol modbus --count` |
| P2 | EtherNet/IP + CIP | ≥ 110 | 同上 |
| P3 | S7comm | ≥ 60 | 同上 |
| P4 | Profinet / OPC UA / IEC104 | ≥ 140 | 同上 |

同时 CI 断言：

- catalog 中每条 op 的 `builder` 可解析、`params_schema` 合法
- 每个声明支持的 variant 都能实际构建成功（构建器覆盖率检查）
- 场景 golden 快照不回归

## 16. 测试策略

| 层次 | 内容 |
|---|---|
| 单元 | adapter 往返：build → Scapy 解析 → 断言语义等价；Scapy 实现有缺陷的功能码（FC0x18、FC0x0C）与诊断子功能按规范逐字节对照 |
| 校验 | 场景 YAML 的正例通过、反例报错（未知 op、参数越界、variant 不支持） |
| Golden | 场景 → payload 的 sha256 快照，防字节级回归 |
| 集成 | 生成 pcap → `scapy.rdpcap()` 读回 → 断言包数、字段与 manifest 一致 |
| 变异 | 变异产物喂回 Scapy 解析器，确保不产生未捕获异常（框架自身健壮性） |
| 服务端 | 起 pymodbus server（plc / client 双角色），验证请求-响应成对、帧内容符合预期 |
| 指标 | catalog 条目数 ≥ §15 阈值 |

## 17. 依赖

| 依赖 | 版本 | 用途 |
|---|---|---|
| scapy | ≥ 2.6 | 链路封装 + 第三方交叉验证解析器（不再作为 Modbus PDU 基座，见 §4.4） |
| pymodbus | ≥ 3.8 | Modbus 服务端模拟 |
| pydantic | ≥ 2.0 | catalog 与场景的模型定义、校验；并由模型反向导出 JSON Schema |
| jsonschema | ≥ 4.20 | 校验 catalog 声明的 `params_schema` 对用户传入的 `params` 是否合规 |
| typer | ≥ 0.9 | CLI |
| pyyaml | ≥ 6.0 | 场景 / catalog 解析 |
| pytest | ≥ 8.0 | 测试 |

校验链路分工：catalog 的元 schema 与场景结构由 pydantic 校验；用户传入的**操作参数**由 catalog 的 `params_schema` 经 jsonschema 校验。

二进制编解码内核为**自研**（§4.4），不引入 `construct` 等二进制 DSL 库。

后续阶段追加：`python-snap7`（P3）、`asyncua`（P4）。

## 18. 风险与缓解

| 风险 | 影响 | 缓解 |
|---|---|---|
| Scapy Modbus 缺 4 个功能码 | 部分操作无法生成 | 在适配器层补充实现（§4.3），并与规范逐字节对照测试 |
| Scapy 无 CIP / S7 层 | P2/P3 需从零自研 | 以 snap7 枚举与公开规范为参照；自研层与 Scapy 保持解耦 |
| CIP 应用层（~100 service）工作量超出预期 | P2 延期 | P2 内部再分批；先覆盖连接管理与显式消息主路径 |
| 变异产物使生成器自身崩溃 | 工具不可用 | 变异后默认做一次 Scapy 解析回归，异常则标记 `mutated_unparsable` 而非中断 |
| pcap 校验和错误导致 Wireshark 告警 | 影响人工分析 | 链路层自行计算 IP/TCP/UDP checksum，不依赖 Scapy 默认行为；集成测试用 tshark 验证 |
| 目录非 git 仓库 | 变更无版本追踪 | 初始化 git 仓库（待用户确认） |

## 19. 未决问题

1. **CLI 框架选型**：Typer（依赖 FastAPI 系生态，类型注解友好）vs Click（更轻，无额外依赖）。倾向 Typer。
2. **catalog 的 DSL 是否需要表达式**：如 `quantity: "min(125, cfg.max)"`。P1 先用静态默认值 + 参数覆盖，表达式留待 P2 评估。
3. **是否需要 GUI / Web 界面**：本 spec 明确只做 CLI + 库，不做界面。若后续需要可视化浏览数据集，可另起 spec。
4. **数据集的版本化**：是否用 git-lfs 或 DVC 管理大数据集。P1 用普通目录 + manifest 中的 sha256 做完整性校验即可。
