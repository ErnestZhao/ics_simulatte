# icsgen Phase 0 内核升级 + P2（EtherNet/IP + CIP）— 设计规格

日期：2026-11-04
状态：待评审
关联规格：`2026-10-30-ics-traffic-generator-design.md`（P1-P4 路线与核心抽象）、
`2026-11-03-icsgen-web-ui-design.md`（Web 层）、`2026-11-03-tcp-session-flow-design.md`（TCP 会话）

---

## 1. 背景与目标

P1（Modbus TCP + RTU）已交付：41 个操作类型 / 192 条覆盖条目，Web 交互界面、
TCP 完整会话、分层数据集、变异引擎、PLC 模拟器都可用。它建好的抽象 —— catalog 驱动的
操作定义、协议注册表、传输层、分层数据集 —— **全部是协议无关的**，新协议接进来不用改框架。

但 P2 开工前有三处内核缺口挡路，另有两处 P1 欠账要还。

### 1.1 三处内核缺口

| 缺口 | 现状 | 阻塞了什么 |
|---|---|---|
| 变体规划住在 Modbus 包里 | `icsgen/protocols/modbus/variants.py` 实际是协议无关的（只 import `spec.model.Variant`），却住在 Modbus 包内 | P2 的 CIP 变体没有地方放；硬搬一份就是复制 |
| codec 缺 `array[T]` / `bitfield` | 规格 §4.4 承诺了这两种字段类型，实际只有 `uint8/int8/uint16/int16/uint32/int32/bytes` | CIP 的定长数组与 P3/P4 的位域字段无处声明 |
| 变异规则硬编码 Modbus 字节偏移 | `length_field_corrupt` 改第 4-5 字节（MBAP 长度）、`func_code_corrupt` 改第 0 字节、`address_corrupt` 改第 2-3 字节、`crc_corrupt` 改末字节 | 对 ENIP/CIP 全是改错位置 —— 变异出来的「坏包」其实没坏在长度字段上 |

### 1.2 两处 P1 欠账

| 欠账 | 现状 | 规格出处 |
|---|---|---|
| 串口（RTU）PLC 服务端未实现 | `run_modbus_server` 接受 `transport="serial"` 但只做了参数校验，pty 方案没落地 | §13.2「RTU：经 `pty` 伪终端注入真实串口帧」 |
| CI 防退化缺失 | 仓库无任何 CI 配置；§15 要求「catalog 条目数 ≥ 阈值」由 CI 断言 | §15 |

### 1.3 本期的目标

1. **Phase 0**：把上面三处缺口补上，让 P2 能站在协议无关的地基上；同时还清两处 P1 欠账。
2. **P2**：交付 EtherNet/IP + CIP 协议族 —— 封装层 + 应用层 + 操作目录 + 适配器 +
   数据集产出，覆盖条目 **≥ 110**（§15 的 P2 门槛）。

**本期不做**：ENIP 服务端。理由：规格 §13.3 把它列在 P2，但服务端的真正价值是
「跑真实请求-响应并抓包」，而那正是 **P5（真实流量采集层）** 的定义。把它挪到 P5，
P2 专注帧生成侧，P5 专注服务端与真实采集侧，两边都更干净。

### 1.4 P5 的定义（本期确定，一并记入路线）

**P5 = 真实流量采集层**：让 PLC 模拟器（`plc` / `client` 双角色）跑真实的请求-响应，
把抓到的包写成与生成器**同构**的 pcap + manifest。产出的数据集既有合成的，也有真实抓的。
落地形态：

- `icsgen capture --protocol modbus --role client --duration 30 -o datasets/real`
- ENIP 服务端也在 P5 一并自研（§13.3 定的 RegisterSession / SendRRData / SendUnitData）
- 串口服务端（pty 方案）也在 P5 一并落地 —— 真实串口帧的价值离不开真串口时序

---

## 2. 范围

### 2.1 本期交付

| 阶段 | 内容 |
|---|---|
| Phase 0.1 | 变体规划下沉到协议无关模块；Modbus 改为引用，**逐字节输出不变** |
| Phase 0.2 | codec 补 `array[T]` 与 `bitfield` 字段类型 |
| Phase 0.3 | 变异层协议感知化：每协议声明字段白名单，规则按声明取字节位置 |
| Phase 0.4 | CLI 协议选择：`validate` / `generate` / `ops show` 加 `--protocol` |
| Phase 0.5 | 串口（RTU）PLC 服务端落地（pty 方案） |
| Phase 0.6 | GitHub Actions CI：跑全套测试 + 断言各协议覆盖条目 ≥ §15 阈值 |
| P2.1 | ENIP 封装层：头、命令数据块、SendRRData / SendUnitData / RegisterSession / ListIdentity / ListInterfaces / ListServices / UnregisterSession |
| P2.2 | CIP 应用层：服务码表、通用状态码表、EPATH 编解码、请求/响应消息结构 |
| P2.3 | ENIP catalog：≥ 40 个操作类型（封装层命令 + CIP 通用服务 + 标签服务 + 连接管理器服务） |
| P2.4 | 适配器 + `inspect`（Web 预览）+ 注册表登记一行 |
| P2.5 | 端到端：数据集产出、变异层对 ENIP 生效、覆盖条目 ≥ 110 的 CI 断言 |

### 2.2 非目标

- 不做隐式（I/O）消息的周期数据生成 —— 隐式消息靠连接路径与 RPI 驱动，与显式消息是
  另一套机制，本期只做显式。
- 不做 CIP 设备描述文件（EDS/DD）解析。
- 不做 ENIP 服务端（见 §1.3）。
- 不做 P3/P4 的任何协议代码。

---

## 3. 关键设计决策

### 3.1 变体规划下沉到 `icsgen/protocols/variants.py`

`icsgen/protocols/modbus/variants.py` 里的 `plan_variant` / `VariantPlan` 不含任何 Modbus 知识
（`func_code` 这个字段名虽带 Modbus 味，但它是「本操作的服务码」，语义协议无关）。
本期把它移到 `icsgen/protocols/variants.py`，Modbus 包改为 `from ..variants import ...` 转发。

**判据**：Modbus 的**现有行为逐字节不变** —— 既有 golden 快照与 313 条测试全绿。
`func_code` 字段名保留不改（改名会波及 Modbus 的 catalog 语义与测试），在新模块的文档串里
说明它指「本操作的服务码」。

### 3.2 codec 的 `array[T]` 与 `bitfield`

**`array[T]`** —— 定长数组。声明：`type: "array[uint16]"`、`count: 3`。
编码按 `count` 个元素逐个打包；解码按 `count` 个元素读出。

**`bitfield`** —— 位域。声明：`type: "bitfield"`、`bit_width: 16`、`bit_fields: {名称: 位宽}`。
位域在大端位序里从最高位开始分配（先声明的占高位）。编码时把各字段值按位宽拼进一个整数再
写成 `bit_width / 8` 字节；解码时反向拆开。

两者的宽度都由声明算出，**不引入新的类型宽度常量表条目** —— `array[T]` 的宽度是 T 的宽度，
`bitfield` 的宽度是 `bit_width / 8`。

### 3.3 变异层协议感知化：每协议声明字段白名单

新增 `icsgen/protocols/<proto>/mutation.yaml`，声明该协议四个概念的字节位置：

```yaml
# icsgen/protocols/modbus/mutation.yaml
protocol: modbus
fields:
  length: {offset: 4, width: 2, endian: big}    # MBAP 长度字段
  code:   {offset: 0, width: 1, endian: big}    # 功能码
  address: {offset: 2, width: 2, endian: big}   # 起始地址
  crc:    {offset: -2, width: 2, endian: big}    # 末两字节（负偏移表示从尾部数）
```

- `offset` 为负时表示从帧尾往回数（`crc` 天然在尾部）。
- 概念名固定四个：`length` / `code` / `address` / `crc`。协议没有的概念就不声明；
  规则遇到未声明的概念 → **该规则在当前协议上不适用**（返回 `None`，与「输入不足」同一语义）。
- `endian` 取 `big` / `little`（ENIP 是小端，Modbus 是大端）。

**为什么是数据而不是代码**：变异规则本身是协议无关的（翻转 bit、截断、追加垃圾），
协议相关的是「哪个字节是长度字段」。把位置声明成数据，新增协议只加一个 YAML，
不改 `mutate/` 里的任何代码。

**Modbus 的行为不变**：现有的 4 条硬编码规则改为查表，取到的字节位置与现在完全一致
（MBAP 长度在第 4-5 字节、功能码在第 0 字节、起始地址在第 2-3 字节、CRC 在末两字节）。
既有变异测试的期望输出必须逐字节不变。

### 3.4 CLI 协议选择

`validate` / `generate` / `ops show` 现在硬编码 Modbus。加 `--protocol`（默认 `modbus`），
按注册表取 catalog 与适配器。`ops list` 已有 `--protocol`。

`generate` 的适配器从注册表取（`get_adapter(protocol)`），不再直接 import Modbus 适配器。

### 3.5 ENIP / CIP 的分层

```
icsgen/protocols/enip/
├── catalog.yaml      操作目录（≥ 40 条）
├── mutation.yaml     变异字段白名单
├── framing.py        ENIP 封装头与命令数据块
├── epath.py          EPATH 段的编解码
├── cip.py            CIP 服务码表、通用状态码表、消息结构
├── layouts.py        字段布局与服务描述
├── adapter.py        适配器
└── inspect.py        帧解析（Web 预览）
```

- **协议名 `enip`**，操作名统一 `enip.*` 前缀。CIP 是 EtherNet/IP 家族的应用层，
  用 `enip.get_attribute_single` 这样的名字比 `cip.*` 更能体现「一个协议、一份目录」。
  CIP 服务在 `summary` 里点名（`CIP 读单个属性 (Get_Attribute_Single 0x03)`）。
- **ENIP 封装是小端**，CIP 消息体也是小端。这与 Modbus 的大端相反，是最容易写错的地方，
  测试必须显式断言。

---

## 4. ENIP 封装层（P2.1）

### 4.1 封装头（24 字节，小端）

| 偏移 | 长度 | 字段 | 说明 |
|---|---|---|---|
| 0 | 2 | `command` | uint16 LE，见 §4.2 |
| 2 | 2 | `length` | uint16 LE，后续数据字节数（不含本头） |
| 4 | 4 | `session` | uint32 LE，会话句柄 |
| 8 | 4 | `status` | uint32 LE，0 表示成功 |
| 12 | 8 | `sender_context` | 8 字节，原样回送 |
| 20 | 4 | `options` | uint32 LE，0 |

`sender_context` 由 `BuildContext.transaction_id` 派生：前 4 字节放事务 id（小端），
后 4 字节放 0 —— 响应原样回送同一段，请求与响应因此可配对。

### 4.2 命令码（取自 ODVA CIP Vol 2 / Scapy `contrib/enipTCP.py`）

| 命令 | 值 | 数据块 |
|---|---|---|
| ListServices | 0x0004 | 空 |
| ListIdentity | 0x0063 | 空 |
| ListInterfaces | 0x0064 | 空 |
| RegisterSession | 0x0065 | §4.3 |
| UnregisterSession | 0x0066 | 空 |
| SendRRData | 0x006F | §4.4 |
| SendUnitData | 0x0070 | §4.4 |

> Scapy 的 `enipTCP.py` 独立实现了这一层，本期把它当**交叉校验参照**：自研编码的字节
> 必须能被 `scapy.contrib.enipTCP.ENIPTCP` 解析出相同的 command/length/session/status。

### 4.3 RegisterSession 数据块

| 偏移 | 长度 | 字段 |
|---|---|---|
| 0 | 2 | `protocol_version`（1） |
| 2 | 2 | `options_flags`（0） |
| 4 | 2 | `reserved`（0） |

### 4.4 SendRRData / SendUnitData 数据块

| 偏移 | 长度 | 字段 |
|---|---|---|
| 0 | 4 | `interface_handle`（0） |
| 4 | 2 | `timeout`（0xFFFF） |
| 6 | 2 | `item_count`（1） |
| 8 | … | ItemData 列表 |

ItemData：

| 偏移 | 长度 | 字段 |
|---|---|---|
| 0 | 2 | `type_id`（0x00B2 = Unconnected Data Item） |
| 2 | 2 | `length` |
| 4 | … | `data`（CIP 消息） |

> SendUnitData 在 CIP 规范里还有连接 ID 与数据长度两个尾部字段。Scapy 的实现同样只到
> ItemData。本期按 Scapy 的口径实现（可被第三方解析器验证），尾部两字段列为 P5 的
> 待办 —— P5 做 ENIP 服务端时必须补齐，届时双向对齐。

---

## 5. CIP 应用层（P2.2）

### 5.1 请求消息结构

```
service         1 字节（通用服务）或 2 字节（连接管理器服务）
service_data    变长
path_size       1 字节，路径长度，单位是 2 字节
path            path_size × 2 字节
data            变长
```

### 5.2 响应消息结构

```
service         1 字节（请求服务码 | 0x80）
reserved        1 字节（0）
general_status  1 字节
add_status_size 1 字节
add_status      变长
data            变长
```

### 5.3 通用状态码（节选，完整表进 `cip.py`）

| 值 | 含义 |
|---|---|
| 0x00 | Success |
| 0x03 | Invalid parameter value |
| 0x04 | Path segment error |
| 0x05 | Path destination unknown |
| 0x08 | Service not supported |
| 0x09 | Invalid attribute value |
| 0x10 | Device state conflict |
| 0x14 | Attribute not supported |
| 0x16 | Object does not exist |
| 0x24 | Invalid message format |

### 5.4 EPATH 段

| 段类型 | 含义 |
|---|---|
| 0x20 / 0x21 / 0x24 / 0x25 / 0x26 | 逻辑段：class(8) / instance(16) / attribute(16) / element count(16) / service id(8) |
| 0x00 / 0x01 | 网络段：1 字节 / 2 字节 |
| 0x80 / 0x81 / 0x82 / 0x83 | 符号段：8 位 / 16 位 / 32 位 / 符号名 |
| 0xA1 / 0xA2 / 0xA3 | 数据段：8 位 / 16 位 / 32 位 |
| 0x01 | 端口段（2 字节） |

典型路径 `0x20 <class> 0x24 <instance> 0x30 <attribute>`：逻辑 8 位 class 段、
逻辑 16 位 instance 段、符号 16 位 attribute 段。

### 5.5 服务码表

**通用服务（1 字节）**：0x01 Get_Attributes_All、0x02 Set_Attributes_All、
0x03 Get_Attribute_Single、0x04 Set_Attribute_Single、0x05 Reset、0x06 Start、0x07 Stop、
0x08 Create、0x09 Delete、0x0A Multiple_Service_Packet、0x0B Apply_Attributes、
0x0D Get_Attribute_Single_Set、0x0E Set_Attribute_Single_Set、
0x10 Get_Attribute_Single_All、0x11 Set_Attribute_Single_All、
0x14 Enter_Set_Attribute_Mode、0x15 Exit_Set_Attribute_Mode、
0x16 Start_Application、0x17 Start_Session、0x18 Start_Session_All、
0x19 Get_Instance_Attribute_List、0x1A Set_Instance_Attribute_List、
0x1B Get_Instance_Attribute_List_All、
0x20 Read_Tag、0x21 Read_Modify_Write_Tag、0x23 Write_Tag、
0x24 Read_Modify_Write_Tag_Fragmented、0x52 Unconnected_Send。

**连接管理器服务（2 字节）**：0x0001 Forward_Open、0x0002 Forward_Close、
0x0003 Unconnected_Send、0x0004 Unconnected_Send_RRU、0x0005 Set_Config_Parameter、
0x0006 Get_Config_Parameter、0x0007 ListIdentity、0x0008 ListServices、
0x0009 ListInterfaces、0x000A RegisterSession、0x000B UnRegisterSession、
0x000C ListIdentity_All、0x000D ListInterfaces_All、0x0013 Close_Forward_Open。

---

## 6. 操作目录（P2.3）

### 6.1 清单（42 个操作类型）

**ENIP 封装层命令（6 个）**

| 操作名 | 命令 | 说明 |
|---|---|---|
| `enip.list_services` | 0x0004 | 列出协议支持的服务 |
| `enip.list_identity` | 0x0063 | 列出设备身份 |
| `enip.list_interfaces` | 0x0064 | 列出接口 |
| `enip.register_session` | 0x0065 | 注册会话 |
| `enip.unregister_session` | 0x0066 | 注销会话 |
| `enip.send_rr_data` | 0x006F | 发送请求-响应数据（承载 CIP 消息） |

**CIP 通用服务（23 个）**

`enip.get_attributes_all`、`enip.set_attributes_all`、`enip.get_attribute_single`、
`enip.set_attribute_single`、`enip.reset`、`enip.start`、`enip.stop`、`enip.create`、
`enip.delete`、`enip.multiple_service_request`、`enip.apply_attributes`、
`enip.get_attribute_single_set`、`enip.set_attribute_single_set`、
`enip.get_attribute_single_all`、`enip.set_attribute_single_all`、
`enip.enter_set_attribute_mode`、`enip.exit_set_attribute_mode`、
`enip.start_application`、`enip.start_session`、`enip.start_session_all`、
`enip.get_instance_attribute_list`、`enip.set_instance_attribute_list`、
`enip.get_instance_attribute_list_all`

**CIP 标签服务（4 个）**

`enip.read_tag`、`enip.read_modify_write_tag`、`enip.write_tag`、
`enip.read_modify_write_tag_fragmented`

**CIP 连接管理器服务（15 个）**

`enip.forward_open`、`enip.forward_close`、`enip.unconnected_send`、
`enip.unconnected_send_rru`、`enip.set_config_parameter`、`enip.get_config_parameter`、
`enip.cim_list_identity`、`enip.cim_list_services`、`enip.cim_list_interfaces`、
`enip.cim_register_session`、`enip.cim_unregister_session`、`enip.cim_list_identity_all`、
`enip.cim_list_interfaces_all`、`enip.close_forward_open`、
`enip.unconnected_send_common`（通用服务 0x52 版本）

> 连接管理器服务与封装层命令重名（ListIdentity / RegisterSession 等），故加 `cim_` 前缀区分；
> `unconnected_send` 与 `unconnected_send_common` 同理。

### 6.2 覆盖条目数

覆盖条目 = Σ(每个操作类型的变体数) × 传输数（传输只有 TCP，故 ×1）。

| 变体组 | 操作类型数 | 变体 | 小计 |
|---|---|---|---|
| 带参数的服务 | 30 | normal + boundary + exception | 90 |
| 无参数的服务 | 12 | normal + exception | 24 |
| **合计** | **42** | | **114** |

114 ≥ 110（§15 的 P2 门槛）。CI 断言 `icsgen catalog --protocol enip --count` ≥ 110。

**边界变体的参数上界**：`instance_id` 0xFFFFFFFF、`attribute_id` 0xFFFF、
`class_id` 0xFF、`tag_count` 8（规范上限）、`data_length` 由 `maxItems` 声明。
上界一律写在 catalog 的参数 schema 里，与 Modbus 一致（变体规划读 schema 的
`maximum` / `maxItems`）。

### 6.3 catalog 格式的扩展

CIP 的服务码有 1 字节与 2 字节两种宽度，同一个 `func_code` 整数在两个空间里会撞
（通用服务 0x0A 与连接管理器服务 0x000A 都是 10）。因此：

- `OperationEntry` 增加一个可选字段 `code_width: int = 1`（服务码字节宽度）。
  这是协议无关的字段，Modbus 不用它（恒为 1）。
- `func_code` 存**本操作的主码**：封装层命令存 ENIP 命令，CIP 服务存 CIP 服务码。
- 适配器的元数据同时给出 `enip_command` 与 `cip_service` 两个键，谁是什么一目了然，
  不靠 `func_code` 猜。

---

## 7. 适配器与注册表（P2.4）

### 7.1 适配器契约

沿用 `ProtocolAdapter`：`build` / `build_response` / `inspect`。

- `build`：产出完整 ENIP 帧（24 字节头 + 数据块）。
- `build_response`：`exception` 变体 → CIP 一般状态非 0 的响应（`service | 0x80`）；
  `malformed` 变体 → `None`（没有可解析的响应）。
- `inspect`：解析出命令、服务码、路径、状态码，供 Web 预览。

### 7.2 注册表

`icsgen/protocols/registry.py` 加一行登记 `enip`。**Web 层不改任何代码** ——
协议枚举走 `available_protocols()`，操作目录走 `get_catalog()`，预览走 `adapter.inspect()`。
本期要有一条测试专门守住这条承诺（新增协议后 Web 层零改动）。

### 7.3 端口

ENIP 的默认端口是 **44818**。`TransportSpec.dport` 的默认值仍是 502（Modbus），
ENIP 场景要显式写 `transport: {kind: tcp, dport: 44818}`。本期不改 `TransportSpec`
的默认值 —— 改默认值会让既有 Modbus 场景的产物字节变化。

---

## 8. 变异层对 ENIP 生效（P2.5）

`icsgen/protocols/enip/mutation.yaml`：

```yaml
protocol: enip
fields:
  length: {offset: 2, width: 2, endian: little}   # ENIP 头的小端长度字段
  code:   {offset: 0, width: 1, endian: little}   # CIP 服务码（在 CIP 消息体内）
  address: {offset: 8, width: 4, endian: little}  # CIP 路径里的 instance
  crc:    null                                     # ENIP 无 CRC
```

> `code` 与 `address` 指向的是 **CIP 消息体内**的位置，相对整帧的偏移取决于封装命令与
> 路径长度，是**变长**的。解决办法：白名单的偏移允许写成**相对锚点**的形式 ——
> `anchor: cip` 表示「相对 CIP 消息体起点」。ENIP 的 CIP 消息体起点是
> 24（封装头）+ 8（SendRRData 固定部分）+ 4（ItemData 固定部分）= 36。

本期采用**锚点**方案：`offset` 相对锚点计算，锚点由协议声明
（`enip` 的锚点是 36）。`crc: null` 表示该协议无此概念，对应规则不适用。

---

## 9. 边界与不变式

- **Modbus 行为零变化**：Phase 0 的三项改动（变体下沉、codec 扩字段类型、变异层查表）
  都不得改变 Modbus 的任何产出字节。既有 313 条测试 + golden 快照必须全绿。
- **codec 扩字段类型不影响既有布局**：新增的 `array[T]` 与 `bitfield` 是新类型，
  既有布局不引用它们，行为不变。
- **ENIP 小端**：ENIP 封装头与 CIP 消息体都是小端。写错端序是最可能的 bug，
  测试必须显式断言字节序，不能只断言「解出来相等」。
- **Scapy 交叉校验只覆盖封装层**：Scapy 没有 CIP 应用层，封装层的字节必须过
  Scapy 的 `ENIPTCP` 解析；CIP 层按 CIP 规范逐字段对照（规格 §4.5 的约定）。
- **变异层**：Modbus 的变异产物逐字节不变；ENIP 的变异产物要能落地 —— 长度字段
  被篡改后，`scapy` 解析应当失败或长度不符（这正是变异要的效果）。

---

## 10. 验收指标（可自动判定）

| # | 指标 | 判定方式 |
|---|---|---|
| 1 | 全套测试通过 | `python3 -m pytest -q -W error` |
| 2 | Modbus 产出逐字节不变 | 既有测试全绿 + 新增 golden 快照比对 |
| 3 | `array[T]` 编解码往返 | 单元测试：定长数组编码与解码对称 |
| 4 | `bitfield` 编解码往返 | 单元测试：多位域拼接与拆分对称，跨字节边界正确 |
| 5 | 变体规划下沉后 Modbus 行为不变 | 既有 Modbus 变体测试全绿 |
| 6 | 变异规则按白名单定位 | 单元测试：Modbus 白名单取到的偏移与旧硬编码一致 |
| 7 | ENIP 封装层能被 Scapy 解析 | 自研编码 → `ENIPTCP` 解析 → 断言各字段相等 |
| 8 | ENIP 字节序是小端 | 单元测试：显式断言头部字节 |
| 9 | CIP 请求/响应消息结构正确 | 单元测试：按 §5.1 / §5.2 逐字段断言 |
| 10 | EPATH 编解码往返 | 单元测试：逻辑段 / 符号段 / 数据段往返一致 |
| 11 | ENIP 操作类型数 ≥ 40 | `icsgen catalog --protocol enip` 断言 |
| 12 | ENIP 覆盖条目数 ≥ 110 | `icsgen catalog --protocol enip --count` 断言 |
| 13 | 每个声明的变体都能构建成功 | 构建器覆盖率检查（逐操作类型逐变体） |
| 14 | Web 层新增协议零改动 | 测试：注册新协议后 Web 的协议列表含它、页面可打开 |
| 15 | CLI 可按协议生成 | 测试：`icsgen generate --protocol enip` 产出数据集 |
| 16 | 变异层对 ENIP 生效 | 测试：ENIP 数据集跑 mutate 产出 mutated 层 |
| 17 | CI 配置存在并跑通 | `.github/workflows/ci.yml` + 本地 `act` 或等价验证 |

---

## 11. 文件改动

| 文件 | 改动 |
|---|---|
| `icsgen/protocols/variants.py` | **新增** —— 协议无关的变体规划（从 Modbus 包移出） |
| `icsgen/protocols/modbus/variants.py` | 改为转发到新模块（行为不变） |
| `icsgen/codec/fields.py` | 新增 `array[T]` 类型与 `bitfield` 类型；`Field` 增加 `count` / `bit_width` / `bit_fields` |
| `icsgen/codec/encoder.py` / `decoder.py` | 支持新类型 |
| `icsgen/codec/mutation.py` | **新增** —— 变异字段白名单的加载与解析 |
| `icsgen/protocols/modbus/mutation.yaml` | **新增** —— Modbus 的白名单声明 |
| `icsgen/mutate/rules.py` | 4 条硬编码规则改为按白名单定位 |
| `icsgen/mutate/engine.py` | 接受白名单参数 |
| `icsgen/cli.py` | `validate` / `generate` / `ops show` 加 `--protocol` |
| `icsgen/spec/catalog.py` | `OperationEntry` 增加 `code_width` |
| `icsgen/protocols/enip/*` | **新增** —— P2 的全部实现 |
| `icsgen/protocols/registry.py` | 登记 `enip` 一行 |
| `icsgen/server/modbus_server.py` | 串口（pty）角色落地 |
| `.github/workflows/ci.yml` | **新增** —— CI |
| `README.md` | 协议列表、操作目录统计、变异层白名单说明更新 |

---

## 12. 风险

| 风险 | 缓解 |
|---|---|
| CIP 的服务数据格式记错 | 每个服务在 catalog 里声明布局；布局由单元测试逐字节对照规范；Scapy 只覆盖封装层，缺口在测试里显式标注 |
| 覆盖条目数凑不够 110 | 42 个操作类型已在清单里定死；实现时变体集按 §6.2 的分组给足 |
| codec 扩字段类型影响 Modbus | 新类型不被既有布局引用；既有测试必须全绿 |
| 变异层白名单让 Modbus 变异产物变化 | 白名单取到的偏移与旧硬编码一致；既有变异测试逐字节比对 |
| ENIP 服务端缺位 | 本期明确不做（§1.3），挪到 P5 —— P5 的定义就是真实流量采集 |
