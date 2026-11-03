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
- **串口传输的 pcap 用 Linux SLL 记录**，帧体是裸 RTU 字节，与 spec §10 一致。

## 变异引擎

变异以**一次操作**为单位：请求帧与响应帧构成一段会话，规则作用于整段会话。

```bash
icsgen mutate datasets/demo -o datasets/fuzz --rules all --seed 42
```

- 单帧规则（`bit_flip`、`truncate`、`func_code_corrupt` 等 10 条）只改请求帧，响应保持设备对合法请求的正常应答。
- 成对规则作用于整段会话：`duplicate_replay` 在会话末尾重放请求帧，`interleave_frames` 把请求与响应逐字节交错、合并成一帧。
- 变异结果按源数据集 manifest 里记录的链路参数重新封装，进入 `mutated` 层的 `session.pcap`，与其它层结构一致。
- 同一 seed 与同一输入必得同一输出；产物记录 `mutation` 溯源（规则名、seed、偏移、原始哈希）。

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
