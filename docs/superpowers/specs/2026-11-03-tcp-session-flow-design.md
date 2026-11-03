# icsgen TCP 完整会话（握手 + 数据 + 挥手）— 设计规格

日期：2026-11-03
状态：待评审
关联规格：`2026-10-30-ics-traffic-generator-design.md`（P1 流量生成器）、`2026-11-03-icsgen-web-ui-design.md`（Web 层）

---

## 1. 背景与问题

TCP 层的 `session.pcap` 目前只有数据段，没有任何连接建立与关闭的过程。以
`scenarios/modbus_demo.yaml` 生成的 `legit/modbus_tcp/session.pcap` 为例（8 包）：

```
[0] 40001→502  PA  seq=0   ack=0   payload=12
[1] 502→40001  PA  seq=12  ack=12  payload=15
[2] 40001→502  PA  seq=10  ack=10  payload=17
...
```

两个问题：

1. **缺三次握手与四次挥手** —— pcap 里看不到连接建立与关闭，Wireshark 会把每一对
   报文当成独立的流，规则引擎无法按会话重放，仿真流量与真实扫描仪抓包不一致。
2. **序列号不成流** —— 客户端 seq 依次是 0、10、20、30，与载荷长度（12/17/12/12）
   无关；ACK 回显的是自己的 seq 而不是对端的 seq。TCP 层面这是无效的。

目标：TCP 会话文件里的包构成一次**完整、可被 Wireshark/Zeek 正确识别为单条 TCP
流的交互流程**，且序列号严格自洽。

## 2. 范围

### 2.1 本期交付

| 项 | 内容 |
|---|---|
| 会话形态 | 三次握手 → 数据交换 → 四次挥手，写进同一份 `session.pcap` |
| 序列号 | 完整的 TCP 序号状态机（SYN/FIN 各占 1 号，数据按载荷长度推进） |
| 声明式开关 | 传输配置新增 `session` 字段（`full` / `data`），默认 `full` |
| 变异层 | `mutated` 层按源 manifest 记录的会话形态重建，形态与源层一致 |
| 文档 | README 的产物布局与协议说明同步更新 |

### 2.2 非目标

- 不改 Web 页面的表单结构（新增字段有默认值，页面不需要改）。
- 不引入真实的 TCP 栈（不真的握一次手），全部是构造出来的字节。
- 不做 TCP 选项（MSS / SACK / 时间戳）—— 序列号与标志位自洽即可。
- 串口 RTU 与 UDP 不变（没有握手这回事）。

## 3. 目标形态

每个会话文件（= 一个 tier/transport，如 `legit/modbus_tcp/session.pcap`）里是**一条
TCP 连接**：

```
[0]      40001→502   SYN      seq=C0          ack=0
[1]      502→40001   SYN-ACK  seq=S0          ack=C0+1
[2]      40001→502   ACK      seq=C0+1        ack=S0+1
[3]      40001→502   PSH-ACK  请求1           seq=C0+1        ack=S0+1
[4]      502→40001   PSH-ACK  应答1           seq=S0+1        ack=C0+1+len(请求1)
[5]      40001→502   PSH-ACK  请求2           seq=C0+1+len(请求1)
...
[N]      40001→502   FIN-ACK  seq=…           ack=…
[N+1]    502→40001   ACK      seq=…           ack=…+1
[N+2]    502→40001   FIN-ACK  seq=…           ack=…+1
[N+3]    40001→502   ACK      seq=…+1         ack=…+1
```

握手在前、挥手在后，中间是全部请求/应答对（一次操作 = 一对）。**一条配置里的
所有操作共享同一条连接** —— 与真实扫描仪/HMI 的行为一致，也避免每个操作各起
一次连接把 pcap 撑爆。

## 4. 序列号模型

会话维护两个计数器：客户端下一个要发的序号 `client_seq`、服务端 `server_seq`。

| 事件 | seq | ack | 序号推进 |
|---|---|---|---|
| SYN | `client_seq` | 0（服务端还没发过东西） | `client_seq += 1` |
| SYN-ACK | `server_seq` | `client_seq`（已含 +1） | `server_seq += 1` |
| ACK | `client_seq` | `server_seq` | — |
| 数据（客户端→服务端） | `client_seq` | `server_seq` | `client_seq += len(载荷)` |
| 数据（服务端→客户端） | `server_seq` | `client_seq` | `server_seq += len(载荷)` |
| FIN | `client_seq` | `server_seq` | `client_seq += 1` |
| FIN | `server_seq` | `client_seq` | `server_seq += 1` |

**ack 的例外**：对端还没发过任何段时，本方向的 ack 为 0 —— TCP 规定未收到任何段
的确认号是 0。`full` 形态下握手在数据之前，服务端已发过 SYN-ACK，因此数据段的
ack 恒为对端当前序号；`data` 形态没有握手，客户端首个数据段的 ack 是 0。

初始序号 ISN 固定（客户端 `0x1000`、服务端 `0x2000`）：生成必须可复现，同一场景
必得同一份字节 —— 这是项目既有的不变式（"同一 seed 与同一输入必得同一输出"）。

**不变式**：任一方向相邻两包的 seq 差 == 前一包的载荷长度（数据段）或 1（SYN/FIN）；
每一包的 ack == 对端当前序号。测试直接断言这两条。

## 5. 声明式配置

会话形态是**传输配置的数据**，不是代码里的分支：

```yaml
transport:
  kind: tcp
  dport: 502
  session: full      # full = 握手+数据+挥手；data = 只发数据段
```

- 新增 `TransportSpec.session: str = "full"`，取值集合声明在传输层一处，非法值在
  构造时直接报错（`__post_init__` 校验），不散落到各调用点。
- 该字段随 `TransportSpec.to_dict()` 进 manifest 的 `transport` 块，因此
  **变异层能按源 manifest 重建同样的会话形态**，不需要猜。
- 旧 manifest 缺该字段时按默认 `full` 处理。
- Web 层无需改动：`ConfigPayload.transport` 是自由字典，服务层只校验「字段必须是
  `TransportSpec` 的已知字段」，新字段自动合法；页面不暴露该开关（默认即 `full`）。

## 6. 边界与不变式

- **串口 RTU**：没有 TCP，不建会话，pcap 仍走 Linux SLL，帧体是裸协议字节 ——
  行为完全不变。
- **UDP**：没有握手，数据段直接发，序号不变（UDP 无序号）。
- **变异层**：一次变异 = 一段会话的帧序列。`mutated` 层是独立的一份会话文件，
  同样带握手与挥手；重放类规则产生的追加帧也按同一套序号推进。
- **manifest**：`pcap_index` 指向请求包所在序号（因握手前导，偏移 3），
  `pcap_resp_index == pcap_index + 1` 不变；`pcap_frame_count` 仍只数产物自己的帧。
  另加 `sessions` 块（会话键 → 该会话 pcap 的真实包数，含握手与挥手）——
  「pcap 里有多少包」与「产物占了几帧」是两个口径，Web 层的「包数」用前者。
- **Web 预览**：只展示 manifest 里的 `pcap_index`，不按字节下标进 pcap，偏移无影响。

## 7. 验收指标（可自动判定）

| # | 指标 | 判定方式 |
|---|---|---|
| 1 | TCP 会话包数 == 3 + 数据帧数 + 4 | 测试按 manifest 统计操作数后断言包数 |
| 2 | flags 序列 == `[S, SA, A] + [PA, PA]×N + [FA, A, FA, A]` | 测试逐包断言 |
| 3 | 客户端 seq 严格递增，步长 == 前包载荷长度（或 1） | 测试逐包断言 |
| 4 | 每包 ack == 对端当前序号 | 测试逐包断言 |
| 5 | SYN 的 seq == 客户端 ISN；SYN-ACK 的 ack == ISN+1 | 测试断言 |
| 6 | 串口会话包数与内容不变（回归） | 既有测试保持通过 |
| 7 | `mutated` 层同样满足 1–5 | 变异测试断言 |
| 8 | `pcap_resp_index == pcap_index + 1` | 既有测试保持通过 |
| 9 | 全套测试通过 | `python3 -m pytest -q -W error` |

## 8. 文件改动

| 文件 | 改动 |
|---|---|
| `icsgen/transport/session.py` | **新增** —— TCP 会话序号状态机（握手 / 数据 / 挥手） |
| `icsgen/transport/spec.py` | 新增 `session` 字段与取值校验 |
| `icsgen/generator.py` | 按会话键维护 `TcpSession`，握手与挥手接入数据集组装 |
| `icsgen/emit/dataset.py` | `DatasetBuilder` 支持会话前导包与收尾包；导出会话键 |
| `icsgen/cli.py` | `mutate` 命令按 manifest 的会话形态重建 mutated 层 |
| `tests/test_transport_session.py` | **新增** —— 状态机单测 |
| `tests/test_generator.py` / `test_emit_dataset.py` / `test_mutate.py` | 补握手挥手断言、修正包序号期望值 |
| `README.md` | 产物布局与协议说明补 TCP 会话流程 |

## 9. 风险

| 风险 | 缓解 |
|---|---|
| 包序号偏移使既有断言失效 | 属预期变化；测试改为按「握手 3 包」偏移断言，并新增握手/挥手断言 |
| 变异层与源层会话形态不一致 | 会话形态随 manifest 传递，变异层按 manifest 重建 |
| 性能 | 每包仍是一次 Scapy 封装，多出 7 包/会话；相对 N 次交互可忽略 |
