# 用 MCP 把 Wireshark 变成“可调用工具”：pcap-mcp 的设计与实战

在 5G 核心网、IMS、SBI（HTTP2）、Rx（Diameter）联调场景里，“抓包分析”几乎是日常必修课：  
Wireshark 很强，但它也很“手工”——过滤、对齐时序、翻字段、下钻、导出表格，往往要来回点很多次。

我最近做了一个 MCP Server：**pcap-mcp**，目标是把 Wireshark/tshark 的核心能力封装成一组结构化工具（tools），让智能体/脚本可以像人一样按流程排障，但同时保留可审计、可复现和安全边界。

本文会先介绍 MCP 的技术背景，再介绍 pcap-mcp 的设计、功能与一个真实排障案例（SIP 580 / QoS / packet filter 问题链路）。

## 0. 开箱即用（当前版本）

1) 一条命令准备环境（尽量自动安装系统依赖 + 创建 `.venv` + 安装 Python 依赖）：

```bash
./scripts/bootstrap.sh
```

2) 自检（推荐遇到问题先跑这个）：

```bash
./.venv/bin/python -m pcap_mcp doctor
```

3) 接入 Windsurf（stdio）：用 `./scripts/run_mcp.sh` 启动。

> 注意：stdio 模式下 stdout 必须只输出 JSON-RPC。不要在启动命令里加任何会向 stdout 打印的内容。

---

## 1. MCP 技术背景：为什么需要 Model Context Protocol？

### 1.1 从“会聊天”到“会干活”
大模型擅长理解、总结和推理，但它本身 **无法直接读取你的本地文件、跑 tshark、查系统状态**。  
要让模型“干活”，就需要给它一套可调用的能力接口（Tools / Functions）。

过去大家常见的做法是“为某个应用写插件”，但问题是：
- 每个平台一套插件规范，迁移成本高
- 调用参数与输出格式不统一
- 难以沉淀一套可复用的工具生态

### 1.2 MCP 的核心：标准化的 Tool 协议
**MCP（Model Context Protocol）** 提供了一个标准，让“客户端（例如 IDE 里的智能体）”与“工具服务端（你自己写的能力）”通过统一协议对接。

它的好处是：
- **通用**：不同客户端只要支持 MCP，就能复用同一批工具
- **结构化**：工具输入输出是 JSON schema 友好的结构化数据
- **可审计**：每次调用都有明确参数、明确返回
- **可控**：服务端可以严格限制文件访问、输出大小、超时等

### 1.3 传输方式（Transport）
MCP 常见支持两类 transport：
- `stdio`：客户端启动一个子进程，通过标准输入输出通信（本地工具很适合）
- `http`：服务端常驻，通过 HTTP 暴露 `/mcp` 端点（适合团队共享/远程）

pcap-mcp 目前使用 `stdio` 启动方式最简单稳定。

---

## 2. 痛点：抓包分析为什么难自动化？

抓包分析的典型痛点：
- **文件大**：pcap 几百 MB 到几 GB 很常见，模型无法直接“读文件内容”
- **跨协议**：一个问题可能横跨 SIP / Diameter / HTTP2 / NAS / NGAP / PFCP
- **强依赖工具**：最终要靠 Wireshark/tshark dissector 才能可靠解码
- **输出不可控**：直接 `tshark -V` 输出很容易爆炸，需要裁剪/分页/截断保护
- **安全风险**：让一个工具随意读取任意路径/执行任意 shell 命令是不可接受的

因此正确做法是：让 MCP Server 只暴露“封装好的能力”，并且每个能力都要可控、可限制、可审计。

---

## 3. pcap-mcp：设计目标与关键原则

### 3.1 设计目标
- **像 Wireshark 一样**：Display Filter、字段抽取、按帧下钻、会话跟踪、导出 Packet List
- **结构化**：输入输出尽量 JSON 化，便于智能体二次处理
- **可控**：超时、分页、最大输出字节数、输出文件落盘等
- **安全**：只允许访问白名单目录下的 pcap；不提供任意 shell 执行

### 3.2 依赖与实现策略
- 依赖 `tshark` + Wireshark dissector 生态（不自研协议解码）
- 用 MCP server 封装常用操作，并对输出做裁剪/截断保护
- 对导出类结果（Packet List）落盘为 TSV，避免一次性返回几万行

---

## 4. 工具能力一览（核心 Tools）

下面列的是目前已经实现且常用的工具（tool 名称即调用入口）：

### 4.1 抓包概览
- `pcap_info`  
  返回抓包包数、起止时间、持续时间、tshark 版本，以及常见协议是否出现（ngap/nas/pfcp/gtpv2/...）。

### 4.2 字段发现（不知道字段名时救命）
- `pcap_list_fields`  
  用来搜索 `tshark -G fields` 的字段名，例如查 `diameter.Session-Id`、`http2.headers.path` 等。

### 4.3 精准定位帧号（分页）
- `pcap_frames_by_filter`  
  输入 Wireshark Display Filter，返回匹配的 `frame.number` 列表。

### 4.4 字段抽取时间线（分页）
- `pcap_timeline`  
  输入 filter + fields，把关键字段抽成“表格时间线”，用于跨协议对齐时序。

### 4.5 指定帧下钻（可控的 tshark -V）
- `pcap_frame_detail`  
  支持两种模式：
  - `restrict_layers=true` + `layers=[...]`：只输出指定协议层（更聚焦）
  - `restrict_layers=false`：输出完整协议树（更接近 Wireshark 全量下钻）
  - `verbosity=full`：额外输出十六进制（`tshark -x`）方便深挖
  - `max_bytes`：输出截断保护

### 4.6 Packet List 导出（写文件）
- `pcap_packet_list`  
  导出 Wireshark 风格 Packet List 为 TSV 文件，并返回少量 preview 行。适合先“扫一遍全局”。

### 4.7 会话跟踪（Follow filter）
- `pcap_follow`  
  从指定帧提取跟踪 key，并生成 follow filter：
  - HTTP2：streamid
  - Diameter：Session-Id
  - SIP：Call-ID

### 4.8 文本搜索（在过滤集合中搜关键字）
- `pcap_text_search`  
  在过滤后的帧集合里搜关键字（例如 `/npcf`、`sm-policies`、`Semantic errors in packet filter`），返回命中帧号与片段。

---

## 5. 配置与安全边界

pcap-mcp 使用 JSON 配置（默认 `pcap_mcp_config.json`），重点关注：

- `allowed_pcap_dirs`：允许分析的抓包目录白名单  
- `allow_any_pcap_path`：是否允许分析任意绝对路径（默认 false，建议保持关闭）
- `output_dir`：导出 TSV 的落盘目录
- `PCAP_MCP_OUTPUT_DIR`：可用环境变量强制覆盖 output_dir（推荐在只读/权限受限环境里使用）
- `global_decode_as`：全局 decode-as（例如某端口强制按 http2 解码）
- `profiles`：常用 display filter / decode_as 组合
- `packet_list_columns`：自定义 Packet List 列模板（用于 Diameter/HTTP2/SIP 跟踪字段）

补充：`./scripts/run_mcp.sh` 会在未指定 `PCAP_MCP_OUTPUT_DIR` 时默认使用可写目录（优先 `XDG_CACHE_HOME`，否则 `/tmp/pcap_mcp_outputs`）。

---

## 6. 推荐排障工作流（Wireshark-like）

一个高效且可复现的排障流程通常是：

1. `pcap_info`：确认抓包时间范围、是否包含关键协议
2. `pcap_packet_list`：导出全局列表，快速锁定问题时间窗/协议栈
3. `pcap_frames_by_filter`：用错误码/路径/命令码定位关键帧号
4. `pcap_frame_detail`：对关键帧做下钻（必要时全量下钻 + hex）
5. `pcap_follow`：把 SIP Call-ID / Diameter Session-Id / HTTP2 streamid 串起完整会话
6. `pcap_timeline`：抽关键字段形成时间线，对齐多协议因果关系

---

## 7. 实战案例：SIP 580 / QoS / packet filter 的因果链

### 7.1 现象
某次 iPhone IMS 呼叫失败，SIP 返回 `580`。从经验看，580 往往不是“IMS 本身坏了”，而是**前置条件（precondition）不满足**，例如 QoS 资源未建立。

### 7.2 用工具快速定位 SIP 580
先用 Display Filter 找到 580 对应帧号：
- `sip && sip.Status-Code==580`

拿到帧号后：
- 对 580 帧 `pcap_frame_detail` 全量下钻（`restrict_layers=false`，必要时 `verbosity=full`）

### 7.3 继续追踪：QoS 为什么没建立？
典型链路会涉及：
- IMS 信令（SIP）
- Rx 策略（Diameter AAR/AAA，cmd.code==265）
- PCF 策略（SBI HTTP2 `/npcf*`）
- 核心网侧下发（SMF/NAS QoS rule / packet filter）
- UE 侧是否接受（NAS reject cause）

#### (1) Rx AAR/AAA（cmd.code==265）
过滤：
- `diameter && diameter.cmd.code==265`

重点看 AAR 里的 `Flow-Description` 是否与 PDU session type/UE 能力匹配。  
在该案例里，AAR 的 Flow-Description 中出现了 IPv4 媒体地址（来自 SDP），但 IMS PDU session 的类型却是 IPV6，导致后续 packet filter/QoS rule 组合出现语义问题，最终 UE 侧以 cause 拒绝，造成资源无法建立。

#### (2) PCF Npcf（HTTP2）
过滤：
- `http2 && http2.headers.path contains "npcf"`

重点看：
- `sm-policies` 创建/更新
- PDU session type、DNN、地址前缀等字段

#### (3) 关键结论链（示意）
- SDP 提供 IPv4 媒体地址  
- Rx AAR 产生包含 IPv4 的 Flow-Description  
- PCF/SMF 下发的 packet filter/QoS rule 在 UE 侧语义不成立  
- UE NAS reject（例如 cause=44）  
- IMS precondition 不满足  
- SIP 最终返回 580

这个案例的价值在于：**它横跨 SIP / Diameter / HTTP2 / NAS 的因果链**。  
而 MCP 工具的意义，就是把这些“跨协议、跨层次”的验证步骤结构化下来，让排障过程更快、更稳定、也更可复现。

---

## 8. 总结：MCP + tshark 是抓包分析自动化的正确打开方式

pcap-mcp 的核心价值不是“自动给结论”，而是：
- 把 Wireshark 的关键能力变成可调用工具
- 让智能体能按工程化流程排障
- 输出受控、可审计、可复现
- 有安全边界（白名单路径、无任意 shell）

下一步还可以扩展：
- 自动聚合 UE 会话（ngap_ue_sessions）
- 按 PDU session 聚合关键信令（ngap_pdu_session_summary）
- 导出子抓包（extract_subcapture）便于分享复现

如果你也在做 5GC/IMS 联调，这类工具会非常“省命”。
