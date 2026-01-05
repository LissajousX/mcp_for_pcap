# 抓包分析太“手工”？用 MCP 让 Wireshark 变成可调用工具（pcap-mcp）

抓包分析是 5G/IMS/SBI 联调里最常见、也最消耗精力的一件事：

- PCAP 很大，模型/脚本无法直接“读文件”
- 问题跨协议（SIP / Diameter / HTTP2 / NAS / NGAP / PFCP / S1AP），人要不停切换上下文
- 最强的解码来自 Wireshark dissector，但 Wireshark 的工作流很“手工”
- `tshark -V` 一下子输出成千上万行，既不可控也不利于自动化
- 让工具随意读任意路径、执行任意 shell 又不安全

**pcap-mcp** 的目标很简单：
把 Wireshark/tshark 的核心能力封装成一组结构化 MCP Tools，让智能体/脚本也能“像人一样用 Wireshark 排障”，并且输出可控、可审计、可复现、可安全落地。

---

## 1. 痛点拆解：为什么抓包难自动化

### 1.1 大文件 + 强工具依赖
抓包往往是几百 MB 到几 GB。模型无法直接读取这些文件内容。
真正可靠的协议解码又必须依赖 Wireshark dissector 生态。

### 1.2 跨协议因果链
一次问题可能横跨：

- IMS 呼叫：SIP
- 策略：Rx（Diameter AAR/AAA）
- SBI：HTTP2 /npcf*
- 核心网控制面：NAS / NGAP（5G）或 NAS-EPS / S1AP（4G）

你要把它们对齐成一个“可解释的时间线”，才能看清根因。

### 1.3 输出不可控
自动化最怕“输出爆炸”。

- 直接 `tshark -V`：不可控、难截断、难给模型消费
- 直接把全量 Packet List 回传：几万行 JSON 会让工具链崩溃

---

## 2. 解决方式：把 Wireshark 工作流结构化成 MCP Tools

pcap-mcp 暴露的能力遵循一个原则：

- **每个工具只做一件事**
- **输入输出结构化**（JSON）
- **输出受控**（分页 / 最大字节数 / 落盘导出）
- **安全边界明确**（PCAP 路径白名单，无任意 shell）

工具概览：

- 定位：`pcap_frames_by_filter`
- 时间线：`pcap_timeline`
- 下钻：`pcap_frame_detail`
- 会话跟踪：`pcap_follow`
- 文本检索：`pcap_text_search`
- 导表：`pcap_packet_list`
- 字段发现：`pcap_list_fields`

---

## 3. 开箱即用（当前版本）

1) 一条命令准备环境（尽量自动安装系统依赖 + 创建 `.venv` + 安装 Python 依赖）：

```bash
./scripts/bootstrap.sh
```

2) 自检（建议遇到问题先跑这个）：

```bash
./.venv/bin/python -m pcap_mcp doctor
```

3) 接入 Windsurf（stdio）：

```bash
./scripts/run_mcp.sh
```

> 注意：stdio 模式下 stdout 必须只输出 JSON-RPC。不要在启动命令里加任何会向 stdout 打印的内容。

---

## 4. 你会怎么用它（3 个高收益套路）

### 4.1 先全局扫一遍：导出 Packet List
用 `pcap_packet_list` 导出 TSV（落盘），回传少量 preview。

价值：
- 快速锁定问题时间窗
- 观察协议栈是否齐全（SIP/Diameter/HTTP2/NGAP/S1AP/NAS…）

### 4.2 精准定位关键帧：frames_by_filter
用 Display Filter 找关键帧号：

- SIP 失败：`sip && sip.Status-Code==580`
- Rx：`diameter && diameter.cmd.code==265`
- PCF：`http2 && http2.headers.path contains "npcf"`

### 4.3 对关键帧做“可控下钻”：frame_detail
对关键帧做 `tshark -V` 级别下钻：

- 只看关心层：`restrict_layers=true` + `layers=[...]`
- 全量下钻：`restrict_layers=false`
- 避免输出爆炸：`max_bytes`

---

## 5. 4G / 5G 一套配置打通

默认配置里提供了两个常用 profile：

- `core_5g`: `(ngap || http2 || diameter || sip)` + NAS-5GS 相关偏好
- `core_4g`: `(s1ap || http2 || diameter || sip)` + NAS-EPS 相关偏好

在同一套工具链里，你可以把 4G/5G 的抓包排障方式统一起来。

---

## 6. 总结：它解决的不是“会不会 Wireshark”，而是“可复现的工程化排障”

Wireshark 很强，但它更像一个“手工 IDE”。
pcap-mcp 做的事情是把最常用的抓包排障动作变成可调用工具，让你：

- 更快：少点 UI、多跑流程
- 更稳：输出可控，不因一条命令把工具链打爆
- 更可复现：每一步都有明确参数、明确返回
- 更安全：白名单目录 + 无任意 shell

如果你经常做 5GC/IMS/HTTP2/Diameter 联调，这类工具会非常省命。
