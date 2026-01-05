# 让Wireshark变身智能助手：pcap-mcp如何重塑抓包分析工作流

## 引言：当抓包分析遇上智能体
在5G核心网/IMS/SBI联调中，工程师常陷入PCAP分析的"手工地狱"：  
- 动辄GB级的抓包文件  
- 跨协议（SIP/Diameter/HTTP2/NAS）的因果链追踪  
- 反复切换Wireshark过滤器和解码视图  

**pcap-mcp**做的事很直接：把 Wireshark/tshark 的“关键动作”拆成一组结构化 MCP Tools。你把 PCAP 交给智能体，它就能按固定流程做定位、下钻、串会话、对齐时间线——更像在跑一个可复现的排障脚本，而不是在 UI 里反复点来点去。

---

## MCP：智能体与工具的桥梁
MCP（Model Context Protocol）是连接AI系统与专业工具的协议：
- **即插即用**：将Wireshark等工具转化为AI可调用API
- **安全隔离**：严格限制文件访问范围，杜绝任意命令执行
- **跨平台**：无缝接入主流开发环境

### 🚀 极简部署
```bash
./scripts/install.sh  # 一键完成环境配置
```
> 自动处理：Python环境、tshark依赖、系统权限

---

## 三大核心价值
### 🔍 化手工为自动化
- `pcap_frames_by_filter`：用 Display Filter 快速定位关键帧（例如 SIP 580）
- `pcap_timeline`：把关键字段抽成时间线（支持分页），跨协议对齐因果链
- `pcap_follow`：从一帧提取 key 并生成会话跟踪条件（HTTP2 streamid / SIP Call-ID / Diameter Session-Id）

### 🛡️ 安全可控
- **白名单机制**：严格限制PCAP访问目录
- **输出熔断**：自动截断超长内容
- **落盘导表**：Packet List 导出为 TSV，避免一次性回传海量内容

### ⚡ 工程化落地
- **开箱即用**：一条命令完成环境配置与依赖检测
- **标准化输出**：所有工具返回结构化JSON，便于二次处理
- **可审计**：每次调用都有明确的输入参数与返回结果

---

## 实战案例：SIP 580根因分析

### 现象
iPhone IMS呼叫失败，SIP返回`580`（通常表示QoS资源未建立）

### 排障过程（按工具链走一遍）
1. **先把“关键帧号”找出来（可分页）**  
   用 `pcap_frames_by_filter` 输入 Wireshark Display Filter，拿到一批 `frame.number`：
   - 过滤示例：`sip && sip.Status-Code==580`

2. **对关键帧做“可控下钻”（替代手工点开协议树）**  
   对上一步返回的某个帧号调用 `pcap_frame_detail`：
   - 想看全量协议树：`restrict_layers=false`
   - 想聚焦：`restrict_layers=true` + `layers=["sip","diameter","http2","nas-5gs","ngap"]`（按你的抓包类型与关心层选择）
   - 为了避免输出爆炸：用 `max_bytes` 做截断保护

3. **把“会话链”串起来，而不是靠肉眼翻包**  
   从关键帧直接用 `pcap_follow` 生成 follow filter，并可返回匹配帧列表：
   - SIP：按 Call-ID 串起 INVITE/183/PRACK/UPDATE/最终响应
   - Diameter：按 Session-Id 串起 AAR/AAA（例如 `diameter && diameter.cmd.code==265`）
   - HTTP2：按 streamid 串起 `/npcf*` 请求与响应

4. **最后用时间线“对齐因果”**  
   用 `pcap_timeline` 在同一组过滤条件下抽字段（分页），把跨协议事件排成一行一行的证据：
   - 字段示例：`frame.time_relative`、`ip.src`、`ip.dst`、`sip.Call-ID`、`sip.Status-Code`、`diameter.Session-Id`、`diameter.cmd.code`、`http2.streamid`、`http2.headers.path`

   下面是“呈现效果”的示意（字段/时间戳以你的抓包为准）：

    | 时间戳     | 协议     | 关键字段/事件                           |
    |------------|----------|----------------------------------------|
    | 12:34:49   | Diameter | AAR/AAA (cmd.code=265), Session-Id    |
    | 12:34:51   | HTTP2    | :path=/npcf/sm-policies ... (streamid)|
    | 12:34:53   | NAS/NGAP | Reject cause（如存在）                 |
    | 12:34:56   | SIP      | Status-Code: 580                      |


### 根因分析
**问题链路**：  
SDP 配置错误 → Diameter 策略冲突 → UE 拒绝资源建立 → SIP 580  

**根本原因**：  
IPv4媒体流部署在IPv6 PDU会话导致规则冲突

---

## 即刻体验
```
[> 项目地址](https://github.com/LissajousX/mcp_for_pcap)
```

> 技术栈：Python 3.10+ / tshark / MCP协议  
> 适用场景：5GC/IMS联调、自动化测试、协议分析
