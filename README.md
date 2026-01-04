# pcap-mcp

基于 **tshark/Wireshark dissector** 的 PCAP 分析 MCP Server。

它把 Wireshark 常用的工作流（Display Filter 检索、字段抽取/时间线、按帧下钻、会话跟踪、导出 Packet List）封装为一组结构化 MCP tools，方便智能体/脚本按“像 Wireshark 一样”的方式自动化排障。

## 适用场景

- 5G 核心网/无线侧信令排障：NGAP/NAS-5GS/PFCP/GTPv2/GTP
- IMS/SIP 呼叫问题排查：SIP + Rx(Diameter) + SBI(HTTP2)
- QoS/策略问题：Rx AAR/AAA、PCF /npcf*、SMF 下发 packet filter 与 UE reject 的因果链

## 依赖

- Python: `>=3.10`
- 系统工具：`tshark`（必须）、`capinfos`（建议，通常随 wireshark 安装）

## 安装

```bash
pip install -r requirements.txt
```

如需以本地源码方式使用：

```bash
pip install -e .
```

## 启动

```bash
python3 -m pcap_mcp
```

或使用脚本入口：

```bash
pcap-mcp
```

## 配置

默认会尝试读取仓库根目录的 `pcap_mcp_config.json`。也可以通过环境变量指定：

- `PCAP_MCP_CONFIG_JSON=/abs/path/to/pcap_mcp_config.json`

常用配置项（见 `pcap_mcp_config.json`）：

- `allowed_pcap_dirs`: 允许分析的 PCAP 目录白名单
- `allow_any_pcap_path`: 是否允许任意绝对路径 PCAP（默认 false，建议保持关闭）
- `global_decode_as`: 全局 `tshark -d` 规则（例如把某端口按 http2 解码）
- `profiles`: 常用 display filter / decode-as 组合
- `packet_list_columns`: Packet List 导出列模板（用于 Diameter/HTTP2/SIP 跟踪字段）

## MCP Tools（已实现）

- `pcap_config_get`
  - 获取当前加载的配置快照（profiles、packet_list_columns 等）
- `pcap_config_reload`
  - 重新加载配置文件（无需重启 server）
- `pcap_list_fields`
  - 字段发现：等价 `tshark -G fields` 的可搜索封装
- `pcap_info`
  - 抓包摘要：包数/时间范围/sha256/tshark 版本/是否包含常见协议等
- `pcap_frames_by_filter`
  - 输入 display filter，返回匹配的 frame.number 列表（分页）
- `pcap_timeline`
  - 输入 display filter + fields，返回“时间线表格”（分页）
- `pcap_frame_detail`
  - 指定帧下钻：
    - `restrict_layers=true` + `layers=[...]`：只输出指定协议树（更像“只看关心层”）
    - `restrict_layers=false`：输出完整协议树（等价 Wireshark 全量下钻）
    - `verbosity=full`：额外输出十六进制（`tshark -x`）
    - `max_bytes`：截断保护
- `pcap_text_search`
  - 在过滤后的帧集合里做文本搜索（内部会抓 detail 形成 snippet）
- `pcap_follow`
  - 会话跟踪：从指定帧提取并生成 follow filter（例如 HTTP2 streamid / Diameter Session-Id / SIP Call-ID）
- `pcap_packet_list`
  - 导出类似 Wireshark Packet List 的 TSV 文件，并返回预览行

## 推荐工作流（Wireshark-like）

1. `pcap_info`：确认抓包概况、协议是否齐全
2. `pcap_packet_list`：先导出一个“全局 Packet List”，观察主要协议与时间窗
3. `pcap_frames_by_filter`：对关键协议/错误码做一次定位（例如 `sip.Status-Code==580`、`diameter.cmd.code==265`、`http2.headers.path contains "npcf"`）
4. `pcap_frame_detail`：对关键帧下钻（必要时 `restrict_layers=false` + `verbosity=full`）
5. `pcap_follow`：用 SIP Call-ID / Diameter Session-Id / HTTP2 streamid 串起完整会话
6. `pcap_timeline`：抽关键字段形成“可读的时间线”并对齐多协议因果关系

## 示例（以工具调用参数为主）

### 1）按 SIP 580 定位并下钻

- `pcap_frames_by_filter`

```json
{
  "pcap_path": "/path/to/test_iphone_call_jx-1230.pcap",
  "display_filter": "sip && sip.Status-Code==580",
  "limit": 50,
  "offset": 0
}
```

- `pcap_frame_detail`（全量下钻）

```json
{
  "pcap_path": "/path/to/test_iphone_call_jx-1230.pcap",
  "frame_numbers": [3470],
  "restrict_layers": false,
  "verbosity": "full",
  "max_bytes": 400000
}
```

### 2）查看 Rx AAR（cmd.code==265）里下发的 Flow-Description

```json
{
  "pcap_path": "/path/to/test_iphone_call_jx-1230.pcap",
  "display_filter": "diameter && diameter.cmd.code==265",
  "columns_profile": "rx_compact",
  "preview_rows": 50
}
```

### 3）查询 PCF Npcf 信令

```json
{
  "pcap_path": "/path/to/test_iphone_call_jx-1230.pcap",
  "display_filter": "http2 && http2.headers.path contains \"npcf\"",
  "limit": 200,
  "offset": 0
}
```

## 输出文件

- Packet List 导出默认写到：`pcap_mcp_config.json` 的 `output_dir`
- 文件名形如：`<pcap_stem>.packet_list.<UTC_TIMESTAMP>.tsv`
