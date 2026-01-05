# pcap-mcp —— 需求文档（含用法）

## 1. 背景

在日常 5G 核心网/无线侧联调中，定位问题通常需要对抓包（pcap）进行快速检索、按流程梳理、抽取关键字段（NGAP/NAS/GTP/PFCP 等）并对异常点进行精确下钻（frame 级细节）。

目标是开发一个 **MCP Server**，向上提供一组结构化工具（tools），使上层智能体能够：

- 接收“原始抓包 + 你要定位的问题描述”。
- 通过调用 MCP tools 自动完成筛选、时间线整理、字段提取与关键帧展开。

本需求文档先定义：范围、工具接口、非功能需求、安全边界、验收标准。

## 1.1 当前实现说明（v0.1.0）

- tool 名称采用下划线风格（例如 `pcap_info`），以适配 MCP/运行环境的工具命名约束。
- 目前已实现：
  - 抓包摘要：`pcap_info`
  - 字段发现：`pcap_list_fields`
  - 过滤取帧：`pcap_frames_by_filter`
  - 时间线字段抽取：`pcap_timeline`
  - 指定帧下钻：`pcap_frame_detail`
  - 文本搜索：`pcap_text_search`
  - 会话跟踪（follow filter）：`pcap_follow`
  - Wireshark 风格 Packet List 导出：`pcap_packet_list`
  - 配置查看/热加载：`pcap_config_get` / `pcap_config_reload`

## 1.2 快速上手（用法）

- 推荐（新手无脑版）：`./scripts/install.sh`
- 自检（强烈建议）：`./.venv/bin/python -m pcap_mcp doctor`
- 启动服务（推荐用于 Windsurf/stdio）：`./scripts/run_mcp.sh`
- 更新：
  - 配置变更：调用 `pcap_config_reload`
  - 代码/依赖更新：`git pull && ./scripts/install.sh`
  - 在 Windsurf MCP 面板里 Disable 再 Enable，以重新执行 `bash -lc "cd /home/lisa/mcp_for_pcap && ./scripts/run_mcp.sh"`
  - 若仍未连上，可删除后重新添加该 MCP 配置或重启 Windsurf
- 卸载/清理：`./scripts/uninstall.sh`（全清理：`./scripts/uninstall.sh --all`）
- 手动安装（可选）：`pip install -r requirements.txt`
  - 说明：当前版本的 `requirements.txt` 通过 `-e .` 安装本项目，依赖来自 `pyproject.toml`
- 配置文件：默认读取仓库根目录 `pcap_mcp_config.json`，也可通过 `PCAP_MCP_CONFIG_JSON` 指定
  - 建议同时设置：`PCAP_MCP_OUTPUT_DIR=/tmp/pcap_mcp_outputs`（避免目录不可写导致导出失败）

> 注意：stdio 模式下，MCP Server 的 stdout 必须只输出 JSON-RPC。请使用 `run_mcp.sh` 启动，不要在启动命令里加入会向 stdout 打印的内容。
- 推荐工作流（Wireshark-like）：
  - 先 `pcap_info`
  - 再 `pcap_packet_list` 快速扫一遍“全局列表”
  - 用 `pcap_frames_by_filter` / `pcap_timeline` 定位关键帧
  - 用 `pcap_frame_detail`（必要时 `restrict_layers=false` + `verbosity=full`）下钻
  - 用 `pcap_follow` 以 SIP Call-ID / Diameter Session-Id / HTTP2 streamid 串起完整会话

## 2. 目标（Goals）

- **G1：结构化检索能力**
  - 支持按 Wireshark Display Filter（例如 `ngap`、`ngap && nas_5gs`、`sctp.port==38412` 等）检索。
  - 支持抽取字段（`-T fields`）形成“时间线表格”。

- **G2：流程定位能力**
  - 能快速产出 NGAP/NAS 关键流程轮廓（例如 Registration、Authentication、InitialContextSetup、PDU Session Setup）。

- **G3：可控的深挖能力**
  - 支持针对指定帧（或小范围帧集合）输出详细解码（等价 `tshark -V`），并提供 **输出裁剪** 以避免内容爆炸。

- **G4：可复现与可审计**
  - 每个 tool 输出中包含其过滤条件、字段列表、分页参数、以及（可选）底层命令/版本信息，便于复查。

- **G5：安全可控**
  - 仅允许分析白名单目录下的 pcap 或 MCP 缓存目录内文件。
  - 禁止任意 shell 执行；MCP 只暴露封装好的功能。

## 3. 非目标（Non-Goals）

- **N1：不在 MCP 内实现“自动判案/根因结论”**
  - MCP 负责提供“可查询、可下钻”的结构化数据；推理与结论由上层智能体完成。

- **N2：不自研 ASN.1 / SCTP / NGAP 解码器**
  - 首期依赖 `tshark`/Wireshark dissector 生态。

- **N3：不负责抓包（capture）**
  - 首期仅分析既有 pcap 文件。

## 4. 运行环境与依赖

- **OS**：Linux
- **核心依赖**：`tshark`（Wireshark CLI）
- **可选依赖**：`capinfos`（通常随 wireshark 安装）
- **约束**：
  - `tshark` 必须可执行（PATH 可找到或可配置绝对路径）。
  - 需要支持 Wireshark Display Filter。

## 5. 用户故事（User Stories）

- **US1：给我 pcap，快速看 NGAP 流程轮廓**
  - 作为用户，我希望输入一个 pcap 文件路径，得到 NGAP 报文的时间线（含 procedureCode、UE NGAP ID、Info 等）。

- **US2：给我 pcap + 目标问题，快速定位关键帧**
  - 作为用户，我描述“注册失败/鉴权失败/重复 PDU session”等，智能体能通过 MCP 工具定位到失败点附近的帧并展开细节。

- **US3：输出要可控**
  - 作为用户，我不希望一次输出几万行；我希望支持分页、限制条数、限制最大输出体积。

## 6. 数据输入模型

### 6.1 pcap 标识

首期（MVP）支持：

- **Path 模式**：直接传入 `pcap_path`（必须位于白名单目录）

后续可选增强：

- **pcap_id 模式**：上传后生成 `pcap_id`，由 MCP 进行缓存管理

### 6.2 时间与帧范围

- 允许按 `frame.number` 列表定位。
- 允许 `limit/offset` 分页。

## 7. 输出模型（统一约定）

- 默认输出为 **JSON**（便于智能体二次处理）。
- 对表格输出，返回 `columns` + `rows` 或直接返回对象数组（需统一）。
- 对 detail 输出，必须支持：
  - `verbosity`：`summary | full`
  - `max_bytes`：最大输出字节数（超过则截断并提示）。
- 对 Packet List 导出：
  - 返回 `output_path`（TSV 文件路径）以及 `rows_written`、`preview_rows` 等摘要信息。

## 8. 工具清单与接口定义

> 说明：以下接口以“当前实现的 tool 名称/参数”为准；如需扩展，建议保持向后兼容（新增参数尽量提供默认值）。

### 8.1 `pcap_info`

- **目的**：获取抓包总体摘要，帮助判断抓包点与协议覆盖。
- **输入**：
  - `pcap_path`: string
- **输出（JSON）**：
  - `pcap_path`
  - `sha256`（可选）
  - `packet_count`
  - `time_start` / `time_end` / `duration`
  - `has_protocols`: { `ngap`: bool, `nas_5gs`: bool, `sctp`: bool, `gtpv2`: bool, `pfcp`: bool, ... }
  - `top_conversations`（可选，N2 重点：SCTP 端口/对端）
  - `tshark_version`
- **错误**：
  - `FILE_NOT_FOUND`
  - `PERMISSION_DENIED`
  - `TSHARK_NOT_FOUND`

### 8.2 `pcap_timeline`

- **目的**：按过滤条件输出“时间线表格”。
- **输入**：
  - `pcap_path`: string
  - `display_filter`: string
  - `fields`: string[]（例如 `frame.number`, `frame.time_relative`, `ip.src`, `ip.dst`, `ngap.procedureCode`, `_ws.col.Info`）
  - `limit`: int（默认 200）
  - `offset`: int（默认 0）
  - `sort_by`: string（可选，默认 `frame.number`）
  - `decode_as`: string[]（可选，等价 `tshark -d`，并会与 global/profile decode_as 合并去重）
  - `profile`: string（可选，从配置文件 profiles 引用）
- **输出（JSON）**：
  - `pcap_path`
  - `display_filter`
  - `fields`
  - `limit`/`offset`
  - `rows`: object[]（每行一个对象：key 为字段名，value 为字符串/数组字符串）
- **要求**：
  - 当字段不存在时，返回 `fields_resolved`（可选）并在 `warnings` 标注。
  - 必须支持分页。
- **错误**：
  - `INVALID_FILTER`
  - `INVALID_FIELDS`
  - `OUTPUT_TOO_LARGE`

### 8.3 `pcap_frames_by_filter`

- **目的**：只返回匹配过滤条件的 frame 列表（便于后续 detail 精准下钻）。
- **输入**：
  - `pcap_path`: string
  - `display_filter`: string
  - `limit`: int（默认 500）
  - `offset`: int（默认 0）
  - `decode_as`: string[]（可选）
  - `profile`: string（可选）
- **输出（JSON）**：
  - `frames`: int[]
  - `total_estimate`（可选）

### 8.4 `pcap_frame_detail`

- **目的**：输出指定帧的详细解码（等价 `tshark -V` 的可控子集）。
- **输入**：
  - `pcap_path`: string
  - `frame_numbers`: int[]
  - `layers`: string[]（可选，如 `["ngap","nas_5gs"]`；为空则输出完整但需更严格裁剪）
  - `restrict_layers`: bool（默认 true；为 true 且 layers 非空时仅输出指定协议树；为 false 时输出完整协议树）
  - `verbosity`: `summary | full`（默认 summary）
  - `max_bytes`: int（默认 200000）
  - `decode_as`: string[]（可选）
  - `profile`: string（可选）
- **输出（JSON）**：
  - `frames`: [{
    - `frame_number`
    - `text`（或 `structured`，首期建议 text）
    - `truncated`: bool
  }]
- **要求**：
  - 必须限制输出体积。
  - 支持对输出做“按 layer 裁剪”（例如只保留 `NGAP` subtree + `NAS-5GS` subtree）。
  - `verbosity=full` 时建议输出更完整信息（当前实现为 `tshark -x`，便于查看十六进制数据）。

### 8.5 `pcap_text_search`

- **目的**：在过滤后的帧集合中进行文本搜索，返回命中的帧号与 snippet 片段。
- **输入**：
  - `pcap_path`: string
  - `display_filter`: string
  - `query`: string
  - `layers`: string[]（可选）
  - `restrict_layers`: bool（默认 true）
  - `limit`/`offset`
  - `max_matches`: int（默认 50）
  - `snippet_context_chars`: int（默认 240）
  - `max_bytes`: int（用于限制抓取 detail 的字节数）
  - `decode_as`: string[]（可选）
  - `profile`: string（可选）
- **输出（JSON）**（精简示意，实际会包含分页与扫描统计信息）：
  - `frames_scanned`: int
  - `matches`: [{ `frame_number`, `truncated`, `snippet` }]

### 8.6 `pcap_follow`

- **目的**：从指定帧中提取可用于“跟踪会话”的 key，并生成对应的 display filter（便于一键串起全会话）。
- **支持**：
  - HTTP2：`http2.streamid`
  - Diameter：`diameter.Session-Id`
  - SIP：`sip.Call-ID`
- **输入**：
  - `pcap_path`: string
  - `frame_number`: int
  - `display_filter`: string（可选，会与 follow filter 合并）
  - `profile`: string（可选）
  - `decode_as`: string[]（可选）
  - `limit`/`offset`: int（可选，返回 follow 会话的帧列表时分页）
- **输出（JSON）**：
  - `follow_type`: string（`http2.streamid` / `diameter.Session-Id` / `sip.Call-ID`）
  - `follow_key`: string
  - `follow_display_filter`: string（只包含 follow 条件）
  - `display_filter`: string（follow + base filter 合并后的最终 filter）
  - `frames`: int[]（分页）

### 8.7 `pcap_packet_list`

- **目的**：导出 Wireshark 风格 Packet List（TSV），用于快速浏览/二次筛选。
- **输入**：
  - `pcap_path`: string
  - `display_filter`: string（可选）
  - `columns_profile`: string（可选，从配置 `packet_list_columns` 引用）
  - `include_default_columns`: bool（默认 true）
  - `extra_columns`: [{ `name`, `field` }]（可选）
  - `preview_rows`: int（默认 50，仅返回文件头部预览；完整结果写入文件）
  - `decode_as`: string[]（可选）
  - `profile`: string（可选）
- **输出（JSON）**：
  - `output_path`: string
  - `rows_written`: int
  - `file_size_bytes`: int（可选）
  - `preview_rows`: object[]
  - `warnings`: string[]（可选）

### 8.8 `pcap_list_fields`

- **目的**：字段发现与校验（封装 `tshark -G fields`），用于快速找到可用字段名。
- **输入**：
  - `query`: string（默认空）
  - `is_regex`: bool
  - `case_sensitive`: bool
  - `limit`: int
  - `include_protocols`: bool
- **输出（JSON）**：
  - `count`: int
  - `items`: object[]

### 8.9 `pcap_config_get` / `pcap_config_reload`

- **目的**：查看/热加载配置（profiles、packet_list_columns、路径白名单等）。
- **输入**：无
- **输出**：配置快照 / reload 标志

## 9. 可选增强工具（Phase 2）

### 9.1 `pcap_fields_search`（可选）
- 说明：当前已提供 `pcap_list_fields`；若需要更强的“按协议/别名/说明”检索，可新增该工具。
- 输入：`prefix`（例如 `ngap.`/`nas_5gs.`）+ `keyword`（可选）
- 输出：字段名列表与说明（来自 `tshark -G fields`）

### 9.2 `ngap.ue_sessions`
- 目的：按 UE 维度聚合 NGAP 会话（RAN/AMF UE NGAP ID、起止时间、出现过的 procedure）。

### 9.3 `ngap.pdu_session_summary`
- 目的：按 `pDUSessionID` 聚合 Setup Request/Response，提取 N3 IP、TEID、失败原因等。

### 9.4 `pcap.extract_subcapture`
- 目的：根据过滤条件或 frame 列表导出子 pcap，便于复现与分享。

## 10. 字段兼容与健壮性要求
- 不同 Wireshark 版本字段名可能存在大小写/命名差异（例如：`ngap.AMF_UE_NGAP_ID` vs `ngap.aMF_UE_NGAP_ID`）。
- 需求：
  - 提供字段别名/回退机制（实现层可维护一份 alias map；或通过 `fields_search` 动态探测）。
  - 当字段无效时要返回清晰错误/警告，不得静默失败。

## 11. 性能与资源限制（Non-Functional Requirements）
- **超时**：单次 tool 调用默认超时（例如 30s），可配置。
- **输出限制**：
  - timeline 行数限制（例如默认 200，最大 5000）
  - detail 最大字节数限制（默认 200KB，最大 2MB）
- **缓存（可选）**：
  - 允许基于 `pcap sha256 + filter + fields` 做结果缓存，提升反复查询效率。

## 12. 安全边界
- **目录白名单**：仅允许访问配置的 `allowed_pcap_dirs`。
- **禁止任意命令执行**：MCP 不提供通用 shell 执行接口。
- **敏感信息处理（可选）**：对 IMSI/SUPI 等字段可提供脱敏选项。

## 13. 错误码与错误信息规范
建议统一返回：
- `code`: string（如 `FILE_NOT_FOUND`）
- `message`: string（人类可读）
- `details`: object（可选）

常见错误码：
- `FILE_NOT_FOUND`
- `PERMISSION_DENIED`
- `TSHARK_NOT_FOUND`
- `INVALID_ARGUMENT`
- `INVALID_FILTER`
- `INVALID_FIELDS`
- `TIMEOUT`
- `OUTPUT_TOO_LARGE`
- `INTERNAL_ERROR`

## 14. 验收标准（Acceptance Criteria）

- **AC1**：对任意给定 pcap，`pcap_info` 能返回 packet_count、时间范围、tshark_version。
- **AC2**：`pcap_timeline` 对 `display_filter=ngap` 能稳定输出时间线，并支持 `limit/offset`。
- **AC3**：`pcap_frames_by_filter` 能返回匹配帧列表，可用于后续下钻。
- **AC4**：`pcap_frame_detail` 对指定 1~10 帧能输出 detail，支持 `restrict_layers=false` 全量下钻、并可控截断不崩溃。
- **AC5**：`pcap_packet_list` 能把全量 Packet List 写入 TSV，并返回可读的 `preview_rows`。
- **AC6**：`pcap_follow` 能从含 key 的帧生成 follow filter（HTTP2/Diameter/SIP）。

## 15. 里程碑（Milestones）
- **M1（MVP）**：实现核心 tools：`pcap_info`、`pcap_timeline`、`pcap_frames_by_filter`、`pcap_frame_detail`。
- **M2**：加入 `pcap_fields_search` + 字段别名回退机制。
- **M3**：加入 `ngap_ue_sessions` / `ngap_pdu_session_summary` 聚合工具。

（当前已额外实现）
- `pcap_packet_list` / `pcap_follow` / `pcap_text_search` / `pcap_list_fields`
- `pcap_config_get` / `pcap_config_reload`

## 快速上手/典型用法

### 1. pcap_info

- 获取 pcap 文件信息（packet_count、时间范围、tshark_version）

### 2. pcap_timeline

- 获取 pcap 文件时间线表格（按过滤条件输出）

### 3. pcap_frames_by_filter

- 获取 pcap 文件匹配帧列表（按过滤条件输出）

### 4. pcap_frame_detail

- 获取 pcap 文件指定帧详细解码（按过滤条件输出）

### 5. pcap_packet_list

- 导出 pcap 文件 Packet List（TSV）

### 6. pcap_follow

- 从 pcap 文件指定帧生成 follow filter（HTTP2/Diameter/SIP）

### 7. pcap_text_search

- 在 pcap 文件中进行文本搜索（按过滤条件输出）

### 8. pcap_list_fields

- 获取 pcap 文件字段列表（按过滤条件输出）

### 9. pcap_config_get / pcap_config_reload

- 获取/热加载 pcap 配置（profiles、packet_list_columns、路径白名单等）
