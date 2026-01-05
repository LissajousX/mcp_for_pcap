# pcap-mcp

[English](./README.en.md) | [中文](./README.md)

License: Apache-2.0

把 **Wireshark/tshark** 变成一组结构化的 **MCP Tools**：
给智能体/脚本一个 PCAP，就能按“像 Wireshark 一样”的方式自动化排障（过滤、下钻、时间线、会话跟踪、导表）。

## 你会用它做什么

- **快速定位**：用 Display Filter 找到关键帧（错误码、路径、AVP、stream 等）
- **深度下钻**：对指定帧做 Wireshark 级别的协议树下钻（可只看关心层）
- **对齐因果链**：抽字段生成时间线，把 SIP/Diameter/HTTP2/PFCP/NGAP/NAS 串起来
- **导出表格**：导出类似 Wireshark Packet List 的 TSV，方便进一步分析

## 依赖

- Python `>=3.10`
- `tshark`（必须）
- `capinfos`（建议，通常随 Wireshark CLI 工具一起安装）

## Quick Start（最推荐，新手无脑版）

1) 从仓库根目录：

```bash
./scripts/install.sh
```

2)（可选）诊断：

```bash
./.venv/bin/python -m pcap_mcp doctor
```

3) Windsurf 配置（stdio，**不要重定向 stdout**）：

```json
{
  "mcpServers": {
    "pcap-mcp": {
      "command": "bash",
      "args": [
        "-lc",
        "cd /ABS/PATH/TO/REPO && ./scripts/run_mcp.sh"
      ],
      "disabled": false,
      "disabledTools": []
    }
  }
}
```

（可选）已自动在 `~/.bashrc` 增加便捷别名：
- `pcap-mcp-doctor` / `pcap-mcp-uninstall`

## 更新 / 重启

- **配置变更**：调用 `pcap_config_reload`，无需重启。
- **代码/依赖更新**：
  - `git pull`
  - `./scripts/install.sh`
  - 在 Windsurf MCP 面板尝试 Disable→Enable 以重新执行启动命令（`bash -lc "cd /home/lisa/mcp_for_pcap && ./scripts/run_mcp.sh"`）。若 Enable 未生效，直接删除后重新添加该 MCP 配置，或重启 Windsurf 再 Enable。

## 卸载 / 清理

```bash
./scripts/uninstall.sh
```

- 同时清理导出目录：`./scripts/uninstall.sh --all`

## 配置

默认读取仓库根目录的 `pcap_mcp_config.json`，也可以通过环境变量覆盖：

- `PCAP_MCP_CONFIG_JSON=/abs/path/to/pcap_mcp_config.json`
- `PCAP_MCP_OUTPUT_DIR=/tmp/pcap_mcp_outputs`

最常改的配置：

- `allowed_pcap_dirs`：允许分析的 PCAP 目录白名单
- `allow_any_pcap_path`：是否允许任意绝对路径 PCAP（默认 false）
- `profiles` / `global_decode_as`：常用过滤/解码组合

## MCP Tools（概览）

- **配置与字段发现**：`pcap_config_get`、`pcap_config_reload`、`pcap_list_fields`
- **定位与表格化**：`pcap_info`、`pcap_frames_by_filter`、`pcap_timeline`、`pcap_packet_list`
- **深度分析**：`pcap_frame_detail`、`pcap_text_search`、`pcap_follow`

## 常见问题

- **Windsurf 初始化超时 / JSON 解析错误**
  - stdio 模式下，server 的 **stdout 必须只输出 JSON-RPC**。
  - 请用 `./scripts/run_mcp.sh` 启动，不要在启动命令里加任何会往 stdout 打印的东西（包括 `echo`、`pip` 输出、shell banner 等）。

- **找不到 tshark/capinfos**
  - Ubuntu/Debian：`sudo apt-get update && sudo apt-get install -y tshark wireshark-common`
  - 然后重新跑：`./scripts/install.sh`

## 文档

- `docs/PCAP_MCP_需求文档.md`
- `docs/BLOG_pcap-mcp_设计与实战.md`
- `docs/BLOG_pcap-mcp_痛点与价值.md`
