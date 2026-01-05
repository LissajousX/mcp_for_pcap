# pcap-mcp

[English](./README.en.md) | [中文](./README.md)

License: Apache-2.0

Turn **Wireshark/tshark** into a set of structured **MCP tools**.
Give an agent a PCAP file, and it can troubleshoot in a “Wireshark-like” workflow (filter, timeline, drill-down, follow session, export packet list) with controlled output and clear safety boundaries.

## What you can do with it

- **Locate fast**: find the exact frames using Wireshark Display Filters
- **Drill down safely**: inspect protocol trees for specific frames (with truncation protection)
- **Align cause-and-effect**: extract fields into timelines across SIP / Diameter / HTTP2 / PFCP / NGAP / NAS / S1AP / NAS-EPS
- **Export tables**: Wireshark-like Packet List TSV for further analysis

## Requirements

- Python `>=3.10`
- `tshark` (required)
- `capinfos` (recommended; usually shipped with Wireshark CLI tools)

## Quick Start (recommended)

1) From the repo root:

```bash
./scripts/bootstrap.sh
```

2) (Optional but recommended) Run diagnostics:

```bash
./.venv/bin/python -m pcap_mcp doctor
```

3) Windsurf MCP config (stdio, **do not print anything to stdout**):

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

## Configuration

By default it reads `pcap_mcp_config.json` from the repo root.
You can override via environment variables:

- `PCAP_MCP_CONFIG_JSON=/abs/path/to/pcap_mcp_config.json`
- `PCAP_MCP_OUTPUT_DIR=/tmp/pcap_mcp_outputs`

The most common settings:

- `allowed_pcap_dirs`: allowlist of directories containing PCAP files
- `allow_any_pcap_path`: allow arbitrary absolute paths (default `false`)
- `profiles`: curated display filters / decode-as / preferences combos

## MCP tools (overview)

- **Config & field discovery**: `pcap_config_get`, `pcap_config_reload`, `pcap_list_fields`
- **Locate & tabularize**: `pcap_info`, `pcap_frames_by_filter`, `pcap_timeline`, `pcap_packet_list`
- **Deep analysis**: `pcap_frame_detail`, `pcap_text_search`, `pcap_follow`

## Troubleshooting

- **Windsurf initialization timeout / JSON parse errors**
  - In stdio mode, server **stdout must contain only JSON-RPC**.
  - Use `./scripts/run_mcp.sh` and do not add anything that prints to stdout (including `echo`, `pip`, shell banners, etc.).

- **Missing tshark/capinfos**
  - Ubuntu/Debian: `sudo apt-get update && sudo apt-get install -y tshark wireshark-common`
  - Then re-run: `./scripts/bootstrap.sh`

## Docs

- `docs/PCAP_MCP_需求文档.md`
- `docs/BLOG_pcap-mcp_设计与实战.md`
- `docs/BLOG_pcap-mcp_痛点与价值.md`
