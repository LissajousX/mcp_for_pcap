# Contributing

Thanks for contributing!

## Quick start

1) Fork and clone
2) Create a virtualenv and install:

```bash
./scripts/install.sh
```

## Development tips

- Keep MCP stdio transport clean: **do not write non-JSON content to stdout** in the server process.
- Prefer adding new capabilities as explicit MCP tools, not arbitrary shell execution.
- When adding a new tool:
  - Validate inputs
  - Bound output size (pagination / max bytes)
  - Return structured JSON

## Reporting issues

Please include:

- OS, Python version
- `./.venv/bin/python -m pcap_mcp doctor` output
- The exact tool call parameters (pcap path, display_filter, profile, etc.)
