#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

VENV_DIR="${PCAP_MCP_VENV_DIR:-"${REPO_DIR}/.venv"}"
PY="${VENV_DIR}/bin/python"

if [[ ! -x "${PY}" ]]; then
  echo "pcap-mcp venv not found at: ${PY}" >&2
  echo "Run once: ${REPO_DIR}/scripts/setup.sh" >&2
  exit 1
fi

# Default config file: repo root pcap_mcp_config.json
export PCAP_MCP_CONFIG_JSON="${PCAP_MCP_CONFIG_JSON:-"${REPO_DIR}/pcap_mcp_config.json"}"

# Default output dir: prefer XDG cache, fall back to /tmp
if [[ -z "${PCAP_MCP_OUTPUT_DIR:-}" ]]; then
  if [[ -n "${XDG_CACHE_HOME:-}" ]]; then
    export PCAP_MCP_OUTPUT_DIR="${XDG_CACHE_HOME}/pcap_mcp_outputs"
  else
    export PCAP_MCP_OUTPUT_DIR="/tmp/pcap_mcp_outputs"
  fi
fi

exec "${PY}" -m pcap_mcp
