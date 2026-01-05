#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${PCAP_MCP_VENV_DIR:-"${REPO_DIR}/.venv"}"
PYTHON_BIN="${PCAP_MCP_PYTHON:-python3}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

if ! need_cmd "$PYTHON_BIN"; then
  echo "python not found: ${PYTHON_BIN}" >&2
  echo "Tip: set PCAP_MCP_PYTHON=/abs/path/to/python3" >&2
  exit 1
fi

if [[ "${PCAP_MCP_SKIP_SYSTEM_CHECKS:-0}" != "1" ]]; then
  if ! need_cmd tshark; then
    echo "tshark not found. Please install Wireshark CLI tools first." >&2
    echo "Ubuntu/Debian: sudo apt-get update && sudo apt-get install -y tshark wireshark-common" >&2
    exit 1
  fi

  if ! need_cmd capinfos; then
    echo "capinfos not found. Please install Wireshark CLI tools first." >&2
    echo "Ubuntu/Debian: sudo apt-get update && sudo apt-get install -y tshark wireshark-common" >&2
    exit 1
  fi
fi

if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
  echo "Creating venv: ${VENV_DIR}" >&2
  "${PYTHON_BIN}" -m venv "${VENV_DIR}"
fi

echo "Installing Python deps into venv..." >&2
"${VENV_DIR}/bin/python" -m pip install --upgrade pip >/dev/null 2>&1 || true
"${VENV_DIR}/bin/python" -m pip install -e "${REPO_DIR}" >/dev/null

"${VENV_DIR}/bin/python" -c "import mcp, pcap_mcp" >/dev/null

echo "Python deps OK." >&2
