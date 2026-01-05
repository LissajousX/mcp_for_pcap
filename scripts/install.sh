#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

add_aliases() {
  local rc_file="${PCAP_MCP_SHELL_RC:-${HOME}/.bashrc}"
  local marker_start="### pcap-mcp aliases (added by install.sh)"
  local marker_end="### end pcap-mcp aliases"

  if [[ -f "${rc_file}" ]] && grep -Fq "${marker_start}" "${rc_file}"; then
    echo "Aliases already present in ${rc_file}" >&2
    return
  fi

  echo "Adding aliases to ${rc_file}" >&2
  {
    echo ""
    echo "${marker_start}"
    echo "alias pcap-mcp-doctor='(cd ${REPO_DIR} && ./.venv/bin/python -m pcap_mcp doctor)'"
    echo "alias pcap-mcp-uninstall='(cd ${REPO_DIR} && ./scripts/uninstall.sh --all)'"
    echo "${marker_end}"
  } >>"${rc_file}"

  # shellcheck source=/dev/null
  if [[ -f "${rc_file}" ]]; then
    echo "Sourcing ${rc_file} to activate aliases in current shell..." >&2
    # Use subshell to avoid breaking current shell on errors
    ( source "${rc_file}" ) >/dev/null 2>&1 || true
  fi
}

install_system_deps_apt() {
  if ! need_cmd sudo; then
    echo "tshark/capinfos not found and sudo is not available." >&2
    return 1
  fi
  if ! need_cmd apt-get; then
    echo "apt-get not found; please install tshark/capinfos manually." >&2
    return 1
  fi

  echo "Installing system deps via apt (tshark, wireshark-common)..." >&2
  sudo apt-get update
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y tshark wireshark-common
}

if ! need_cmd tshark || ! need_cmd capinfos; then
  echo "Missing system deps: tshark and/or capinfos." >&2
  if [[ "${PCAP_MCP_NO_SYSTEM_DEPS:-0}" == "1" ]]; then
    echo "PCAP_MCP_NO_SYSTEM_DEPS=1 set; skipping system deps install." >&2
  else
    install_system_deps_apt
  fi
fi

chmod +x "${REPO_DIR}/scripts/setup.sh" "${REPO_DIR}/scripts/run_mcp.sh" "${REPO_DIR}/scripts/uninstall.sh" 2>/dev/null || true
chmod +x "${REPO_DIR}/scripts/install.sh" 2>/dev/null || true

"${REPO_DIR}/scripts/setup.sh"
add_aliases

echo "" >&2
echo "Running doctor..." >&2
"${REPO_DIR}/.venv/bin/python" -m pcap_mcp doctor || true

echo "" >&2
echo "Install complete." >&2
echo "Next:" >&2
echo "  - Start MCP server (for Windsurf): ${REPO_DIR}/scripts/run_mcp.sh" >&2
echo "  - Optional env overrides:" >&2
echo "      PCAP_MCP_CONFIG_JSON=${REPO_DIR}/pcap_mcp_config.json" >&2
echo "      PCAP_MCP_OUTPUT_DIR=/tmp/pcap_mcp_outputs" >&2

echo "" >&2
echo "Windsurf mcp_config.json snippet:" >&2
cat >&2 <<EOF
{
  "mcpServers": {
    "pcap-mcp": {
      "command": "bash",
      "args": [
        "-lc",
        "cd ${REPO_DIR} && ./scripts/run_mcp.sh"
      ],
      "disabled": false,
      "disabledTools": []
    }
  }
}
EOF
