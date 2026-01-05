#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

VENV_DIR_DEFAULT="${REPO_DIR}/.venv"
VENV_DIR="${PCAP_MCP_VENV_DIR:-"${VENV_DIR_DEFAULT}"}"

# Default output dir from config file is repo-relative, but run_mcp.sh defaults to XDG cache or /tmp.
OUTPUT_DIR_REPO_DEFAULT="${REPO_DIR}/pcap_mcp_outputs"
OUTPUT_DIR_XDG_DEFAULT="${XDG_CACHE_HOME:-""}/pcap_mcp_outputs"
OUTPUT_DIR_TMP_DEFAULT="/tmp/pcap_mcp_outputs"

DO_VENV=1
DO_OUTPUTS=0
ASSUME_YES=0
DRY_RUN=0
FORCE=0

remove_aliases() {
  local rc_file="${PCAP_MCP_SHELL_RC:-${HOME}/.bashrc}"
  local marker_start="### pcap-mcp aliases (added by install.sh)"
  local marker_end="### end pcap-mcp aliases"

  if [[ ! -f "${rc_file}" ]]; then
    return
  fi

  if ! grep -Fq "${marker_start}" "${rc_file}"; then
    return
  fi

  echo "Removing aliases from ${rc_file}" >&2
  python3 - <<PY
from pathlib import Path
rc = Path(${rc_file@Q})
start = ${marker_start@Q}
end = ${marker_end@Q}
lines = rc.read_text().splitlines()
out = []
skip = False
for line in lines:
    if line.strip() == start:
        skip = True
        continue
    if skip and line.strip() == end:
        skip = False
        continue
    if not skip:
        out.append(line)
rc.write_text("\n".join(out) + ("\n" if out and out[-1] != "" else ""))
PY

  # shellcheck source=/dev/null
  if [[ -f "${rc_file}" ]]; then
    echo "Sourcing ${rc_file} to refresh shell aliases..." >&2
    ( source "${rc_file}" ) >/dev/null 2>&1 || true
  fi
}

usage() {
  cat <<'USAGE' >&2
Usage: ./scripts/uninstall.sh [options]

This script removes local *development artifacts* for this repo.
It does NOT uninstall system packages (tshark/capinfos) and does NOT touch other Python environments.

Options:
  --venv           Remove the local venv (default)
  --outputs        Remove known output directories (repo ./pcap_mcp_outputs, XDG cache, /tmp)
  --all            Remove both venv and outputs
  --yes            Do not prompt for confirmation
  --dry-run        Show what would be removed, without deleting
  --force          Allow deleting paths outside the repo directory
  -h, --help       Show help
USAGE
}

is_under_repo() {
  local p="$1"
  python3 - <<PY
from pathlib import Path
repo = Path(${REPO_DIR@Q}).resolve()
p = Path(${p@Q}).expanduser().resolve()
try:
    print(str(p).startswith(str(repo) + "/") or str(p) == str(repo))
except Exception:
    print("False")
PY
}

confirm() {
  local msg="$1"
  if [[ "$ASSUME_YES" == "1" ]]; then
    return 0
  fi
  echo "${msg} [y/N]" >&2
  read -r ans
  [[ "${ans}" == "y" || "${ans}" == "Y" ]]
}

rm_dir() {
  local p="$1"
  if [[ -z "$p" ]]; then
    return 0
  fi
  if [[ ! -e "$p" ]]; then
    return 0
  fi

  local under_repo
  under_repo="$(is_under_repo "$p")"
  if [[ "$FORCE" != "1" && "$under_repo" != "True" && "$under_repo" != "true" ]]; then
    echo "Refusing to remove path outside repo without --force: ${p}" >&2
    return 1
  fi

  if [[ "$DRY_RUN" == "1" ]]; then
    echo "[dry-run] rm -rf ${p}" >&2
    return 0
  fi

  rm -rf "${p}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --venv)
      DO_VENV=1; DO_OUTPUTS=0; shift 1 ;;
    --outputs)
      DO_VENV=0; DO_OUTPUTS=1; shift 1 ;;
    --all)
      DO_VENV=1; DO_OUTPUTS=1; shift 1 ;;
    --yes)
      ASSUME_YES=1; shift 1 ;;
    --dry-run)
      DRY_RUN=1; shift 1 ;;
    --force)
      FORCE=1; shift 1 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "Unknown arg: $1" >&2
      usage
      exit 2
      ;;
  esac
done

echo "Repo: ${REPO_DIR}" >&2

if [[ "$DO_VENV" == "1" ]]; then
  echo "Venv: ${VENV_DIR}" >&2
fi

if [[ "$DO_OUTPUTS" == "1" ]]; then
  echo "Outputs (known locations):" >&2
  echo "  - ${OUTPUT_DIR_REPO_DEFAULT}" >&2
  if [[ -n "${OUTPUT_DIR_XDG_DEFAULT%/pcap_mcp_outputs}" && -n "${XDG_CACHE_HOME:-}" ]]; then
    echo "  - ${OUTPUT_DIR_XDG_DEFAULT}" >&2
  fi
  echo "  - ${OUTPUT_DIR_TMP_DEFAULT}" >&2
fi

echo "" >&2

if [[ "$DO_VENV" == "1" ]]; then
  if confirm "Remove venv directory: ${VENV_DIR}?"; then
    rm_dir "${VENV_DIR}"
    echo "Removed venv: ${VENV_DIR}" >&2
  else
    echo "Skipped venv." >&2
  fi
fi

if [[ "$DO_OUTPUTS" == "1" ]]; then
  if confirm "Remove output directories (generated files)?"; then
    rm_dir "${OUTPUT_DIR_REPO_DEFAULT}"
    if [[ -n "${XDG_CACHE_HOME:-}" ]]; then
      rm_dir "${OUTPUT_DIR_XDG_DEFAULT}"
    fi
    rm_dir "${OUTPUT_DIR_TMP_DEFAULT}"
    echo "Removed outputs." >&2
  else
    echo "Skipped outputs." >&2
  fi
fi

echo "Done." >&2
remove_aliases
