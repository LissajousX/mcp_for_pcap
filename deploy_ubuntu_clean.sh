#!/usr/bin/env bash
set -euo pipefail

ENV_NAME="pcap-mcp"
PYTHON_VERSION="3.12"
CONDA_PREFIX_DIR="${HOME}/miniconda3"
INSTALL_SYSTEM_DEPS=1
START_SERVER=0

usage() {
  cat <<'USAGE'
Usage: ./deploy_ubuntu_clean.sh [options]

Options:
  --env <name>           Conda env name (default: pcap-mcp)
  --python <version>     Python version for env (default: 3.12)
  --conda-prefix <path>  Miniconda install dir (default: ~/miniconda3)
  --no-system-deps       Skip installing tshark/capinfos via apt
  --start                Start server after install
  -h, --help             Show help

Proxy (optional):
  export http_proxy=http://192.168.245.1:10808
  export https_proxy=http://192.168.245.1:10808
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env)
      ENV_NAME="$2"; shift 2 ;;
    --python)
      PYTHON_VERSION="$2"; shift 2 ;;
    --conda-prefix)
      CONDA_PREFIX_DIR="$2"; shift 2 ;;
    --no-system-deps)
      INSTALL_SYSTEM_DEPS=0; shift 1 ;;
    --start)
      START_SERVER=1; shift 1 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "Unknown arg: $1" >&2
      usage
      exit 2
      ;;
  esac
done

REPO_DIR="$(pwd)"

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

install_miniconda() {
  if [[ -x "${CONDA_PREFIX_DIR}/bin/conda" ]]; then
    return 0
  fi

  local installer="/tmp/miniconda3.sh"
  local url="https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh"

  if need_cmd curl; then
    curl -fsSL "$url" -o "$installer"
  elif need_cmd wget; then
    wget -O "$installer" "$url"
  else
    echo "Need curl or wget to download Miniconda" >&2
    exit 1
  fi

  bash "$installer" -b -p "$CONDA_PREFIX_DIR"
}

install_system_deps() {
  if [[ $INSTALL_SYSTEM_DEPS -eq 0 ]]; then
    return 0
  fi

  if need_cmd tshark && need_cmd capinfos; then
    return 0
  fi

  if ! need_cmd sudo; then
    echo "tshark/capinfos not found and sudo is not available." >&2
    echo "Please install Wireshark CLI tools (tshark + capinfos) first, then re-run." >&2
    exit 1
  fi

  sudo apt-get update
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y tshark wireshark-common

  if ! need_cmd tshark; then
    echo "tshark still not found after install." >&2
    exit 1
  fi
  if ! need_cmd capinfos; then
    echo "capinfos still not found after install." >&2
    exit 1
  fi
}

main() {
  install_system_deps
  install_miniconda

  local conda_exe="${CONDA_PREFIX_DIR}/bin/conda"

  "$conda_exe" config --set auto_activate_base false >/dev/null

  if ! "$conda_exe" env list | awk '{print $1}' | grep -qx "$ENV_NAME"; then
    "$conda_exe" create -y -n "$ENV_NAME" "python=${PYTHON_VERSION}"
  fi

  "$conda_exe" run -n "$ENV_NAME" python -m pip install --upgrade pip

  "$conda_exe" run -n "$ENV_NAME" python -m pip install -e "$REPO_DIR"

  "$conda_exe" run -n "$ENV_NAME" python -c "import pcap_mcp; import mcp; print('import ok')"

  echo ""
  echo "Installed OK."
  echo "Run server:"
  echo "  ${conda_exe} run -n ${ENV_NAME} pcap-mcp"
  echo ""
  echo "Optional config override:"
  echo "  export PCAP_MCP_CONFIG_JSON=${REPO_DIR}/pcap_mcp_config.json"

  if [[ $START_SERVER -eq 1 ]]; then
    echo ""
    echo "Starting server..."
    exec "$conda_exe" run -n "$ENV_NAME" pcap-mcp
  fi
}

main
