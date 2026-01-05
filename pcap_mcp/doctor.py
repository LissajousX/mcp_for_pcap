from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any


def _print_kv(k: str, v: Any) -> None:
    print(f"{k}: {v}")


def _run_first_line(cmd: list[str], timeout_s: float = 5.0) -> str:
    try:
        cp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout_s)
    except Exception as e:
        return f"ERROR: {e}"
    out = (cp.stdout or "").splitlines()
    return out[0].strip() if out else ""


def _check_writable_dir(p: Path) -> tuple[bool, str]:
    try:
        p.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        return False, f"mkdir failed: {e}"

    try:
        with tempfile.NamedTemporaryFile(prefix="pcap_mcp_", dir=str(p), delete=True):
            pass
    except Exception as e:
        return False, f"write test failed: {e}"

    return True, "ok"


def run_doctor() -> int:
    ok = True

    _print_kv("python.executable", sys.executable)
    _print_kv("python.version", sys.version.replace("\n", " "))

    try:
        from . import __version__ as pcap_mcp_version

        _print_kv("pcap_mcp.version", pcap_mcp_version)
    except Exception as e:
        ok = False
        _print_kv("pcap_mcp.version", f"ERROR: {e}")

    try:
        import importlib.metadata as md

        _print_kv("mcp.version", md.version("mcp"))
    except Exception as e:
        ok = False
        _print_kv("mcp.version", f"ERROR: {e}")

    _print_kv("env.PCAP_MCP_CONFIG_JSON", os.environ.get("PCAP_MCP_CONFIG_JSON") or "")
    _print_kv("env.PCAP_MCP_OUTPUT_DIR", os.environ.get("PCAP_MCP_OUTPUT_DIR") or "")

    try:
        from .config import load_config

        cfg = load_config()
        _print_kv("config.allowed_pcap_dirs", ", ".join(str(p) for p in cfg.allowed_pcap_dirs))
        _print_kv("config.allow_any_pcap_path", cfg.allow_any_pcap_path)
        _print_kv("config.tshark_path", cfg.tshark_path)
        _print_kv("config.capinfos_path", cfg.capinfos_path)
        _print_kv("config.output_dir", str(cfg.output_dir))

        tshark_which = shutil.which(cfg.tshark_path) if cfg.tshark_path else None
        capinfos_which = shutil.which(cfg.capinfos_path) if cfg.capinfos_path else None
        _print_kv("which.tshark", tshark_which or "NOT FOUND")
        _print_kv("which.capinfos", capinfos_which or "NOT FOUND")

        if not tshark_which:
            ok = False
        if not capinfos_which:
            # capinfos is recommended but not strictly required for all tools
            pass

        if tshark_which:
            _print_kv("tshark.version", _run_first_line([cfg.tshark_path, "-v"]))
        if capinfos_which:
            _print_kv("capinfos.version", _run_first_line([cfg.capinfos_path, "-v"]))

        writable, reason = _check_writable_dir(cfg.output_dir)
        _print_kv("output_dir.writable", writable)
        if not writable:
            ok = False
            _print_kv("output_dir.writable_reason", reason)

    except Exception as e:
        ok = False
        _print_kv("config.load", f"ERROR: {e}")

    return 0 if ok else 1
