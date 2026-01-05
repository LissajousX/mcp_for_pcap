from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import os
from typing import Any


@dataclass(frozen=True)
class Profile:
    display_filter: str
    decode_as: tuple[str, ...]
    preferences: tuple[str, ...]


@dataclass(frozen=True)
class Config:
    allowed_pcap_dirs: tuple[Path, ...]
    allow_any_pcap_path: bool
    tshark_path: str
    capinfos_path: str
    default_timeout_s: float
    max_timeline_rows: int
    max_detail_bytes: int
    export_timeout_s: float
    output_dir: Path
    time_offset_hours: int
    global_decode_as: tuple[str, ...]
    global_preferences: tuple[str, ...]
    profiles: dict[str, Profile]
    packet_list_columns: dict[str, tuple[tuple[str, str], ...]]


def load_config() -> Config:
    cfg_path = (os.environ.get("PCAP_MCP_CONFIG_JSON") or "").strip()
    if not cfg_path:
        try:
            default_cfg = (Path(__file__).resolve().parents[1] / "pcap_mcp_config.json").resolve()
            if default_cfg.exists() and default_cfg.is_file():
                cfg_path = str(default_cfg)
        except Exception:
            cfg_path = ""
    file_cfg: dict[str, Any] = {}
    cfg_base_dir = Path.cwd()
    if cfg_path:
        p = Path(cfg_path).expanduser().resolve()
        cfg_base_dir = p.parent
        if p.exists() and p.is_file():
            try:
                file_cfg = json.loads(p.read_text(encoding="utf-8")) or {}
            except Exception as e:
                raise RuntimeError(f"invalid json config: {p}: {e}")

    def _resolve_path(raw: str) -> Path:
        v = Path(raw).expanduser()
        if v.is_absolute():
            return v.resolve()
        return (cfg_base_dir / v).resolve()

    allowed_dirs_raw = (
        str(file_cfg.get("allowed_pcap_dirs"))
        if isinstance(file_cfg.get("allowed_pcap_dirs"), str)
        else os.environ.get("PCAP_MCP_ALLOWED_DIRS", ".")
    )

    if isinstance(file_cfg.get("allowed_pcap_dirs"), list):
        allowed_dirs = tuple(_resolve_path(str(x)) for x in file_cfg.get("allowed_pcap_dirs") if str(x).strip())
    else:
        allowed_dirs = tuple(
            _resolve_path(raw.strip())
            for raw in (allowed_dirs_raw or "").split(",")
            if raw.strip()
        )

    allow_any_pcap_path_raw = file_cfg.get("allow_any_pcap_path")
    if isinstance(allow_any_pcap_path_raw, bool):
        allow_any_pcap_path = bool(allow_any_pcap_path_raw)
    else:
        allow_any_pcap_path = str(os.environ.get("PCAP_MCP_ALLOW_ANY_PCAP_PATH", "0")).strip() in ("1", "true", "TRUE", "yes", "YES")

    tshark_path = str(file_cfg.get("tshark_path") or os.environ.get("PCAP_MCP_TSHARK", "tshark"))
    capinfos_path = str(file_cfg.get("capinfos_path") or os.environ.get("PCAP_MCP_CAPINFOS", "capinfos"))
    default_timeout_s = float(file_cfg.get("default_timeout_s") or os.environ.get("PCAP_MCP_TIMEOUT_S", "30"))
    max_timeline_rows = int(file_cfg.get("max_timeline_rows") or os.environ.get("PCAP_MCP_MAX_TIMELINE_ROWS", "5000"))
    max_detail_bytes = int(file_cfg.get("max_detail_bytes") or os.environ.get("PCAP_MCP_MAX_DETAIL_BYTES", "200000"))
    export_timeout_s = float(file_cfg.get("export_timeout_s") or os.environ.get("PCAP_MCP_EXPORT_TIMEOUT_S", "300"))

    output_dir_raw = str(os.environ.get("PCAP_MCP_OUTPUT_DIR") or file_cfg.get("output_dir") or "./pcap_mcp_outputs")
    output_dir = _resolve_path(output_dir_raw)
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    if "time_offset_hours" in file_cfg:
        time_offset_hours = int(file_cfg.get("time_offset_hours") or 0)
    else:
        time_offset_hours = int(os.environ.get("PCAP_MCP_TIME_OFFSET_HOURS", "0"))

    global_decode_as_raw = file_cfg.get("global_decode_as")
    if isinstance(global_decode_as_raw, list):
        global_decode_as = tuple(str(x).strip() for x in global_decode_as_raw if str(x).strip())
    else:
        env_global_decode_as = (os.environ.get("PCAP_MCP_GLOBAL_DECODE_AS") or "").strip()
        global_decode_as = tuple(s.strip() for s in env_global_decode_as.split(",") if s.strip())

    global_preferences_raw = file_cfg.get("global_preferences")
    if isinstance(global_preferences_raw, list):
        global_preferences = tuple(str(x).strip() for x in global_preferences_raw if str(x).strip())
    else:
        env_global_preferences = (os.environ.get("PCAP_MCP_GLOBAL_PREFERENCES") or "").strip()
        global_preferences = tuple(s.strip() for s in env_global_preferences.split(",") if s.strip())

    profiles: dict[str, Profile] = {}
    profiles_raw = file_cfg.get("profiles")
    if isinstance(profiles_raw, dict):
        for name, pv in profiles_raw.items():
            if not isinstance(name, str) or not name.strip() or not isinstance(pv, dict):
                continue
            df = str(pv.get("display_filter") or "").strip()
            da_raw = pv.get("decode_as")
            if isinstance(da_raw, list):
                da = tuple(str(x).strip() for x in da_raw if str(x).strip())
            else:
                da = ()
            pref_raw = pv.get("preferences")
            if isinstance(pref_raw, list):
                prefs = tuple(str(x).strip() for x in pref_raw if str(x).strip())
            else:
                prefs = ()
            profiles[name.strip()] = Profile(display_filter=df, decode_as=da, preferences=prefs)

    packet_list_columns: dict[str, tuple[tuple[str, str], ...]] = {}
    plc_raw = file_cfg.get("packet_list_columns")
    if isinstance(plc_raw, dict):
        for name, cols_raw in plc_raw.items():
            if not isinstance(name, str) or not name.strip() or not isinstance(cols_raw, list):
                continue
            cols: list[tuple[str, str]] = []
            for item in cols_raw:
                if isinstance(item, dict):
                    col_name = str(item.get("name") or "").strip()
                    field = str(item.get("field") or "").strip()
                elif isinstance(item, (list, tuple)) and len(item) == 2:
                    col_name = str(item[0] or "").strip()
                    field = str(item[1] or "").strip()
                else:
                    continue
                if not col_name or not field:
                    continue
                cols.append((col_name, field))
            if cols:
                packet_list_columns[name.strip()] = tuple(cols)

    return Config(
        allowed_pcap_dirs=allowed_dirs,
        allow_any_pcap_path=bool(allow_any_pcap_path),
        tshark_path=tshark_path,
        capinfos_path=capinfos_path,
        default_timeout_s=default_timeout_s,
        max_timeline_rows=max_timeline_rows,
        max_detail_bytes=max_detail_bytes,
        export_timeout_s=export_timeout_s,
        output_dir=output_dir,
        time_offset_hours=time_offset_hours,
        global_decode_as=global_decode_as,
        global_preferences=global_preferences,
        profiles=profiles,
        packet_list_columns=packet_list_columns,
    )
