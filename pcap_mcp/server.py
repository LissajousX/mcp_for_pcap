from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

from .config import load_config
from .errors import PcapMcpError
from .paths import validate_pcap_path
from .tshark_tools import (
    capinfos_basic,
    follow_filter_for_frame as _follow_filter_for_frame,
    frames_by_filter as _frames_by_filter,
    frame_detail as _frame_detail,
    has_any_packet,
    list_fields as _list_fields,
    packet_list_export as _packet_list_export,
    text_search as _text_search,
    timeline as _timeline,
    tshark_version,
)


cfg = load_config()
app = FastMCP("pcap-mcp")


def _ok(payload: dict[str, Any]) -> dict[str, Any]:
    return payload


def _dedupe_strs(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in items:
        s = (x or "").strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def _handle_error(e: Exception) -> None:
    if isinstance(e, PcapMcpError):
        raise
    raise PcapMcpError("INTERNAL_ERROR", str(e))


def _available_profile_names() -> list[str]:
    return sorted(cfg.profiles.keys())


def _get_profile(name: str) -> Optional[Any]:
    if not name:
        return None
    return cfg.profiles.get(name)


def _config_snapshot() -> dict[str, Any]:
    return {
        "allowed_pcap_dirs": [str(p) for p in cfg.allowed_pcap_dirs],
        "allow_any_pcap_path": bool(cfg.allow_any_pcap_path),
        "tshark_path": cfg.tshark_path,
        "capinfos_path": cfg.capinfos_path,
        "default_timeout_s": cfg.default_timeout_s,
        "max_timeline_rows": cfg.max_timeline_rows,
        "max_detail_bytes": cfg.max_detail_bytes,
        "export_timeout_s": cfg.export_timeout_s,
        "output_dir": str(cfg.output_dir),
        "time_offset_hours": cfg.time_offset_hours,
        "global_decode_as": list(cfg.global_decode_as),
        "global_preferences": list(cfg.global_preferences),
        "profiles": {
            name: {
                "display_filter": prof.display_filter,
                "decode_as": list(prof.decode_as),
                "preferences": list(prof.preferences),
            }
            for name, prof in cfg.profiles.items()
        },
        "packet_list_columns": {
            name: [{"name": col_name, "field": field} for col_name, field in cols]
            for name, cols in cfg.packet_list_columns.items()
        },
    }


@app.tool(name="pcap_config_get")
def pcap_config_get() -> dict[str, Any]:
    """获取当前 MCP Server 的配置快照。

    返回的快照包含：允许的 PCAP 目录、decode-as 规则、profiles、packet_list_columns 等。
    """
    try:
        return _ok(_config_snapshot())
    except Exception as e:
        _handle_error(e)
        raise


@app.tool(name="pcap_config_reload")
def pcap_config_reload() -> dict[str, Any]:
    """热加载配置。

    重新读取 `pcap_mcp_config.json`（或 `PCAP_MCP_CONFIG_JSON` 指定的配置文件），无需重启服务。
    """
    try:
        global cfg
        cfg = load_config()
        return _ok({"reloaded": True, **_config_snapshot()})
    except Exception as e:
        _handle_error(e)
        raise


@app.tool(name="pcap_list_fields")
def pcap_list_fields(
    query: str = "",
    is_regex: bool = False,
    case_sensitive: bool = False,
    limit: int = 200,
    include_protocols: bool = False,
) -> dict[str, Any]:
    """列出/搜索 tshark 可用字段（字段发现）。

    适用于：不知道 Wireshark 字段名时先查字段，再用于 `pcap_timeline`/`pcap_packet_list`。
    """
    try:
        res = _list_fields(
            cfg,
            query=query,
            is_regex=bool(is_regex),
            case_sensitive=bool(case_sensitive),
            limit=int(limit),
            include_protocols=bool(include_protocols),
        )
        return _ok(res)
    except Exception as e:
        _handle_error(e)
        raise


@app.tool(name="pcap_follow")
def pcap_follow(
    pcap_path: str,
    frame_number: int,
    display_filter: str = "",
    profile: Optional[str] = None,
    limit: int = 500,
    offset: int = 0,
    decode_as: Optional[list[str]] = None,
) -> dict[str, Any]:
    """从指定帧生成“会话跟踪”过滤器（follow filter）。

    支持提取并跟踪的 key：
    - HTTP2：streamid
    - Diameter：Session-Id
    - SIP：Call-ID

    输出会返回生成的 follow filter，并可直接给出匹配帧列表，便于串起完整会话。
    """
    try:
        p = validate_pcap_path(cfg, pcap_path)

        effective_base_filter = (display_filter or "").strip()
        profile_decode_as: list[str] = []
        profile_preferences: list[str] = []

        if profile:
            prof = _get_profile(profile)
            if not prof:
                raise PcapMcpError(
                    "INVALID_ARGUMENT",
                    "unknown profile",
                    {"profile": profile, "available": _available_profile_names()},
                )

            if (prof.display_filter or "").strip():
                if effective_base_filter:
                    effective_base_filter = f"({prof.display_filter}) && ({effective_base_filter})"
                else:
                    effective_base_filter = prof.display_filter

            profile_decode_as = list(prof.decode_as)
            profile_preferences = list(prof.preferences)

        effective_decode_as = _dedupe_strs([*cfg.global_decode_as, *profile_decode_as, *(decode_as or [])])
        effective_preferences = _dedupe_strs([*cfg.global_preferences, *profile_preferences])

        follow = _follow_filter_for_frame(
            cfg,
            p=p,
            frame_number=int(frame_number),
            decode_as=effective_decode_as,
            preferences=effective_preferences,
        )

        follow_filter = (follow.get("display_filter") or "").strip()
        if not follow_filter:
            raise PcapMcpError("INTERNAL_ERROR", "follow_filter_for_frame returned empty display_filter")

        effective_display_filter = follow_filter
        if effective_base_filter:
            effective_display_filter = f"({effective_base_filter}) && ({follow_filter})"

        frames = _frames_by_filter(
            cfg,
            p=p,
            display_filter=effective_display_filter,
            decode_as=effective_decode_as,
            preferences=effective_preferences,
            limit=int(limit),
            offset=int(offset),
        )

        return _ok(
            {
                "pcap_path": str(p),
                "frame_number": int(frame_number),
                "profile": profile or "",
                "decode_as": effective_decode_as,
                "preferences": effective_preferences,
                "follow_type": follow.get("follow_type") or "",
                "follow_key": follow.get("follow_key") or "",
                "follow_display_filter": follow_filter,
                "display_filter": effective_display_filter,
                "limit": int(limit),
                "offset": int(offset),
                "frames": frames,
            }
        )
    except Exception as e:
        _handle_error(e)
        raise



@app.tool(name="pcap_info")
def pcap_info(pcap_path: str) -> dict[str, Any]:
    """抓包摘要信息。

    返回抓包的包数、起止时间、持续时间、tshark 版本，以及常见协议是否出现（快速判断抓包点）。
    """
    try:
        p = validate_pcap_path(cfg, pcap_path)
        info = capinfos_basic(cfg, p)
        info["tshark_version"] = tshark_version(cfg)
        info["has_protocols"] = {
            "sctp": has_any_packet(cfg, p, "sctp"),
            "ngap": has_any_packet(cfg, p, "ngap"),
            "nas_5gs": has_any_packet(cfg, p, "nas-5gs"),
            "pfcp": has_any_packet(cfg, p, "pfcp"),
            "gtpv2": has_any_packet(cfg, p, "gtpv2"),
            "gtp": has_any_packet(cfg, p, "gtp"),
        }
        return _ok(info)
    except Exception as e:
        _handle_error(e)
        raise


@app.tool(name="pcap_text_search")
def pcap_text_search(
    pcap_path: str,
    display_filter: str,
    query: str,
    profile: Optional[str] = None,
    is_regex: bool = False,
    case_sensitive: bool = False,
    layers: Optional[list[str]] = None,
    restrict_layers: bool = True,
    limit: int = 200,
    offset: int = 0,
    max_matches: int = 50,
    snippet_context_chars: int = 240,
    max_bytes: Optional[int] = None,
    decode_as: Optional[list[str]] = None,
) -> dict[str, Any]:
    """在指定过滤条件的帧集合中进行文本搜索。

    典型用途：
    - 搜索 `/npcf`、`sm-policies`、`Semantic errors in packet filter` 等关键字
    - 将命中帧号回填给 `pcap_frame_detail` 做进一步下钻
    """
    try:
        p = validate_pcap_path(cfg, pcap_path)

        effective_display_filter = (display_filter or "").strip()
        profile_decode_as: list[str] = []
        profile_preferences: list[str] = []

        if profile:
            prof = _get_profile(profile)
            if not prof:
                raise PcapMcpError(
                    "INVALID_ARGUMENT",
                    "unknown profile",
                    {"profile": profile, "available": _available_profile_names()},
                )

            if (prof.display_filter or "").strip():
                if effective_display_filter:
                    effective_display_filter = f"({prof.display_filter}) && ({effective_display_filter})"
                else:
                    effective_display_filter = prof.display_filter

            profile_decode_as = list(prof.decode_as)
            profile_preferences = list(prof.preferences)

        effective_decode_as = _dedupe_strs([*cfg.global_decode_as, *profile_decode_as, *(decode_as or [])])
        effective_preferences = _dedupe_strs([*cfg.global_preferences, *profile_preferences])
        effective_max_bytes = int(max_bytes) if max_bytes is not None else cfg.max_detail_bytes

        res = _text_search(
            cfg,
            p=p,
            display_filter=effective_display_filter,
            query=query,
            is_regex=bool(is_regex),
            case_sensitive=bool(case_sensitive),
            layers=layers,
            restrict_layers=bool(restrict_layers),
            decode_as=effective_decode_as,
            preferences=effective_preferences,
            limit=int(limit),
            offset=int(offset),
            max_matches=int(max_matches),
            max_bytes=int(effective_max_bytes),
            snippet_context_chars=int(snippet_context_chars),
        )

        return _ok(
            {
                "pcap_path": str(p),
                "profile": profile or "",
                "decode_as": effective_decode_as,
                "preferences": effective_preferences,
                **res,
            }
        )
    except Exception as e:
        _handle_error(e)
        raise


@app.tool(name="pcap_timeline")
def pcap_timeline(
    pcap_path: str,
    display_filter: str,
    fields: list[str],
    profile: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
    sort_by: Optional[str] = None,
    decode_as: Optional[list[str]] = None,
) -> dict[str, Any]:
    """抽取指定字段形成时间线（类似 Wireshark 自定义列/表格）。

    用于对齐多协议时序：例如 SIP / NGAP / NAS / PFCP / HTTP2 / Diameter。
    """
    try:
        _ = sort_by
        p = validate_pcap_path(cfg, pcap_path)

        effective_display_filter = (display_filter or "").strip()
        profile_decode_as: list[str] = []
        profile_preferences: list[str] = []

        if profile:
            prof = _get_profile(profile)
            if not prof:
                raise PcapMcpError(
                    "INVALID_ARGUMENT",
                    "unknown profile",
                    {"profile": profile, "available": _available_profile_names()},
                )

            if (prof.display_filter or "").strip():
                if effective_display_filter:
                    effective_display_filter = f"({prof.display_filter}) && ({effective_display_filter})"
                else:
                    effective_display_filter = prof.display_filter

            profile_decode_as = list(prof.decode_as)
            profile_preferences = list(prof.preferences)

        effective_decode_as = _dedupe_strs([*cfg.global_decode_as, *profile_decode_as, *(decode_as or [])])
        effective_preferences = _dedupe_strs([*cfg.global_preferences, *profile_preferences])
        res = _timeline(
            cfg,
            p=p,
            display_filter=effective_display_filter,
            decode_as=effective_decode_as,
            preferences=effective_preferences,
            fields=fields,
            limit=limit,
            offset=offset,
        )
        return _ok(
            {
                "pcap_path": str(p),
                "profile": profile or "",
                "display_filter": effective_display_filter,
                "decode_as": effective_decode_as,
                "preferences": effective_preferences,
                "fields": fields,
                "limit": limit,
                "offset": offset,
                "rows": res.rows,
                "warnings": res.warnings,
            }
        )
    except Exception as e:
        _handle_error(e)
        raise


@app.tool(name="pcap_frames_by_filter")
def pcap_frames_by_filter(
    pcap_path: str,
    display_filter: str,
    limit: int = 500,
    offset: int = 0,
    profile: Optional[str] = None,
    decode_as: Optional[list[str]] = None,
) -> dict[str, Any]:
    """按 Wireshark Display Filter 筛选并返回 frame.number 列表（分页）。

    常用于：先定位错误帧/关键帧号，再用 `pcap_frame_detail` 下钻。
    """
    try:
        p = validate_pcap_path(cfg, pcap_path)

        effective_display_filter = (display_filter or "").strip()
        profile_decode_as: list[str] = []
        profile_preferences: list[str] = []

        if profile:
            prof = _get_profile(profile)
            if not prof:
                raise PcapMcpError(
                    "INVALID_ARGUMENT",
                    "unknown profile",
                    {"profile": profile, "available": _available_profile_names()},
                )

            if (prof.display_filter or "").strip():
                if effective_display_filter:
                    effective_display_filter = f"({prof.display_filter}) && ({effective_display_filter})"
                else:
                    effective_display_filter = prof.display_filter

            profile_decode_as = list(prof.decode_as)
            profile_preferences = list(prof.preferences)

        effective_decode_as = _dedupe_strs([*cfg.global_decode_as, *profile_decode_as, *(decode_as or [])])
        effective_preferences = _dedupe_strs([*cfg.global_preferences, *profile_preferences])
        frames = _frames_by_filter(
            cfg,
            p=p,
            display_filter=effective_display_filter,
            decode_as=effective_decode_as,
            preferences=effective_preferences,
            limit=limit,
            offset=offset,
        )
        return _ok(
            {
                "pcap_path": str(p),
                "profile": profile or "",
                "display_filter": effective_display_filter,
                "decode_as": effective_decode_as,
                "preferences": effective_preferences,
                "limit": limit,
                "offset": offset,
                "frames": frames,
            }
        )
    except Exception as e:
        _handle_error(e)
        raise


@app.tool(name="pcap_frame_detail")
def pcap_frame_detail(
    pcap_path: str,
    frame_numbers: list[int],
    layers: Optional[list[str]] = None,
    restrict_layers: bool = True,
    profile: Optional[str] = None,
    verbosity: str = "summary",
    max_bytes: Optional[int] = None,
    decode_as: Optional[list[str]] = None,
) -> dict[str, Any]:
    """对指定帧做协议树下钻（tshark -V）。

    - `restrict_layers=true` 且 `layers` 非空：只输出指定协议层（更聚焦）
    - `restrict_layers=false`：输出完整协议树（更接近 Wireshark 全量下钻）
    - `verbosity=full`：额外输出十六进制（tshark -x），便于更深排查
    - `max_bytes`：输出截断保护
    """
    try:
        p = validate_pcap_path(cfg, pcap_path)

        if not frame_numbers:
            raise PcapMcpError("INVALID_ARGUMENT", "frame_numbers is empty")

        if len(frame_numbers) > 50:
            raise PcapMcpError("INVALID_ARGUMENT", "too many frame_numbers", {"max": 50})

        if verbosity not in ("summary", "full"):
            raise PcapMcpError("INVALID_ARGUMENT", "verbosity must be summary|full")

        effective_max_bytes = int(max_bytes) if max_bytes is not None else cfg.max_detail_bytes

        profile_decode_as: list[str] = []
        profile_preferences: list[str] = []
        if profile:
            prof = _get_profile(profile)
            if not prof:
                raise PcapMcpError(
                    "INVALID_ARGUMENT",
                    "unknown profile",
                    {"profile": profile, "available": _available_profile_names()},
                )
            profile_decode_as = list(prof.decode_as)
            profile_preferences = list(prof.preferences)

        effective_decode_as = _dedupe_strs([*cfg.global_decode_as, *profile_decode_as, *(decode_as or [])])
        effective_preferences = _dedupe_strs([*cfg.global_preferences, *profile_preferences])

        frames_out: list[dict[str, Any]] = []
        for n in frame_numbers:
            text, truncated = _frame_detail(
                cfg,
                p=p,
                frame_number=int(n),
                layers=layers,
                restrict_layers=bool(restrict_layers),
                verbosity=str(verbosity),
                decode_as=effective_decode_as,
                preferences=effective_preferences,
                max_bytes=effective_max_bytes,
            )
            frames_out.append(
                {
                    "frame_number": int(n),
                    "text": text,
                    "truncated": truncated,
                }
            )

        return _ok(
            {
                "pcap_path": str(p),
                "frame_numbers": [int(x) for x in frame_numbers],
                "layers": layers or [],
                "restrict_layers": bool(restrict_layers),
                "profile": profile or "",
                "verbosity": verbosity,
                "max_bytes": effective_max_bytes,
                "decode_as": effective_decode_as,
                "preferences": effective_preferences,
                "frames": frames_out,
            }
        )
    except Exception as e:
        _handle_error(e)
        raise


@app.tool(name="pcap_packet_list")
def pcap_packet_list(
    pcap_path: str,
    display_filter: str = "",
    profile: Optional[str] = None,
    columns_profile: Optional[str] = None,
    include_default_columns: bool = True,
    extra_columns: Optional[list[dict[str, str]]] = None,
    decode_as: Optional[list[str]] = None,
    output_basename: Optional[str] = None,
    preview_rows: int = 50,
) -> dict[str, Any]:
    """导出 Wireshark 风格 Packet List（TSV 文件）。

    - 完整结果写入 `output_dir` 下的 TSV 文件
    - 返回文件路径、写入行数、以及少量 `preview_rows` 预览
    - 可通过 `columns_profile`/`extra_columns` 增加 Diameter/HTTP2/SIP 跟踪字段
    """
    try:
        p = validate_pcap_path(cfg, pcap_path)

        effective_display_filter = (display_filter or "").strip()
        profile_decode_as: list[str] = []
        profile_preferences: list[str] = []

        if profile:
            prof = _get_profile(profile)
            if not prof:
                raise PcapMcpError(
                    "INVALID_ARGUMENT",
                    "unknown profile",
                    {"profile": profile, "available": _available_profile_names()},
                )

            if (prof.display_filter or "").strip():
                if effective_display_filter:
                    effective_display_filter = f"({prof.display_filter}) && ({effective_display_filter})"
                else:
                    effective_display_filter = prof.display_filter

            profile_decode_as = list(prof.decode_as)
            profile_preferences = list(prof.preferences)

        effective_decode_as = _dedupe_strs([*cfg.global_decode_as, *profile_decode_as, *(decode_as or [])])
        effective_preferences = _dedupe_strs([*cfg.global_preferences, *profile_preferences])
        if len(effective_decode_as) > 50:
            raise PcapMcpError("INVALID_ARGUMENT", "too many decode_as entries", {"max": 50})

        cfg_extra_cols: list[tuple[str, str]] = []
        if columns_profile:
            cols = cfg.packet_list_columns.get(columns_profile)
            if not cols:
                raise PcapMcpError(
                    "INVALID_ARGUMENT",
                    "unknown columns_profile",
                    {"columns_profile": columns_profile, "available": sorted(cfg.packet_list_columns.keys())},
                )
            cfg_extra_cols = list(cols)

        req_extra_cols: list[tuple[str, str]] = []
        if extra_columns:
            if not isinstance(extra_columns, list):
                raise PcapMcpError("INVALID_ARGUMENT", "extra_columns must be a list")
            for item in extra_columns:
                if not isinstance(item, dict):
                    continue
                n = str(item.get("name") or "").strip()
                f = str(item.get("field") or "").strip()
                if not n or not f:
                    continue
                req_extra_cols.append((n, f))

        safe_base = (output_basename or "").strip()
        if not safe_base:
            safe_base = p.stem
        safe_base = "".join(ch if (ch.isalnum() or ch in ("-", "_", ".")) else "_" for ch in safe_base)
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        out_path = (cfg.output_dir / f"{safe_base}.packet_list.{ts}.tsv").resolve()

        export_res = _packet_list_export(
            cfg,
            p=p,
            display_filter=effective_display_filter,
            decode_as=effective_decode_as,
            preferences=effective_preferences,
            output_path=out_path,
            extra_columns=[*cfg_extra_cols, *req_extra_cols],
            include_default_columns=bool(include_default_columns),
        )

        effective_preview_rows = int(preview_rows)
        if effective_preview_rows < 0:
            raise PcapMcpError("INVALID_ARGUMENT", "preview_rows must be non-negative")
        if effective_preview_rows > 200:
            effective_preview_rows = 200

        preview: list[dict[str, str]] = []
        if effective_preview_rows > 0:
            with out_path.open("r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f, delimiter="\t")
                for _i, row in enumerate(reader):
                    preview.append({k: (v or "") for k, v in row.items() if k is not None})
                    if len(preview) >= effective_preview_rows:
                        break

        try:
            file_size = out_path.stat().st_size
        except Exception:
            file_size = None

        return _ok(
            {
                "pcap_path": str(p),
                "profile": profile or "",
                "columns_profile": columns_profile or "",
                "include_default_columns": bool(include_default_columns),
                "display_filter": effective_display_filter,
                "decode_as": effective_decode_as,
                "preferences": effective_preferences,
                "output_path": str(out_path),
                "file_size_bytes": file_size,
                "rows_written": int(export_res.get("rows_written") or 0),
                "preview_rows": preview,
                "warnings": export_res.get("warnings") or [],
            }
        )
    except Exception as e:
        _handle_error(e)
        raise


def main() -> None:
    app.run()
