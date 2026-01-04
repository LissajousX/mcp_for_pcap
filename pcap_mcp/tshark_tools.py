from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
import re
import time
from typing import Any, Optional

from .config import Config
from .errors import PcapMcpError
from .proc import popen_lines, read_all_stderr, run_checked, safe_kill


def _append_preferences(args: list[str], preferences: Optional[list[str]]) -> None:
    if not preferences:
        return
    if len(preferences) > 100:
        raise PcapMcpError("INVALID_ARGUMENT", "too many preferences", {"max": 100})
    for pref in preferences:
        s = (pref or "").strip()
        if not s:
            continue
        args += ["-o", s]


def _quote_display_filter_string(s: str) -> str:
    v = (s or "")
    v = v.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{v}"'


def frame_fields(
    cfg: Config,
    *,
    p: Path,
    frame_number: int,
    fields: list[str],
    decode_as: Optional[list[str]] = None,
    preferences: Optional[list[str]] = None,
) -> dict[str, str]:
    if frame_number <= 0:
        raise PcapMcpError("INVALID_ARGUMENT", "frame_number must be > 0")
    if not fields:
        raise PcapMcpError("INVALID_ARGUMENT", "fields is empty")

    args: list[str] = [cfg.tshark_path]
    if decode_as:
        if len(decode_as) > 50:
            raise PcapMcpError("INVALID_ARGUMENT", "too many decode_as entries", {"max": 50})
        for d in decode_as:
            s = (d or "").strip()
            if not s:
                continue
            args += ["-d", s]

    _append_preferences(args, preferences)

    args += [
        "-r",
        str(p),
        "-Y",
        f"frame.number=={int(frame_number)}",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "quote=d",
        "-E",
        "occurrence=a",
        "-E",
        "aggregator=|",
    ]
    for f in fields:
        key = (f or "").strip()
        if not key:
            continue
        args += ["-e", key]

    r = run_checked(args, timeout_s=cfg.default_timeout_s)
    if r.returncode != 0:
        raise PcapMcpError("INTERNAL_ERROR", "tshark frame fields failed", {"stderr": r.stderr.strip()})

    line = (r.stdout.splitlines() or [""])[0]
    try:
        parts = next(csv.reader([line], delimiter="\t", quotechar='"'))
    except Exception:
        parts = line.split("\t")

    out: dict[str, str] = {}
    for i, f in enumerate(fields):
        out[f] = (parts[i] if i < len(parts) else "") or ""
    return out


def follow_filter_for_frame(
    cfg: Config,
    *,
    p: Path,
    frame_number: int,
    decode_as: Optional[list[str]] = None,
    preferences: Optional[list[str]] = None,
) -> dict[str, str]:
    vals = frame_fields(
        cfg,
        p=p,
        frame_number=int(frame_number),
        fields=["http2.streamid", "diameter.Session-Id", "sip.Call-ID"],
        decode_as=decode_as,
        preferences=preferences,
    )

    http2_streamid_raw = (vals.get("http2.streamid") or "").strip()
    if http2_streamid_raw:
        first = http2_streamid_raw.split("|")[0].strip()
        try:
            sid = int(first)
            return {
                "follow_type": "http2.streamid",
                "follow_key": str(sid),
                "display_filter": f"http2.streamid=={sid}",
            }
        except Exception:
            pass

    dia_sess_raw = (vals.get("diameter.Session-Id") or "").strip()
    if dia_sess_raw:
        sess = dia_sess_raw.split("|")[0].strip()
        return {
            "follow_type": "diameter.Session-Id",
            "follow_key": sess,
            "display_filter": f"diameter.Session-Id=={_quote_display_filter_string(sess)}",
        }

    sip_callid_raw = (vals.get("sip.Call-ID") or "").strip()
    if sip_callid_raw:
        callid = sip_callid_raw.split("|")[0].strip()
        return {
            "follow_type": "sip.Call-ID",
            "follow_key": callid,
            "display_filter": f"sip.Call-ID=={_quote_display_filter_string(callid)}",
        }

    raise PcapMcpError(
        "NOT_FOUND",
        "no supported follow key found in frame",
        {"frame_number": int(frame_number), "checked": ["http2.streamid", "diameter.Session-Id", "sip.Call-ID"]},
    )


def tshark_version(cfg: Config) -> str:
    r = run_checked([cfg.tshark_path, "-v"], timeout_s=cfg.default_timeout_s)
    if r.returncode != 0:
        raise PcapMcpError("TSHARK_NOT_FOUND", "tshark not available", {"stderr": r.stderr.strip()})
    first = (r.stdout.splitlines() or [""])[0].strip()
    return first


def list_fields(
    cfg: Config,
    *,
    query: str = "",
    is_regex: bool = False,
    case_sensitive: bool = False,
    limit: int = 200,
    include_protocols: bool = False,
) -> dict[str, Any]:
    q = (query or "").strip()
    if limit <= 0:
        raise PcapMcpError("INVALID_ARGUMENT", "limit must be > 0")
    if limit > 1000:
        limit = 1000

    pat: Optional[re.Pattern[str]] = None
    if q and is_regex:
        flags = 0 if case_sensitive else re.IGNORECASE
        pat = re.compile(q, flags)

    r = run_checked([cfg.tshark_path, "-G", "fields"], timeout_s=cfg.default_timeout_s)
    if r.returncode != 0:
        raise PcapMcpError("INTERNAL_ERROR", "tshark -G fields failed", {"stderr": r.stderr.strip()})

    items: list[dict[str, Any]] = []
    for line in r.stdout.splitlines():
        if not line:
            continue

        parts = line.split("\t")
        kind = (parts[0] if parts else "").strip()

        if kind not in ("F", "P"):
            continue
        if kind == "P" and not include_protocols:
            continue

        name = (parts[1] if len(parts) > 1 else "").strip()
        field = (parts[2] if len(parts) > 2 else "").strip()
        ftype = (parts[3] if len(parts) > 3 else "").strip()
        proto = (parts[4] if len(parts) > 4 else "").strip()

        hay = f"{name} {field} {proto}".strip()
        if q:
            if pat:
                if not pat.search(hay):
                    continue
            else:
                hay2 = hay if case_sensitive else hay.lower()
                q2 = q if case_sensitive else q.lower()
                if q2 not in hay2:
                    continue

        items.append({"kind": kind, "name": name, "field": field, "type": ftype, "proto": proto})
        if len(items) >= limit:
            break

    return {
        "query": q,
        "is_regex": bool(is_regex),
        "case_sensitive": bool(case_sensitive),
        "include_protocols": bool(include_protocols),
        "limit": int(limit),
        "count": len(items),
        "items": items,
    }


def capinfos_basic(cfg: Config, p: Path) -> dict:
    r = run_checked(
        [cfg.capinfos_path, "-M", "-c", "-a", "-e", "-u", "-H", str(p)],
        timeout_s=cfg.default_timeout_s,
    )
    if r.returncode != 0:
        raise PcapMcpError("INTERNAL_ERROR", "capinfos failed", {"stderr": r.stderr.strip()})

    out = {}
    for line in r.stdout.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        out[k.strip()] = v.strip()

    return {
        "pcap_path": str(p),
        "packet_count": int(out.get("Number of packets", "0") or "0"),
        "duration": float(out.get("Capture duration", "0").split()[0] or "0"),
        "time_start": out.get("First packet time"),
        "time_end": out.get("Last packet time"),
        "sha256": out.get("SHA256"),
    }


def has_any_packet(cfg: Config, p: Path, display_filter: str) -> bool:
    frames = frames_by_filter(
        cfg,
        p=p,
        display_filter=display_filter,
        limit=1,
        offset=0,
    )
    return len(frames) > 0


@dataclass(frozen=True)
class TimelineResult:
    rows: list[dict]
    warnings: list[str]


def _extract_snippet(text: str, start: int, end: int, *, context_chars: int = 240) -> str:
    a = max(0, int(start) - int(context_chars))
    b = min(len(text), int(end) + int(context_chars))
    return text[a:b]


def timeline(
    cfg: Config,
    *,
    p: Path,
    display_filter: str,
    decode_as: Optional[list[str]] = None,
    preferences: Optional[list[str]] = None,
    fields: list[str],
    limit: int,
    offset: int,
) -> TimelineResult:
    if limit < 0 or offset < 0:
        raise PcapMcpError("INVALID_ARGUMENT", "limit/offset must be non-negative")

    if limit > cfg.max_timeline_rows:
        raise PcapMcpError(
            "INVALID_ARGUMENT",
            "limit exceeds max_timeline_rows",
            {"limit": limit, "max_timeline_rows": cfg.max_timeline_rows},
        )

    args: list[str] = [
        cfg.tshark_path,
    ]

    if decode_as:
        if len(decode_as) > 50:
            raise PcapMcpError("INVALID_ARGUMENT", "too many decode_as entries", {"max": 50})
        for d in decode_as:
            s = (d or "").strip()
            if not s:
                continue
            args += ["-d", s]

    _append_preferences(args, preferences)

    args += [
        "-r",
        str(p),
    ]

    if display_filter:
        args += ["-Y", display_filter]

    args += [
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=a",
        "-E",
        "aggregator=|",
    ]

    for f in fields:
        args += ["-e", f]

    proc = popen_lines(args)
    started = time.time()
    warnings: list[str] = []
    rows: list[dict] = []

    try:
        if not proc.stdout:
            raise PcapMcpError("INTERNAL_ERROR", "tshark produced no stdout")

        header = proc.stdout.readline()
        if not header:
            stderr = read_all_stderr(proc).strip()
            raise PcapMcpError("INTERNAL_ERROR", "tshark produced no output", {"stderr": stderr})

        header_fields = header.rstrip("\n").split("\t")
        if len(header_fields) != len(fields):
            warnings.append("header_field_count_mismatch")

        seen = 0
        for line in proc.stdout:
            if cfg.default_timeout_s and (time.time() - started) > cfg.default_timeout_s:
                raise PcapMcpError("TIMEOUT", "tshark timed out")

            line = line.rstrip("\n")
            if line == "":
                continue

            if seen < offset:
                seen += 1
                continue

            parts = line.split("\t")
            row: dict = {}

            for i, key in enumerate(fields):
                raw = parts[i] if i < len(parts) else ""
                if "|" in raw:
                    row[key] = [x for x in raw.split("|") if x != ""]
                else:
                    row[key] = raw

            rows.append(row)
            if len(rows) >= limit:
                break

        returncode = proc.poll()
        if returncode is None:
            safe_kill(proc)

        stderr = read_all_stderr(proc).strip()
        if stderr:
            if "Some fields aren't valid" in stderr:
                invalid: list[str] = []
                for ln in stderr.splitlines():
                    s = ln.strip()
                    if not s or s.lower().startswith("tshark:"):
                        continue
                    if s.startswith("Some fields"):
                        continue
                    invalid.append(s)

                suggestions: dict[str, list[dict[str, Any]]] = {}
                for f in invalid[:10]:
                    try:
                        res = list_fields(cfg, query=f, limit=10)
                        suggestions[f] = res.get("items") or []
                    except Exception:
                        suggestions[f] = []

                raise PcapMcpError(
                    "INVALID_FIELDS",
                    "invalid fields",
                    {"stderr": stderr, "fields": fields, "invalid": invalid, "suggestions": suggestions},
                )
            if "Invalid display filter" in stderr:
                raise PcapMcpError("INVALID_FILTER", "invalid display filter", {"stderr": stderr, "filter": display_filter})

        return TimelineResult(rows=rows, warnings=warnings)
    finally:
        if proc.poll() is None:
            safe_kill(proc)


def text_search(
    cfg: Config,
    *,
    p: Path,
    display_filter: str,
    query: str,
    is_regex: bool = False,
    case_sensitive: bool = False,
    layers: Optional[list[str]] = None,
    decode_as: Optional[list[str]] = None,
    preferences: Optional[list[str]] = None,
    restrict_layers: bool = True,
    limit: int = 200,
    offset: int = 0,
    max_matches: int = 50,
    max_bytes: int = 200000,
    snippet_context_chars: int = 240,
) -> dict[str, Any]:
    if not (query or "").strip():
        raise PcapMcpError("INVALID_ARGUMENT", "query is empty")

    if limit < 0 or offset < 0:
        raise PcapMcpError("INVALID_ARGUMENT", "limit/offset must be non-negative")

    effective_max_matches = int(max_matches)
    if effective_max_matches <= 0:
        raise PcapMcpError("INVALID_ARGUMENT", "max_matches must be > 0")
    if effective_max_matches > 200:
        effective_max_matches = 200

    frames = frames_by_filter(
        cfg,
        p=p,
        display_filter=display_filter or "",
        decode_as=decode_as,
        preferences=preferences,
        limit=limit,
        offset=offset,
    )

    q = str(query)
    q_norm = q if case_sensitive else q.lower()

    pat: Optional[re.Pattern[str]] = None
    if is_regex:
        flags = 0 if case_sensitive else re.IGNORECASE
        pat = re.compile(q, flags)

    matches: list[dict[str, Any]] = []
    for n in frames:
        text, truncated = frame_detail(
            cfg,
            p=p,
            frame_number=int(n),
            layers=layers,
            restrict_layers=bool(restrict_layers),
            decode_as=decode_as,
            preferences=preferences,
            max_bytes=max_bytes,
        )

        hit = False
        snippet = ""
        if pat:
            m = pat.search(text)
            if m:
                hit = True
                snippet = _extract_snippet(text, m.start(), m.end(), context_chars=int(snippet_context_chars))
        else:
            hay = text if case_sensitive else text.lower()
            pos = hay.find(q_norm)
            if pos >= 0:
                hit = True
                snippet = _extract_snippet(text, pos, pos + len(q_norm), context_chars=int(snippet_context_chars))

        if hit:
            matches.append(
                {
                    "frame_number": int(n),
                    "truncated": bool(truncated),
                    "snippet": snippet,
                }
            )
            if len(matches) >= effective_max_matches:
                break

    return {
        "display_filter": display_filter or "",
        "query": query,
        "is_regex": bool(is_regex),
        "case_sensitive": bool(case_sensitive),
        "layers": layers or [],
        "restrict_layers": bool(restrict_layers),
        "limit": int(limit),
        "offset": int(offset),
        "frames_scanned": len(frames),
        "matches": matches,
    }


def frames_by_filter(
    cfg: Config,
    *,
    p: Path,
    display_filter: str,
    decode_as: Optional[list[str]] = None,
    preferences: Optional[list[str]] = None,
    limit: int,
    offset: int,
) -> list[int]:
    if limit < 0 or offset < 0:
        raise PcapMcpError("INVALID_ARGUMENT", "limit/offset must be non-negative")

    if limit > cfg.max_timeline_rows:
        raise PcapMcpError(
            "INVALID_ARGUMENT",
            "limit exceeds max_timeline_rows",
            {"limit": limit, "max_timeline_rows": cfg.max_timeline_rows},
        )

    args: list[str] = [
        cfg.tshark_path,
    ]

    if decode_as:
        if len(decode_as) > 50:
            raise PcapMcpError("INVALID_ARGUMENT", "too many decode_as entries", {"max": 50})
        for d in decode_as:
            s = (d or "").strip()
            if not s:
                continue
            args += ["-d", s]

    _append_preferences(args, preferences)

    args += [
        "-r",
        str(p),
    ]

    if display_filter:
        args += ["-Y", display_filter]

    args += ["-T", "fields", "-e", "frame.number"]

    proc = popen_lines(args)
    started = time.time()

    frames: list[int] = []
    seen = 0

    try:
        if not proc.stdout:
            raise PcapMcpError("INTERNAL_ERROR", "tshark produced no stdout")

        for line in proc.stdout:
            if cfg.default_timeout_s and (time.time() - started) > cfg.default_timeout_s:
                raise PcapMcpError("TIMEOUT", "tshark timed out")

            s = line.strip()
            if not s:
                continue

            if seen < offset:
                seen += 1
                continue

            try:
                frames.append(int(s))
            except ValueError:
                continue

            if len(frames) >= limit:
                break

        if proc.poll() is None:
            safe_kill(proc)

        stderr = read_all_stderr(proc).strip()
        if stderr:
            if "Invalid display filter" in stderr:
                raise PcapMcpError("INVALID_FILTER", "invalid display filter", {"stderr": stderr, "filter": display_filter})

        return frames
    finally:
        if proc.poll() is None:
            safe_kill(proc)


_LAYER_TO_PROTO = {
    "ngap": "ngap",
    "nas_5gs": "nas-5gs",
    "nas-5gs": "nas-5gs",
    "s1ap": "s1ap",
    "sctp": "sctp",
    "ip": "ip",
    "ipv6": "ipv6",
    "tcp": "tcp",
    "udp": "udp",
    "http": "http",
    "http2": "http2",
    "gtp": "gtp",
    "gtpv2": "gtpv2",
    "pfcp": "pfcp",
    "diameter": "diameter",
    "sip": "sip",
}


def frame_detail(
    cfg: Config,
    *,
    p: Path,
    frame_number: int,
    layers: Optional[list[str]],
    restrict_layers: bool = True,
    verbosity: str = "summary",
    decode_as: Optional[list[str]] = None,
    preferences: Optional[list[str]] = None,
    max_bytes: int,
) -> tuple[str, bool]:
    if max_bytes <= 0:
        raise PcapMcpError("INVALID_ARGUMENT", "max_bytes must be > 0")

    if verbosity not in ("summary", "full"):
        raise PcapMcpError("INVALID_ARGUMENT", "verbosity must be summary|full")

    protos: list[str] = []
    if layers:
        for l in layers:
            key = (l or "").strip()
            if not key:
                continue
            proto = _LAYER_TO_PROTO.get(key)
            if proto and proto not in protos:
                protos.append(proto)

    args: list[str] = [
        cfg.tshark_path,
    ]

    if decode_as:
        if len(decode_as) > 50:
            raise PcapMcpError("INVALID_ARGUMENT", "too many decode_as entries", {"max": 50})
        for d in decode_as:
            s = (d or "").strip()
            if not s:
                continue
            args += ["-d", s]

    _append_preferences(args, preferences)

    args += [
        "-r",
        str(p),
        "-Y",
        f"frame.number=={frame_number}",
        "-V",
    ]

    if verbosity == "full":
        args += ["-x"]

    if protos and restrict_layers:
        args += ["-O", ",".join(protos)]

    r = run_checked(args, timeout_s=cfg.default_timeout_s)
    if r.returncode != 0 and r.stdout.strip() == "":
        raise PcapMcpError("INTERNAL_ERROR", "tshark frame detail failed", {"stderr": r.stderr.strip()})

    text = r.stdout
    truncated = False
    if len(text.encode("utf-8", errors="replace")) > max_bytes:
        truncated = True
        text = text.encode("utf-8", errors="replace")[:max_bytes].decode("utf-8", errors="replace")

    return text, truncated


def packet_list_export(
    cfg: Config,
    *,
    p: Path,
    display_filter: str,
    decode_as: Optional[list[str]] = None,
    preferences: Optional[list[str]] = None,
    output_path: Path,
    extra_columns: Optional[list[tuple[str, str]]] = None,
    include_default_columns: bool = True,
) -> dict[str, Any]:
    columns: list[tuple[str, str]] = []
    if include_default_columns:
        columns += [
            ("No", "frame.number"),
            ("Time", "frame.time_epoch"),
            ("Source", "_ws.col.Source"),
            ("Destination", "_ws.col.Destination"),
            ("Protocol", "_ws.col.Protocol"),
            ("Length", "frame.len"),
            ("Info", "_ws.col.Info"),
            ("IMSI", "e212.imsi"),
            ("SUCI", "nas_5gs.mm.suci.scheme_output"),
            ("SUCI_NAI", "nas_5gs.mm.suci.nai"),
            ("RAN_UE_NGAP_ID", "ngap.RAN_UE_NGAP_ID"),
            ("AMF_UE_NGAP_ID", "ngap.AMF_UE_NGAP_ID"),
            ("NAS_PDU_SESSION_ID", "nas_5gs.pdu_session_id"),
            ("NGAP_PDU_SESSION_ID", "ngap.pDUSessionID"),
            ("DIAMETER_CMD_CODE", "diameter.cmd.code"),
            ("DIAMETER_APP_ID", "diameter.applicationId"),
            ("DIAMETER_SESSION_ID", "diameter.Session-Id"),
            ("DIAMETER_RESULT_CODE", "diameter.Result-Code"),
            ("DIAMETER_ORIGIN_HOST", "diameter.Origin-Host"),
            ("DIAMETER_DEST_HOST", "diameter.Destination-Host"),
            ("DIAMETER_CC_REQUEST_TYPE", "diameter.CC-Request-Type"),
            ("DIAMETER_SUBSCRIPTION_ID_DATA", "diameter.Subscription-Id-Data"),
            ("DIAMETER_FLOW_DESCRIPTION", "diameter.Flow-Description"),
            ("PFCP_SEID", "pfcp.seid"),
            ("PFCP_FSEID_IPV4", "pfcp.f_seid.ipv4"),
            ("GTP_TEID", "gtp.teid"),
            ("GTPV2_TEID", "gtpv2.teid"),
            ("HTTP2_METHOD", "http2.headers.method"),
            ("HTTP2_PATH", "http2.headers.path"),
            ("HTTP2_STATUS", "http2.headers.status"),
            ("HTTP2_STREAMID", "http2.streamid"),
            ("HTTP2_TYPE", "http2.type"),
            ("HTTP2_FLAGS", "http2.flags"),
            ("SCTP_SPORT", "sctp.srcport"),
            ("SCTP_DPORT", "sctp.dstport"),
            ("TCP_SPORT", "tcp.srcport"),
            ("TCP_DPORT", "tcp.dstport"),
            ("UDP_SPORT", "udp.srcport"),
            ("UDP_DPORT", "udp.dstport"),
            ("IP_SRC", "ip.src"),
            ("IP_DST", "ip.dst"),
            ("IPV6_SRC", "ipv6.src"),
            ("IPV6_DST", "ipv6.dst"),
        ]

    if extra_columns:
        seen_names = {name for name, _f in columns if name}
        for name, field in extra_columns:
            n = (name or "").strip()
            f = (field or "").strip()
            if not n or not f:
                continue
            if n in seen_names:
                continue
            seen_names.add(n)
            columns.append((n, f))

    if not columns:
        raise PcapMcpError("INVALID_ARGUMENT", "no columns selected")

    args: list[str] = [
        cfg.tshark_path,
    ]

    if decode_as:
        if len(decode_as) > 50:
            raise PcapMcpError("INVALID_ARGUMENT", "too many decode_as entries", {"max": 50})
        for d in decode_as:
            s = (d or "").strip()
            if not s:
                continue
            args += ["-d", s]

    _append_preferences(args, preferences)

    args += [
        "-r",
        str(p),
    ]

    if display_filter:
        args += ["-Y", display_filter]

    args += [
        "-T",
        "fields",
        "-E",
        "header=n",
        "-E",
        "separator=\t",
        "-E",
        "quote=d",
        "-E",
        "occurrence=a",
        "-E",
        "aggregator=|",
    ]

    for _name, field in columns:
        args += ["-e", field]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    proc = popen_lines(args)
    started = time.time()
    warnings: list[str] = []
    rows_written = 0

    try:
        if not proc.stdout:
            raise PcapMcpError("INTERNAL_ERROR", "tshark produced no stdout")

        header = "\t".join(name for name, _field in columns) + "\n"
        time_delta = timedelta(hours=int(cfg.time_offset_hours or 0))
        with output_path.open("w", encoding="utf-8", errors="replace") as f:
            writer = csv.writer(
                f,
                delimiter="\t",
                quotechar='"',
                quoting=csv.QUOTE_ALL,
                lineterminator="\n",
            )
            f.write(header)
            for line in proc.stdout:
                if cfg.export_timeout_s and (time.time() - started) > cfg.export_timeout_s:
                    raise PcapMcpError("TIMEOUT", "tshark export timed out")

                if line == "":
                    continue

                line = line.rstrip("\n")
                if line == "":
                    continue

                try:
                    parts = next(csv.reader([line], delimiter="\t", quotechar='"'))
                except Exception:
                    parts = line.split("\t")

                expected_len = len(columns)
                if len(parts) < expected_len:
                    parts += [""] * (expected_len - len(parts))

                epoch_raw = (parts[1] or "").strip()
                if epoch_raw:
                    try:
                        dt = datetime.fromtimestamp(float(epoch_raw)) + time_delta
                        parts[1] = dt.strftime("%Y-%m-%d %H:%M:%S.%f")
                    except Exception:
                        parts[1] = epoch_raw

                writer.writerow(parts)
                rows_written += 1

        returncode = proc.poll()
        if returncode is None:
            safe_kill(proc)

        stderr = read_all_stderr(proc).strip()
        if stderr:
            if "Invalid display filter" in stderr:
                raise PcapMcpError(
                    "INVALID_FILTER",
                    "invalid display filter",
                    {"stderr": stderr, "filter": display_filter},
                )

        return {
            "output_path": str(output_path),
            "rows_written": rows_written,
            "warnings": warnings,
        }
    finally:
        if proc.poll() is None:
            safe_kill(proc)
