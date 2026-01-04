from __future__ import annotations

from pathlib import Path

from .config import Config
from .errors import PcapMcpError


def _is_relative_to(path: Path, base: Path) -> bool:
    try:
        return path.is_relative_to(base)
    except AttributeError:
        try:
            path.relative_to(base)
            return True
        except Exception:
            return False


def validate_pcap_path(cfg: Config, pcap_path: str) -> Path:
    raw = Path(pcap_path).expanduser()
    allow_any_abs = bool(cfg.allow_any_pcap_path) and raw.is_absolute()
    candidates: list[Path] = []
    if raw.is_absolute():
        candidates.append(raw.resolve())
    else:
        candidates.append(raw.resolve())
        for d in cfg.allowed_pcap_dirs:
            candidates.append((d / raw).resolve())

    matches: list[Path] = []
    for c in candidates:
        if not c.exists():
            continue
        if not c.is_file():
            continue
        if allow_any_abs and c == raw.resolve():
            matches.append(c)
            continue

        if any(_is_relative_to(c, d) for d in cfg.allowed_pcap_dirs):
            matches.append(c)

    uniq: list[Path] = []
    seen: set[str] = set()
    for m in matches:
        k = str(m)
        if k in seen:
            continue
        seen.add(k)
        uniq.append(m)

    if len(uniq) == 1:
        return uniq[0]
    if len(uniq) > 1:
        raise PcapMcpError(
            "AMBIGUOUS_PCAP_PATH",
            "multiple pcaps matched",
            {"pcap_path": pcap_path, "matches": [str(x) for x in uniq]},
        )

    p = raw.resolve()
    raise PcapMcpError(
        "FILE_NOT_FOUND",
        "pcap file not found",
        {"pcap_path": str(p), "allowed_pcap_dirs": [str(d) for d in cfg.allowed_pcap_dirs]},
    )
