from __future__ import annotations

from dataclasses import dataclass
import subprocess
from typing import Iterable, Optional


@dataclass(frozen=True)
class ProcResult:
    returncode: int
    stdout: str
    stderr: str


def run_checked(
    args: list[str],
    *,
    timeout_s: Optional[float],
) -> ProcResult:
    cp = subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout_s,
        check=False,
    )
    return ProcResult(cp.returncode, cp.stdout, cp.stderr)


def popen_lines(
    args: list[str],
) -> subprocess.Popen[str]:
    return subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )


def safe_kill(p: subprocess.Popen[str]) -> None:
    try:
        p.kill()
    except Exception:
        return


def read_all_stderr(p: subprocess.Popen[str]) -> str:
    if not p.stderr:
        return ""
    try:
        return p.stderr.read() or ""
    except Exception:
        return ""
