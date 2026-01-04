from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class PcapMcpError(Exception):
    code: str
    message: str
    details: Optional[dict] = None

    def __str__(self) -> str:
        if self.details:
            return f"{self.code}: {self.message} ({self.details})"
        return f"{self.code}: {self.message}"
