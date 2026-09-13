from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }[self]


@dataclass(frozen=True)
class Finding:
    severity: Severity
    category: str
    message: str
    file_path: str
    detail: str = ""


@dataclass
class FileScanResult:
    path: Path
    format_detected: str
    findings: list[Finding] = field(default_factory=list)
    skipped_reason: str | None = None

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: f.severity.rank).severity


@dataclass
class ScanReport:
    root: Path
    model_id: str
    files: list[FileScanResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def all_findings(self) -> list[Finding]:
        out: list[Finding] = []
        for fr in self.files:
            out.extend(fr.findings)
        return out

    @property
    def verdict(self) -> str:
        """PASS only when there are no CRITICAL/HIGH findings."""
        for f in self.all_findings:
            if f.severity in (Severity.CRITICAL, Severity.HIGH):
                return "FAIL"
        if self.errors:
            return "FAIL"
        return "PASS"

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.all_findings:
            counts[f.severity.value] += 1
        return counts
