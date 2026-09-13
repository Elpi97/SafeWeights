from __future__ import annotations

import struct
from pathlib import Path

from safewights.models import Finding, Severity

GGUF_MAGIC = b"GGUF"


def scan_gguf(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        with path.open("rb") as f:
            magic = f.read(4)
            if magic != GGUF_MAGIC:
                return [
                    Finding(
                        severity=Severity.HIGH,
                        category="gguf.magic",
                        message="File extension is .gguf but magic is not GGUF",
                        file_path=str(path),
                        detail=f"magic={magic!r}",
                    )
                ]
            version_raw = f.read(4)
            if len(version_raw) < 4:
                return [
                    Finding(
                        severity=Severity.HIGH,
                        category="gguf.parse",
                        message="Truncated GGUF header",
                        file_path=str(path),
                    )
                ]
            version = struct.unpack("<I", version_raw)[0]
            if version not in (1, 2, 3):
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        category="gguf.version",
                        message=f"Unrecognized GGUF version: {version}",
                        file_path=str(path),
                    )
                )
            counts = f.read(16)
            if len(counts) == 16:
                tensor_count, kv_count = struct.unpack("<QQ", counts)
                if tensor_count > 10_000_000 or kv_count > 10_000_000:
                    findings.append(
                        Finding(
                            severity=Severity.CRITICAL,
                            category="gguf.header",
                            message="Implausible GGUF tensor/metadata counts",
                            file_path=str(path),
                            detail=f"tensor_count={tensor_count} kv_count={kv_count}",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            severity=Severity.INFO,
                            category="gguf.format",
                            message="GGUF magic/version header looks valid",
                            file_path=str(path),
                            detail=f"version={version} tensors={tensor_count} kv={kv_count}",
                        )
                    )
            else:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        category="gguf.parse",
                        message="Incomplete GGUF count fields",
                        file_path=str(path),
                    )
                )
    except OSError as exc:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                category="gguf.io",
                message="Could not read GGUF file",
                file_path=str(path),
                detail=str(exc),
            )
        )
    return findings
