from __future__ import annotations

import json
import struct
from pathlib import Path

from safewights.models import Finding, Severity

SAFETENSORS_MAX_HEADER = 100_000_000  # bytes; guardrail against header bombs


def scan_safetensors(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        with path.open("rb") as f:
            header_len_raw = f.read(8)
            if len(header_len_raw) < 8:
                return [
                    Finding(
                        severity=Severity.HIGH,
                        category="safetensors.parse",
                        message="Truncated safetensors file",
                        file_path=str(path),
                    )
                ]
            header_len = struct.unpack("<Q", header_len_raw)[0]
            if header_len == 0 or header_len > SAFETENSORS_MAX_HEADER:
                findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        category="safetensors.header",
                        message=f"Suspicious safetensors header length: {header_len}",
                        file_path=str(path),
                    )
                )
                return findings
            header_bytes = f.read(header_len)
            if len(header_bytes) < header_len:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        category="safetensors.parse",
                        message="Header shorter than declared length",
                        file_path=str(path),
                    )
                )
                return findings
            try:
                header = json.loads(header_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        category="safetensors.parse",
                        message="Invalid safetensors JSON header",
                        file_path=str(path),
                        detail=str(exc),
                    )
                )
                return findings

            if not isinstance(header, dict):
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        category="safetensors.parse",
                        message="Safetensors header is not an object",
                        file_path=str(path),
                    )
                )
                return findings

            meta = header.get("__metadata__")
            if isinstance(meta, dict):
                for k, v in meta.items():
                    text = f"{k}={v}".lower()
                    if any(x in text for x in ("eval(", "exec(", "__import__", "subprocess", "os.system")):
                        findings.append(
                            Finding(
                                severity=Severity.CRITICAL,
                                category="safetensors.metadata",
                                message=f"Suspicious metadata entry: {k}",
                                file_path=str(path),
                                detail=str(v)[:500],
                            )
                        )

            file_size = path.stat().st_size
            data_start = 8 + header_len
            for tensor_name, info in header.items():
                if tensor_name == "__metadata__":
                    continue
                if not isinstance(info, dict):
                    findings.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            category="safetensors.tensor",
                            message=f"Malformed tensor entry: {tensor_name}",
                            file_path=str(path),
                        )
                    )
                    continue
                offsets = info.get("data_offsets")
                if not isinstance(offsets, list) or len(offsets) != 2:
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            category="safetensors.tensor",
                            message=f"Bad data_offsets for {tensor_name}",
                            file_path=str(path),
                        )
                    )
                    continue
                start, end = offsets
                if not (isinstance(start, int) and isinstance(end, int)) or start < 0 or end < start:
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            category="safetensors.tensor",
                            message=f"Invalid offset range for {tensor_name}",
                            file_path=str(path),
                        )
                    )
                    continue
                absolute_end = data_start + end
                if absolute_end > file_size:
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            category="safetensors.tensor",
                            message=f"Tensor {tensor_name} offsets exceed file size",
                            file_path=str(path),
                            detail=f"absolute_end={absolute_end} file_size={file_size}",
                        )
                    )

            findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="safetensors.format",
                    message="Valid safetensors container structure",
                    file_path=str(path),
                    detail=f"tensors={len([k for k in header if k != '__metadata__'])}",
                )
            )
    except OSError as exc:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                category="safetensors.io",
                message="Could not read safetensors file",
                file_path=str(path),
                detail=str(exc),
            )
        )
    return findings
