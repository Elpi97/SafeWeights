from __future__ import annotations

from pathlib import Path

from safewights.models import Finding, Severity

# ONNX Model proto often begins with field tags; also check for embedded custom ops strings.
SUSPICIOUS_ONNX_STRINGS = (
    b"PythonOp",
    b"PyFunc",
    b"ATen",
    b"/bin/sh",
    b"powershell",
    b"cmd.exe",
    b"subprocess",
    b"os.system",
    b"eval(",
    b"exec(",
)


def scan_onnx(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        data = path.read_bytes()
        size = len(data)
        if size < 16:
            return [
                Finding(
                    severity=Severity.HIGH,
                    category="onnx.parse",
                    message="ONNX file too small to be valid",
                    file_path=str(path),
                )
            ]

        # Heuristic: protobuf messages usually start with a field tag byte in a reasonable range
        first = data[0]
        if first not in range(0x08, 0x80) and not data.startswith(b"\x08"):
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    category="onnx.magic",
                    message="ONNX file does not look like a protobuf model header",
                    file_path=str(path),
                    detail=f"first_byte=0x{first:02x}",
                )
            )

        # Sample up to 8 MiB for string markers to avoid huge RAM on multi-GB external-data refs
        sample = data[: min(size, 8 * 1024 * 1024)]
        for marker in SUSPICIOUS_ONNX_STRINGS:
            if marker in sample:
                sev = Severity.CRITICAL if marker in (b"/bin/sh", b"powershell", b"cmd.exe", b"os.system") else Severity.HIGH
                findings.append(
                    Finding(
                        severity=sev,
                        category="onnx.content",
                        message=f"Suspicious embedded marker in ONNX: {marker.decode('latin-1')}",
                        file_path=str(path),
                    )
                )

        if b"onnx" not in sample.lower() and b"ONNX" not in sample:
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    category="onnx.content",
                    message="No obvious ONNX domain string in first 8 MiB (may still be valid)",
                    file_path=str(path),
                )
            )

        if not any(f.severity.rank >= Severity.HIGH.rank for f in findings):
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="onnx.format",
                    message="ONNX static string scan completed",
                    file_path=str(path),
                    detail=f"size_bytes={size}",
                )
            )
    except OSError as exc:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                category="onnx.io",
                message="Could not read ONNX file",
                file_path=str(path),
                detail=str(exc),
            )
        )
    return findings
