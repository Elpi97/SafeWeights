from __future__ import annotations

from pathlib import Path

from safewights.models import Finding, Severity

HDF5_MAGIC = b"\x89HDF\r\n\x1a\n"
SUSPICIOUS_ATTR_MARKERS = (
    "lambda",
    "exec",
    "eval",
    "__import__",
    "subprocess",
    "os.system",
    "popen",
    "ctypes",
)


def scan_h5(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        with path.open("rb") as f:
            magic = f.read(8)
        if magic != HDF5_MAGIC:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    category="h5.magic",
                    message="Not a valid HDF5/H5 container",
                    file_path=str(path),
                    detail=f"magic={magic!r}",
                )
            )
            return findings

        try:
            import h5py  # type: ignore
        except ImportError:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="h5.format",
                    message="HDF5 magic OK; install h5py for deep attribute scan",
                    file_path=str(path),
                )
            )
            return findings

        def walk(name: str, obj) -> None:  # noqa: ANN001
            try:
                attrs = dict(obj.attrs)
            except Exception:  # noqa: BLE001
                return
            for key, value in attrs.items():
                text = f"{key}={value}".lower()
                for marker in SUSPICIOUS_ATTR_MARKERS:
                    if marker in text:
                        sev = Severity.CRITICAL if marker in ("exec", "eval", "__import__", "os.system") else Severity.HIGH
                        findings.append(
                            Finding(
                                severity=sev,
                                category="h5.attribute",
                                message=f"Suspicious HDF5 attribute at {name}: {key}",
                                file_path=str(path),
                                detail=str(value)[:500],
                            )
                        )

        with h5py.File(path, "r") as h5:
            h5.visititems(walk)
            # Keras Lambda layers often live under model_weights or layer names
            def visit_lambda(name: str, obj) -> None:  # noqa: ANN001
                lower = name.lower()
                if "lambda" in lower:
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            category="h5.lambda",
                            message=f"Possible Keras Lambda layer path: {name}",
                            file_path=str(path),
                        )
                    )

            h5.visititems(visit_lambda)

        if not findings:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="h5.format",
                    message="HDF5 structure scanned; no suspicious attributes flagged",
                    file_path=str(path),
                )
            )
    except OSError as exc:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                category="h5.io",
                message="Could not read H5/HDF5 file",
                file_path=str(path),
                detail=str(exc),
            )
        )
    except Exception as exc:  # noqa: BLE001
        findings.append(
            Finding(
                severity=Severity.HIGH,
                category="h5.parse",
                message="Error during H5 scan",
                file_path=str(path),
                detail=str(exc),
            )
        )
    return findings
