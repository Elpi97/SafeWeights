from __future__ import annotations

import io
import pickletools
import zipfile
from pathlib import Path

from safewights.config import (
    ALLOWLISTED_PICKLE_IMPORTS,
    DANGEROUS_PICKLE_IMPORTS,
    SENSITIVE_MODULE_PREFIXES,
)
from safewights.models import Finding, Severity


def _severity_for_import(module: str, attr: str | None) -> Severity | None:
    full = f"{module}.{attr}" if attr else module
    if full in ALLOWLISTED_PICKLE_IMPORTS:
        return None
    for allowed in ALLOWLISTED_PICKLE_IMPORTS:
        if full.startswith(allowed + "."):
            return None

    if full in DANGEROUS_PICKLE_IMPORTS:
        return Severity(DANGEROUS_PICKLE_IMPORTS[full])
    if module in DANGEROUS_PICKLE_IMPORTS:
        return Severity(DANGEROUS_PICKLE_IMPORTS[module])
    for key, sev in DANGEROUS_PICKLE_IMPORTS.items():
        if full.startswith(key + ".") or module == key or module.startswith(key + "."):
            return Severity(sev)

    for prefix in SENSITIVE_MODULE_PREFIXES:
        if module == prefix or module.startswith(prefix + "."):
            return Severity.MEDIUM
    return Severity.LOW  # any non-allowlisted GLOBAL is at least noted


def _stack_global_name(stack: list[str]) -> tuple[str, str] | None:
    if len(stack) < 2:
        return None
    attr = stack.pop()
    module = stack.pop()
    return module, attr


def scan_pickle_bytes(data: bytes, file_path: str) -> list[Finding]:
    findings: list[Finding] = []
    stack: list[str] = []
    seen: set[str] = set()

    try:
        for opcode, arg, pos in pickletools.genops(io.BytesIO(data)):
            name = opcode.name
            if name in ("SHORT_BINSTRING", "BINSTRING", "BINUNICODE", "SHORT_BINUNICODE", "UNICODE", "STRING"):
                if isinstance(arg, str):
                    stack.append(arg)
                continue

            if name == "GLOBAL":
                # arg is "module attr" or "module\nattr" depending on version; pickletools gives "module attr"
                if not isinstance(arg, str):
                    continue
                parts = arg.replace("\n", " ").split()
                if len(parts) >= 2:
                    module, attr = parts[0], parts[1]
                elif len(parts) == 1:
                    module, attr = parts[0], ""
                else:
                    continue
                key = f"{module}.{attr}" if attr else module
                if key in seen:
                    continue
                seen.add(key)
                sev = _severity_for_import(module, attr or None)
                if sev is None:
                    continue
                findings.append(
                    Finding(
                        severity=sev,
                        category="pickle.import",
                        message=f"Pickle imports {key}",
                        file_path=file_path,
                        detail=f"opcode=GLOBAL pos={pos}",
                    )
                )
            elif name == "STACK_GLOBAL":
                resolved = _stack_global_name(stack)
                if not resolved:
                    continue
                module, attr = resolved
                key = f"{module}.{attr}"
                if key in seen:
                    continue
                seen.add(key)
                sev = _severity_for_import(module, attr)
                if sev is None:
                    continue
                findings.append(
                    Finding(
                        severity=sev,
                        category="pickle.import",
                        message=f"Pickle STACK_GLOBAL imports {key}",
                        file_path=file_path,
                        detail=f"opcode=STACK_GLOBAL pos={pos}",
                    )
                )
            elif name in ("REDUCE", "BUILD", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX"):
                # Presence of REDUCE with prior dangerous GLOBAL already flagged;
                # note REDUCE itself at INFO when dangerous imports exist.
                pass
            elif name == "EXT1" or name == "EXT2" or name == "EXT4":
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        category="pickle.ext",
                        message="Pickle uses extension registry opcode",
                        file_path=file_path,
                        detail=f"opcode={name} arg={arg!r} pos={pos}",
                    )
                )
    except Exception as exc:  # noqa: BLE001 — corrupt pickle must not crash scanner
        findings.append(
            Finding(
                severity=Severity.HIGH,
                category="pickle.parse",
                message="Failed to statically parse pickle stream",
                file_path=file_path,
                detail=str(exc),
            )
        )

    if not findings:
        # Parsed cleanly with only allowlisted / no imports — still note format risk
        findings.append(
            Finding(
                severity=Severity.INFO,
                category="pickle.format",
                message="Pickle/PyTorch serialized content detected (inherently executable on load)",
                file_path=file_path,
                detail="Prefer safetensors when available for Lambda deployment",
            )
        )
    return findings


def looks_like_pickle(data: bytes) -> bool:
    if not data:
        return False
    # Protocol 2+
    if data[0:1] == b"\x80" and len(data) > 1 and data[1] in range(0, 6):
        return True
    # Protocol 0 ASCII markers
    if data.startswith(b"(") or data.startswith(b"c") or data.startswith(b"]"):
        return True
    return False


def scan_zip_for_pickles(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        with zipfile.ZipFile(path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                # Zip slip / suspicious names
                name = info.filename.replace("\\", "/")
                if name.startswith("/") or ".." in name.split("/"):
                    findings.append(
                        Finding(
                            severity=Severity.CRITICAL,
                            category="archive.path",
                            message=f"Suspicious archive member path: {info.filename}",
                            file_path=str(path),
                        )
                    )
                lower = name.lower()
                if lower.endswith((".pkl", ".pickle", ".dat")) or "data.pkl" in lower or lower.endswith(
                    "/data.pkl"
                ):
                    raw = zf.read(info)
                    findings.extend(scan_pickle_bytes(raw, f"{path}!{info.filename}"))
                elif looks_like_pickle(zf.read(info)[:16]) and info.file_size < 50_000_000:
                    raw = zf.read(info)
                    if looks_like_pickle(raw[:8]):
                        findings.extend(scan_pickle_bytes(raw, f"{path}!{info.filename}"))
    except zipfile.BadZipFile:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                category="archive.parse",
                message="File claimed zip-like extension but is not a valid zip",
                file_path=str(path),
            )
        )
    except Exception as exc:  # noqa: BLE001
        findings.append(
            Finding(
                severity=Severity.HIGH,
                category="archive.parse",
                message="Error reading archive",
                file_path=str(path),
                detail=str(exc),
            )
        )
    return findings


def scan_pickle_file(path: Path) -> list[Finding]:
    data = path.read_bytes()
    if zipfile.is_zipfile(path):
        return scan_zip_for_pickles(path)
    if looks_like_pickle(data):
        return scan_pickle_bytes(data, str(path))
    # Torch .bin sometimes raw pickle without clear header in first bytes
    try:
        return scan_pickle_bytes(data, str(path))
    except Exception:  # noqa: BLE001
        return [
            Finding(
                severity=Severity.MEDIUM,
                category="pickle.unknown",
                message="Could not confirm pickle structure",
                file_path=str(path),
            )
        ]
