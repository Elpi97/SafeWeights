from __future__ import annotations

import zipfile
from pathlib import Path

from safewights.config import (
    GGUF_EXTENSIONS,
    H5_EXTENSIONS,
    ONNX_EXTENSIONS,
    PICKLE_EXTENSIONS,
    SAFETENSORS_EXTENSIONS,
    SCANNABLE_EXTENSIONS,
    TORCH_EXTENSIONS,
)
from safewights.models import FileScanResult, Finding, ScanReport, Severity
from safewights.scanner.gguf_scan import scan_gguf
from safewights.scanner.h5_scan import scan_h5
from safewights.scanner.onnx_scan import scan_onnx
from safewights.scanner.pickle_scan import looks_like_pickle, scan_pickle_file
from safewights.scanner.safetensors_scan import scan_safetensors

SKIP_DIR_NAMES = {".git", ".cache", "__pycache__", ".huggingface"}


def detect_format(path: Path) -> str:
    ext = path.suffix.lower()
    if ext in SAFETENSORS_EXTENSIONS:
        return "safetensors"
    if ext in GGUF_EXTENSIONS:
        return "gguf"
    if ext in ONNX_EXTENSIONS:
        return "onnx"
    if ext in H5_EXTENSIONS:
        return "h5"
    if ext in PICKLE_EXTENSIONS:
        return "pickle"
    if ext in TORCH_EXTENSIONS:
        if zipfile.is_zipfile(path):
            return "pytorch_zip"
        return "pytorch_pickle"
    if ext == ".json" and path.name in {"config.json", "tokenizer.json", "generation_config.json"}:
        return "config_json"
    return "unknown"


def _scan_one(path: Path) -> FileScanResult:
    fmt = detect_format(path)
    findings: list[Finding] = []

    if fmt == "safetensors":
        findings = scan_safetensors(path)
    elif fmt == "gguf":
        findings = scan_gguf(path)
    elif fmt == "onnx":
        findings = scan_onnx(path)
    elif fmt == "h5":
        findings = scan_h5(path)
    elif fmt in {"pickle", "pytorch_pickle", "pytorch_zip"}:
        findings = scan_pickle_file(path)
    elif fmt == "config_json":
        findings = [
            Finding(
                severity=Severity.INFO,
                category="config",
                message="Config/tokenizer JSON noted (not executable weights)",
                file_path=str(path),
            )
        ]
    else:
        # Try magic sniff for pickle-like .bin without matching heuristic
        try:
            head = path.read_bytes()[:64]
            if looks_like_pickle(head) or zipfile.is_zipfile(path):
                findings = scan_pickle_file(path)
                fmt = "pytorch_pickle"
            else:
                return FileScanResult(path=path, format_detected=fmt, skipped_reason="unsupported or non-model file")
        except OSError as exc:
            return FileScanResult(
                path=path,
                format_detected=fmt,
                findings=[
                    Finding(
                        severity=Severity.MEDIUM,
                        category="io",
                        message="Could not read file",
                        file_path=str(path),
                        detail=str(exc),
                    )
                ],
            )

    return FileScanResult(path=path, format_detected=fmt, findings=findings)


def iter_model_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    files: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIR_NAMES for part in p.parts):
            continue
        ext = p.suffix.lower()
        if ext in SCANNABLE_EXTENSIONS or p.name in {
            "config.json",
            "tokenizer.json",
            "generation_config.json",
            "model.safetensors.index.json",
        }:
            files.append(p)
    return sorted(files)


def scan_path(root: Path, model_id: str = "") -> ScanReport:
    root = root.resolve()
    report = ScanReport(root=root, model_id=model_id or root.name)
    if not root.exists():
        report.errors.append(f"Path does not exist: {root}")
        return report

    targets = iter_model_files(root)
    if not targets:
        report.errors.append("No scannable model files found in the selected path.")
        return report

    for path in targets:
        try:
            report.files.append(_scan_one(path))
        except Exception as exc:  # noqa: BLE001
            report.errors.append(f"{path}: {exc}")
            report.files.append(
                FileScanResult(
                    path=path,
                    format_detected="error",
                    findings=[
                        Finding(
                            severity=Severity.HIGH,
                            category="scanner",
                            message="Unhandled scanner exception",
                            file_path=str(path),
                            detail=str(exc),
                        )
                    ],
                )
            )

    report.metadata["file_count"] = len(report.files)
    report.metadata["verdict"] = report.verdict
    return report
