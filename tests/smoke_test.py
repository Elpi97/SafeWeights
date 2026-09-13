"""Minimal offline smoke test for SafeWeights scanners (no HF download)."""

from __future__ import annotations

import pickle
import struct
import tempfile
from pathlib import Path

from safewights import __version__
from safewights.report import write_markdown_report
from safewights.scanner.engine import scan_path
from safewights.scanner.pickle_scan import scan_pickle_bytes


def main() -> None:
    assert __version__ == "1.2.0", __version__

    # Safe-ish pickle (collections only)
    safe = pickle.dumps({"weights": [1, 2, 3]}, protocol=4)
    safe_findings = scan_pickle_bytes(safe, "safe.pkl")
    assert any(f.category == "pickle.format" for f in safe_findings)

    # Dangerous pickle
    class Boom:
        def __reduce__(self):
            return (eval, ("2+2",))

    dangerous = pickle.dumps(Boom(), protocol=4)
    bad_findings = scan_pickle_bytes(dangerous, "bad.pkl")
    assert any(f.severity.value in {"CRITICAL", "HIGH"} for f in bad_findings), bad_findings

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "safe.pkl").write_bytes(safe)
        # Minimal fake safetensors header
        header = b'{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
        st = struct.pack("<Q", len(header)) + header + b"\x00\x00\x00\x00"
        (root / "model.safetensors").write_bytes(st)
        (root / "model.gguf").write_bytes(b"GGUF" + struct.pack("<I", 3) + struct.pack("<QQ", 1, 0))

        report = scan_path(root, model_id="test/smoke")
        out = root / "report.md"
        write_markdown_report(report, out, analyst="smoke")
        assert out.exists()
        assert report.verdict in {"PASS", "FAIL"}
        text = out.read_text(encoding="utf-8")
        assert "Do this next" in text
        assert "Details for specialists" in text
        assert "Analyst sign-off" in text
        assert "PASS" in text or "FAIL" in text
        assert "Risk level" in text
        print("SMOKE OK", report.verdict, "files=", len(report.files), "version=", __version__)


if __name__ == "__main__":
    main()
