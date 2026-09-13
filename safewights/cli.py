from __future__ import annotations

import argparse
import sys
from pathlib import Path

from safewights.report import write_markdown_report
from safewights.scanner.engine import scan_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SafeWeights — static local model scanner")
    parser.add_argument("--path", "-p", required=True, help="Model file or folder to scan")
    parser.add_argument("--model-id", default="", help="Hugging Face model id for the report")
    parser.add_argument("--out", "-o", default="", help="Markdown report output path")
    parser.add_argument("--analyst", default="", help="Analyst name")
    parser.add_argument("--gui", action="store_true", help="Launch GUI instead of CLI")
    args = parser.parse_args(argv)

    if args.gui:
        from safewights.gui import run_app

        run_app()
        return 0

    report = scan_path(Path(args.path), model_id=args.model_id)
    out = Path(args.out) if args.out else Path(f"SafeWeights_report_{report.verdict}.md")
    write_markdown_report(report, out, analyst=args.analyst)
    print(f"Verdict: {report.verdict}")
    print(f"Report: {out}")
    return 0 if report.verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
