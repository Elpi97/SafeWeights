from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from safewights import __app_name__, __version__
from safewights.models import Finding, ScanReport, Severity

# Everyday labels for non-technical readers
_SEVERITY_PLAIN = {
    Severity.CRITICAL: "Urgent — stop and review",
    Severity.HIGH: "Serious — needs review",
    Severity.MEDIUM: "Worth a look",
    Severity.LOW: "Minor note",
    Severity.INFO: "Good news / info",
}

_SEVERITY_BAR = {
    Severity.CRITICAL: "█████",
    Severity.HIGH: "████",
    Severity.MEDIUM: "███",
    Severity.LOW: "██",
    Severity.INFO: "█",
}


def _short_path(path: Path | str, root: Path | None = None) -> str:
    """Prefer basename or path relative to scan root for executive sections."""
    p = Path(path)
    try:
        if root is not None:
            return str(p.resolve().relative_to(Path(root).resolve())).replace("\\", "/")
    except Exception:  # noqa: BLE001
        pass
    return p.name or str(p)


def _plain_finding_line(finding: Finding, root: Path | None = None) -> str:
    """One-line plain-language summary of a finding."""
    cat = (finding.category or "").lower()
    msg = (finding.message or "").lower()
    detail = (finding.detail or "").lower()
    blob = f"{cat} {msg} {detail}"
    where = _short_path(finding.file_path, root)

    if finding.severity == Severity.INFO and ("safetensor" in blob or "valid" in blob):
        return f"Weights use a safer file format (safetensors) in `{where}`. Good."
    if "pickle" in blob and finding.severity in (Severity.CRITICAL, Severity.HIGH):
        return f"Dangerous code pattern found in `{where}`. Treat as unsafe until reviewed."
    if "pickle" in blob and "import" in blob:
        return f"A model file (`{where}`) embeds runnable code patterns that need specialist review."
    if finding.severity in (Severity.CRITICAL, Severity.HIGH):
        return f"Serious issue in `{where}`: {finding.message}"
    if finding.severity == Severity.INFO:
        return f"Note on `{where}`: {finding.message}"
    return f"{finding.message} (`{where}`)"


def _risk_level_phrase(verdict: str, counts: dict[str, int]) -> str:
    if verdict == "PASS":
        if counts.get("MEDIUM", 0) or counts.get("LOW", 0):
            return "No serious problems found — a few minor notes are listed below."
        return "No serious problems found."
    crit = counts.get("CRITICAL", 0)
    high = counts.get("HIGH", 0)
    if crit:
        return "Serious problems — do not deploy without cybersecurity review."
    if high:
        return "Serious problems — do not deploy without review."
    return "Problems were found — pause and review before deploying."


def _what_we_checked(report: ScanReport) -> str:
    formats = sorted({fr.format_detected for fr in report.files if fr.format_detected})
    n = len(report.files)
    if not n:
        return "We looked for common AI model weight files in the folder you selected."
    fmt = ", ".join(formats[:6]) if formats else "common model formats"
    return (
        f"We checked **{n}** file(s) for risky patterns (without running the model). "
        f"Formats seen: {fmt}."
    )


def _what_we_found(report: ScanReport, counts: dict[str, int]) -> str:
    if report.verdict == "PASS" and not any(counts[s.value] for s in Severity if s != Severity.INFO):
        info_n = counts.get("INFO", 0)
        if info_n:
            return f"Nothing dangerous stood out. {info_n} informational note(s) only."
        return "Nothing dangerous stood out in this static check."
    if report.verdict == "PASS":
        return "No urgent or serious issues. See the summary cards for smaller notes."
    parts: list[str] = []
    if counts.get("CRITICAL", 0):
        parts.append(f"{counts['CRITICAL']} urgent")
    if counts.get("HIGH", 0):
        parts.append(f"{counts['HIGH']} serious")
    joined = " and ".join(parts) if parts else "important"
    return f"We found {joined} finding(s) that need a human review before this model is trusted."


def _next_steps(verdict: str) -> list[str]:
    if verdict == "PASS":
        return [
            "**Cybersecurity / AI team:** Skim the summary cards and open Details only if something looks odd.",
            "**Analyst:** Keep this report with the scanned model folder.",
            "**Handoff:** Manually copy the model + report to the corporate shared drive for Lambda when ready.",
        ]
    return [
        "**Cybersecurity:** Review every Urgent/Serious item under Details before any deploy.",
        "**AI team:** Do not load this model in production until Cybersecurity signs off.",
        "**Handoff:** Do not transfer to Lambda until risk acceptance is documented.",
    ]


def write_markdown_report(report: ScanReport, output_path: Path, analyst: str = "") -> Path:
    output_path = output_path.expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    counts = report.counts_by_severity()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    verdict = report.verdict
    root = report.root
    model_label = report.model_id or Path(root).name or "unknown model"

    if verdict == "PASS":
        banner = "# ✅ PASS — Looks safe to proceed"
        meaning = (
            "Plain English: this static check did **not** find urgent or serious risk patterns. "
            "It does **not** run the model, so it is not a full security guarantee."
        )
    else:
        banner = "# ❌ FAIL — Needs human review"
        meaning = (
            "Plain English: we found **urgent or serious** issues (or scanner errors). "
            "Treat this model as **not ready** until Cybersecurity reviews it."
        )

    lines: list[str] = [
        banner,
        "",
        meaning,
        "",
        f"> **Risk level:** {_risk_level_phrase(verdict, counts)}",
        "",
        "---",
        "",
        "## In 30 seconds",
        "",
        f"- **What we checked:** {_what_we_checked(report)}",
        f"- **What we found:** {_what_we_found(report, counts)}",
        f"- **Model:** `{model_label}`",
        f"- **When:** {now}",
        f"- **Who scanned:** {analyst or 'not specified'}",
        f"- **Tool:** {__app_name__} v{__version__}",
        "",
        "## Do this next",
        "",
    ]
    for i, step in enumerate(_next_steps(verdict), start=1):
        lines.append(f"{i}. {step}")

    lines.extend(
        [
            "",
            "## Snapshot of findings",
            "",
            "How many issues at each level (bigger bar = more attention):",
            "",
        ]
    )
    for sev in Severity:
        n = counts.get(sev.value, 0)
        bar = _SEVERITY_BAR[sev] if n else "·"
        mark = "← look here" if n and sev in (Severity.CRITICAL, Severity.HIGH) else ""
        lines.append(
            f"- **{_SEVERITY_PLAIN[sev]}** (`{sev.value}`): {n}  `{bar}` {mark}".rstrip()
        )

    # Highlight cards — top findings in plain language
    highlights = sorted(report.all_findings, key=lambda f: -f.severity.rank)[:8]
    lines.extend(["", "## What stands out", ""])
    if not highlights and not report.errors:
        lines.append("Nothing notable — no findings were recorded.")
    else:
        for f in highlights:
            emoji = {
                Severity.CRITICAL: "🛑",
                Severity.HIGH: "⚠️",
                Severity.MEDIUM: "📎",
                Severity.LOW: "📝",
                Severity.INFO: "ℹ️",
            }.get(f.severity, "•")
            lines.append(f"- {emoji} **{_SEVERITY_PLAIN[f.severity]}** — {_plain_finding_line(f, root)}")
        for err in report.errors[:5]:
            lines.append(f"- 🛑 **Scanner problem** — {err}")

    lines.extend(
        [
            "",
            "---",
            "",
            "## Details for specialists",
            "",
            "_Technical section — skip unless you need file-level evidence._",
            "",
            f"- Scan root: `{root}`",
            f"- Files examined: {len(report.files)}",
            f"- Verdict rule: FAIL if any CRITICAL/HIGH finding or scanner error; else PASS.",
            "",
            "### Transfer note",
            "",
            "SafeWeights only scans and writes this report. Analysts copy the model and report to the corporate "
            "shared drive manually. **FAIL** means CRITICAL or HIGH findings (or scanner errors) — do not "
            "hand off to Lambda without documented risk acceptance.",
            "",
        ]
    )

    if report.errors:
        lines.extend(["### Scanner errors", ""])
        for err in report.errors:
            lines.append(f"- {err}")
        lines.append("")

    lines.extend(["### Files scanned", ""])
    for fr in report.files:
        short = _short_path(fr.path, root)
        skip = f" _(skipped: {fr.skipped_reason})_" if fr.skipped_reason else ""
        lines.append(f"#### `{short}`")
        lines.append("")
        lines.append(f"- Format: `{fr.format_detected}`{skip}")
        if not fr.findings:
            lines.append("- Findings: none")
            lines.append("")
            continue
        lines.append("")
        lines.append("| Severity | Category | Message | Detail |")
        lines.append("|---|---|---|---|")
        for f in sorted(fr.findings, key=lambda x: -x.severity.rank):
            detail = (f.detail or "").replace("|", "\\|").replace("\n", " ")
            msg = f.message.replace("|", "\\|")
            lines.append(f"| {f.severity.value} | {f.category} | {msg} | {detail} |")
        lines.append("")

    lines.extend(
        [
            "## Analyst sign-off",
            "",
            "- [ ] I reviewed this report before any handoff.",
            "- [ ] Destination: Lambda inference servers / corporate shared drive (when approved).",
            "",
            "Signature / initials: ______________  Date: ______________",
            "",
        ]
    )

    output_path.write_text("\n".join(lines), encoding="utf-8")
    return output_path
