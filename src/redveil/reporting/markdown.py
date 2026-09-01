from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from redveil.findings.finding import Finding
from redveil.findings.severity import Severity

_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🟢",
    Severity.INFO: "🔵",
}


def render_summary(findings: list[Finding], target_name: str) -> str:
    by_sev: dict[Severity, int] = dict.fromkeys(Severity, 0)
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    lines = [
        f"# redveil Security Assessment — {target_name}",
        "",
        f"**Generated:** {datetime.now(UTC).isoformat()}  ",
        f"**Findings:** {len(findings)}  ",
        "",
        "## Summary by severity",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        if by_sev.get(sev, 0) > 0:
            lines.append(f"| {_SEVERITY_EMOJI[sev]} {sev.value.upper()} | {by_sev[sev]} |")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    for f in findings:
        lines.append(f"- [{_SEVERITY_EMOJI[f.severity]} {f.severity.value.upper()}] **{f.title}** — {f.target.endpoint} (confidence: {f.confidence.value})")
    lines.append("")
    return "\n".join(lines)


def render_finding(f: Finding) -> str:
    lines = [
        f"# {f.id}: {f.title}",
        "",
        f"**Severity:** {f.severity.value.upper()}  ",
        f"**Confidence:** {f.confidence.value.upper()}  ",
        f"**Status:** {f.status.value.upper()}  ",
        "",
        f"**Affected endpoint:** `{f.target.method} {f.target.scheme}://{f.target.host}{f.target.endpoint}`",
    ]
    if f.parameter:
        lines.append(f"**Parameter:** `{f.parameter}`")
    if f.input_used:
        lines.append(f"**Input used:** `{f.input_used}`")
    lines.append("")

    lines += [
        "## Summary",
        "",
        f.summary,
        "",
        "## Technical explanation",
        "",
        f.technical_explanation,
        "",
    ]

    # Attack scenario — numbered list
    if f.attack_scenario:
        lines.append("## Attack scenario")
        lines.append("")
        # Split on numbered-prefix or newline; normalize to numbered list
        steps = _parse_attack_steps(f.attack_scenario)
        for i, step in enumerate(steps, 1):
            lines.append(f"{i}. {step}")
        lines.append("")

    lines += [
        "## Steps to reproduce",
        "",
    ]
    for step in f.reproduction:
        lines.append(f"{step.step}. {step.description}")
        if step.request:
            lines.append("   ```")
            lines.append(f"   {step.request}")
            lines.append("   ```")
        if step.response_excerpt:
            lines.append("   ```")
            lines.append(f"   {step.response_excerpt[:300]}")
            lines.append("   ```")
    lines.append("")

    lines += [
        "## Impact",
        "",
        f.impact,
        "",
        "## Evidence",
        "",
        f"_{len(f.evidence_ids)} evidence record(s). See `evidence/{f.id}-*.txt` in the report directory._",
        "",
        "## Remediation",
        "",
    ]
    for i, r in enumerate(f.remediation, 1):
        lines.append(f"{i}. {r}")
    lines.append("")

    # Code examples — labeled blocks (Markdown doesn't support tabs natively
    # but we render them as separate sub-sections so readers can find the
    # framework they want quickly).
    if f.code_examples:
        lines.append("## Code examples")
        lines.append("")
        for framework, snippet in f.code_examples.items():
            lines.append(f"### {framework}")
            lines.append("")
            lines.append("```")
            lines.append(snippet.rstrip())
            lines.append("```")
            lines.append("")

    if f.cwe or f.owasp:
        lines.append("## References")
        lines.append("")
        for c in f.cwe:
            lines.append(f"- {c} (https://cwe.mitre.org/data/definitions/{c.split('-')[-1]}.html)")
        for o in f.owasp:
            lines.append(f"- OWASP {o}")
        for url in f.references:
            lines.append(f"- {url}")
        lines.append("")

    lines += [
        "---",
        f"*Discovered: {f.discovered_at.isoformat() if f.discovered_at else 'n/a'}*  ",
        "*Tool: redveil v0.1.0*",
    ]
    return "\n".join(lines)


def _parse_attack_steps(text: str) -> list[str]:
    """Parse an attack_scenario string into individual steps.

    The knowledge base stores scenarios as multi-line strings with steps
    like ``"1. Step one\\n2. Step two"``. We strip the numeric prefix and
    return the textual content.
    """
    steps: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        # Strip leading "N." or "N) " prefix
        if len(s) > 2 and s[0].isdigit():
            # Find the first '. ' or ') '
            for i in range(1, min(4, len(s))):
                if s[i] in {".", ")"} and i + 1 < len(s) and s[i + 1] == " ":
                    s = s[i + 2:].strip()
                    break
        steps.append(s)
    return steps


def write_report(findings: list[Finding], target_name: str, output_dir: Path) -> dict[str, Path]:
    """Write summary.md, findings.json, findings/<id>.md, and report.html."""
    output_dir.mkdir(parents=True, exist_ok=True)
    findings_dir = output_dir / "findings"
    findings_dir.mkdir(exist_ok=True)

    written: dict[str, Path] = {}

    # summary
    summary_path = output_dir / "summary.md"
    summary_path.write_text(render_summary(findings, target_name))
    written["summary"] = summary_path

    # findings.json (delegate)
    from redveil.reporting.json_report import write_findings_json
    written["findings_json"] = write_findings_json(findings, target_name, output_dir)

    # per-finding markdown
    for f in findings:
        p = findings_dir / f"{f.id}.md"
        p.write_text(render_finding(f))
        written[f.id] = p

    # HTML report (always-on; the kind of artifact you can email)
    from redveil.reporting.html_report import write_html_report
    written["report_html"] = write_html_report(findings, target_name, output_dir)

    return written
