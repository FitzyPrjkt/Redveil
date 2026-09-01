"""HTML report renderer for redveil.

Produces a single self-contained HTML file with embedded CSS. No external
resources, no CDN. Designed to be:
- Easy to email or attach to a bug bounty report (one file, no images)
- Print-friendly (CSS @media print rules hide chrome)
- Readable in light and dark mode (prefers-color-scheme)

The report uses a card-per-finding layout with collapsible sections for
attack scenario, code examples, and references.
"""
from __future__ import annotations

import html
from datetime import UTC, datetime
from pathlib import Path

from redveil.findings.finding import Finding
from redveil.findings.severity import Severity

_SEVERITY_COLORS = {
    Severity.CRITICAL: "#b91c1c",
    Severity.HIGH: "#ea580c",
    Severity.MEDIUM: "#ca8a04",
    Severity.LOW: "#16a34a",
    Severity.INFO: "#2563eb",
}

_SEVERITY_LABEL = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Info",
}


def _esc(text: str | None) -> str:
    if text is None:
        return ""
    return html.escape(str(text))


def _summary_section(findings: list[Finding]) -> str:
    """Severity badge summary at the top of the report."""
    by_sev: dict[Severity, int] = dict.fromkeys(Severity, 0)
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    parts = ['<section class="summary">']
    parts.append('<h2>Summary</h2>')
    parts.append('<div class="badges">')
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        count = by_sev.get(sev, 0)
        if count == 0:
            continue
        color = _SEVERITY_COLORS[sev]
        parts.append(
            f'<div class="badge" style="background:{color};">'
            f'<span class="badge-count">{count}</span>'
            f'<span class="badge-label">{_SEVERITY_LABEL[sev]}</span>'
            f'</div>'
        )
    parts.append('</div>')
    parts.append('</section>')
    return "\n".join(parts)


def _finding_card(f: Finding) -> str:
    color = _SEVERITY_COLORS.get(f.severity, "#6b7280")
    sev = _SEVERITY_LABEL[f.severity]
    fid = _esc(f.id)

    parts = [
        f'<article class="finding" id="finding-{fid}">',
        '<header>',
        '<div class="finding-title">',
        f'<span class="sev-badge" style="background:{color};">{_esc(sev)}</span>',
        f'<h3>{_esc(f.title)}</h3>',
        '</div>',
        '<div class="finding-meta">',
        f'<span class="meta-item"><strong>ID:</strong> <code>{fid}</code></span>',
        f'<span class="meta-item"><strong>Status:</strong> {_esc(f.status.value.upper())}</span>',
        f'<span class="meta-item"><strong>Confidence:</strong> {_esc(f.confidence.value.upper())}</span>',
        '</div>',
        '<div class="finding-target">',
        f'<strong>Target:</strong> <code>{_esc(f.target.method)} {_esc(f.target.scheme)}://{_esc(f.target.host)}{_esc(f.target.endpoint)}</code>',
    ]
    if f.parameter:
        parts.append(f'<br><strong>Parameter:</strong> <code>{_esc(f.parameter)}</code>')
    if f.input_used:
        parts.append(f'<br><strong>Input used:</strong> <code>{_esc(f.input_used)}</code>')
    parts.append('</div>')
    parts.append('</header>')

    parts.append('<div class="finding-body">')

    # Summary
    parts.append('<section>')
    parts.append('<h4>Summary</h4>')
    parts.append(f'<p>{_esc(f.summary)}</p>')
    parts.append('</section>')

    # Technical
    parts.append('<section>')
    parts.append('<h4>Technical explanation</h4>')
    parts.append(f'<p>{_esc(f.technical_explanation)}</p>')
    parts.append('</section>')

    # Attack scenario (collapsible)
    if f.attack_scenario:
        steps = _parse_attack_steps(f.attack_scenario)
        parts.append('<details class="attack-scenario" open>')
        parts.append('<summary><h4 style="display:inline;">Attack scenario</h4></summary>')
        parts.append('<ol class="attack-steps">')
        for step in steps:
            parts.append(f'<li>{_esc(step)}</li>')
        parts.append('</ol>')
        parts.append('</details>')

    # Impact
    parts.append('<section>')
    parts.append('<h4>Impact</h4>')
    parts.append(f'<p>{_esc(f.impact)}</p>')
    parts.append('</section>')

    # Evidence
    parts.append('<section>')
    parts.append('<h4>Evidence</h4>')
    parts.append(
        f'<p><em>{len(f.evidence_ids)} evidence record(s). See '
        f'<code>evidence/{fid}-*.txt</code> in the report directory.</em></p>'
    )
    parts.append('</section>')

    # Reproduction
    if f.reproduction:
        parts.append('<section>')
        parts.append('<h4>Steps to reproduce</h4>')
        parts.append('<ol class="reproduction">')
        for step in f.reproduction:
            parts.append(f'<li>{_esc(step.description)}')
            if step.request:
                parts.append(
                    '<pre class="code-block"><code>'
                    f'{_esc(step.request)}'
                    '</code></pre>'
                )
            parts.append('</li>')
        parts.append('</ol>')
        parts.append('</section>')

    # Remediation
    parts.append('<section>')
    parts.append('<h4>Remediation</h4>')
    parts.append('<ol class="remediation">')
    for r in f.remediation:
        parts.append(f'<li>{_esc(r)}</li>')
    parts.append('</ol>')
    parts.append('</section>')

    # Code examples
    if f.code_examples:
        parts.append('<details class="code-examples" open>')
        parts.append('<summary><h4 style="display:inline;">Code examples</h4></summary>')
        for framework, snippet in f.code_examples.items():
            parts.append(f'<h5>{_esc(framework)}</h5>')
            parts.append('<pre class="code-block"><code>')
            parts.append(_esc(snippet.rstrip()))
            parts.append('</code></pre>')
        parts.append('</details>')

    # References
    if f.cwe or f.owasp or f.references:
        parts.append('<section>')
        parts.append('<h4>References</h4>')
        parts.append('<ul class="references">')
        for c in f.cwe:
            url = f"https://cwe.mitre.org/data/definitions/{c.split('-')[-1]}.html"
            parts.append(f'<li><a href="{_esc(url)}" target="_blank" rel="noopener">{_esc(c)}</a></li>')
        for o in f.owasp:
            parts.append(f'<li>OWASP {_esc(o)}</li>')
        for url in f.references:
            parts.append(f'<li><a href="{_esc(url)}" target="_blank" rel="noopener">{_esc(url)}</a></li>')
        parts.append('</ul>')
        parts.append('</section>')

    parts.append('</div>')  # finding-body
    parts.append('</article>')
    return "\n".join(parts)


def _parse_attack_steps(text: str) -> list[str]:
    """Parse an attack_scenario string into individual steps."""
    steps: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if len(s) > 2 and s[0].isdigit():
            for i in range(1, min(4, len(s))):
                if s[i] in {".", ")"} and i + 1 < len(s) and s[i + 1] == " ":
                    s = s[i + 2:].strip()
                    break
        steps.append(s)
    return steps


_CSS = """
:root {
  --bg: #ffffff;
  --fg: #111827;
  --muted: #6b7280;
  --border: #e5e7eb;
  --card-bg: #f9fafb;
  --code-bg: #1f2937;
  --code-fg: #f3f4f6;
  --accent: #2563eb;
  --link: #1d4ed8;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0b0f19;
    --fg: #e5e7eb;
    --muted: #9ca3af;
    --border: #1f2937;
    --card-bg: #111827;
    --code-bg: #030712;
    --code-fg: #d1d5db;
    --accent: #60a5fa;
    --link: #93c5fd;
  }
}
* { box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  margin: 0;
  padding: 0;
  background: var(--bg);
  color: var(--fg);
  line-height: 1.5;
}
.container {
  max-width: 1100px;
  margin: 0 auto;
  padding: 2rem 1.5rem;
}
header.page-header {
  border-bottom: 1px solid var(--border);
  padding-bottom: 1.5rem;
  margin-bottom: 2rem;
}
header.page-header h1 {
  margin: 0 0 0.5rem;
  font-size: 1.75rem;
}
header.page-header .subtitle {
  color: var(--muted);
  font-size: 0.95rem;
}
.summary {
  margin-bottom: 2rem;
}
.summary h2 {
  margin-top: 0;
}
.badges {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
}
.badge {
  display: inline-flex;
  align-items: baseline;
  gap: 0.5rem;
  color: #ffffff;
  padding: 0.5rem 0.9rem;
  border-radius: 0.375rem;
  font-weight: 600;
}
.badge-count {
  font-size: 1.5rem;
}
.badge-label {
  font-size: 0.85rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.finding {
  background: var(--card-bg);
  border: 1px solid var(--border);
  border-radius: 0.5rem;
  padding: 1.5rem;
  margin-bottom: 1.5rem;
}
.finding header {
  margin-bottom: 1rem;
}
.finding-title {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-bottom: 0.5rem;
}
.finding-title h3 {
  margin: 0;
  font-size: 1.2rem;
}
.sev-badge {
  color: #ffffff;
  padding: 0.25rem 0.6rem;
  border-radius: 0.25rem;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.finding-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 1rem;
  color: var(--muted);
  font-size: 0.85rem;
  margin-bottom: 0.5rem;
}
.meta-item code {
  background: var(--code-bg);
  color: var(--code-fg);
  padding: 0.05rem 0.35rem;
  border-radius: 0.2rem;
  font-size: 0.85em;
}
.finding-target {
  font-size: 0.9rem;
  margin-bottom: 1rem;
}
.finding-target code {
  background: var(--code-bg);
  color: var(--code-fg);
  padding: 0.1rem 0.4rem;
  border-radius: 0.2rem;
}
.finding-body section {
  margin-bottom: 1.25rem;
}
.finding-body h4 {
  margin: 0 0 0.5rem;
  font-size: 1rem;
  color: var(--accent);
}
.finding-body h5 {
  margin: 1rem 0 0.25rem;
  font-size: 0.9rem;
  text-transform: uppercase;
  color: var(--muted);
  letter-spacing: 0.05em;
}
.finding-body p {
  margin: 0;
  white-space: pre-wrap;
}
ol.attack-steps,
ol.reproduction,
ol.remediation {
  padding-left: 1.5rem;
  margin: 0.5rem 0;
}
ol.attack-steps li,
ol.reproduction li,
ol.remediation li {
  margin-bottom: 0.4rem;
}
pre.code-block {
  background: var(--code-bg);
  color: var(--code-fg);
  padding: 0.75rem;
  border-radius: 0.3rem;
  overflow-x: auto;
  font-size: 0.85rem;
  margin: 0.5rem 0;
}
pre.code-block code {
  font-family: "SFMono-Regular", Menlo, Consolas, monospace;
  background: none;
  color: inherit;
}
details {
  margin: 0.75rem 0;
}
details summary {
  cursor: pointer;
  padding: 0.25rem 0;
  user-select: none;
}
ul.references {
  padding-left: 1.5rem;
  margin: 0.5rem 0;
}
ul.references a {
  color: var(--link);
  text-decoration: none;
  word-break: break-all;
}
ul.references a:hover {
  text-decoration: underline;
}
footer.page-footer {
  border-top: 1px solid var(--border);
  margin-top: 2rem;
  padding-top: 1.5rem;
  color: var(--muted);
  font-size: 0.85rem;
  text-align: center;
}
@media print {
  body { background: #fff; color: #000; }
  .finding { page-break-inside: avoid; border: 1px solid #ccc; }
  pre.code-block { background: #f4f4f4; color: #000; border: 1px solid #ddd; }
  details { open: true; }
  details summary { color: #000; }
}
"""


def render_html_report(findings: list[Finding], target_name: str) -> str:
    """Return the HTML report as a single string."""
    cards = "\n".join(_finding_card(f) for f in findings)
    summary = _summary_section(findings)
    generated = datetime.now(UTC).isoformat()
    css = _CSS

    body = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>redveil security assessment — {_esc(target_name)}</title>
<style>
{css}
</style>
</head>
<body>
<div class="container">
<header class="page-header">
<h1>redveil Security Assessment</h1>
<div class="subtitle">Target: <strong>{_esc(target_name)}</strong></div>
<div class="subtitle">Generated: {_esc(generated)}</div>
<div class="subtitle">Findings: <strong>{len(findings)}</strong></div>
</header>
{summary}
<section class="findings">
{cards}
</section>
<footer class="page-footer">
Generated by <strong>redveil</strong> v0.1.0 &middot; <a href="https://github.com/" target="_blank" rel="noopener">view project</a>
</footer>
</div>
</body>
</html>
"""
    return body


def write_html_report(findings: list[Finding], target_name: str, output_dir: Path) -> Path:
    """Write report.html into output_dir. Returns the Path."""
    output_dir.mkdir(parents=True, exist_ok=True)
    p = output_dir / "report.html"
    p.write_text(render_html_report(findings, target_name))
    return p
