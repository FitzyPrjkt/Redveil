"""Tests for the HTML report renderer."""
from __future__ import annotations

from pathlib import Path

from redveil.findings.confidence import Confidence
from redveil.findings.finding import CheckRef, Finding, ReproductionStep, TargetRef
from redveil.findings.severity import Severity
from redveil.reporting.html_report import (
    render_html_report,
    write_html_report,
)


def _make_finding(
    *,
    sev: Severity = Severity.MEDIUM,
    title: str = "Test finding",
    attack_scenario: str | None = None,
    code_examples: dict[str, str] | None = None,
    remediation: list[str] | None = None,
    **overrides,
) -> Finding:
    defaults = {
        "check": CheckRef(id="test-check", name="Test Check", category="disclosure"),
        "title": title,
        "severity": sev,
        "confidence": Confidence.HIGH,
        "target": TargetRef(host="example.com", endpoint="/test", method="GET"),
        "summary": "Test summary text",
        "technical_explanation": "Test technical explanation",
        "impact": "Test impact",
        "remediation": remediation or ["Fix A", "Fix B", "Fix C"],
        "cwe": ["CWE-79"],
        "owasp": ["A03:2021"],
        "evidence_ids": ["EV-001"],
        "attack_scenario": attack_scenario,
        "code_examples": code_examples or {},
    }
    defaults.update(overrides)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# render_html_report — shape of the output
# ---------------------------------------------------------------------------


def test_render_html_report_includes_doctype():
    out = render_html_report([], "example.com")
    assert out.lower().startswith("<!doctype html>")


def test_render_html_report_has_embedded_style():
    out = render_html_report([], "example.com")
    assert "<style>" in out
    assert "prefers-color-scheme" in out
    assert "@media print" in out


def test_render_html_report_contains_target_name():
    out = render_html_report([], "example.com")
    assert "example.com" in out


def test_render_html_report_no_findings_says_so():
    out = render_html_report([], "example.com")
    # No severity badges
    assert "Findings:" in out or "Findings:</strong>" in out or "Findings</strong>" in out


def test_render_html_report_severity_badges_present():
    findings = [
        _make_finding(sev=Severity.CRITICAL, title="C"),
        _make_finding(sev=Severity.HIGH, title="H"),
        _make_finding(sev=Severity.MEDIUM, title="M"),
        _make_finding(sev=Severity.LOW, title="L"),
    ]
    out = render_html_report(findings, "example.com")
    assert "Critical" in out
    assert "High" in out
    assert "Medium" in out
    assert "Low" in out
    # Count badges
    assert out.count("class=\"badge\"") >= 4


def test_render_html_report_includes_finding_titles():
    findings = [
        _make_finding(title="CORS Wildcard Origin"),
        _make_finding(title="Missing CSP Header"),
    ]
    out = render_html_report(findings, "example.com")
    assert "CORS Wildcard Origin" in out
    assert "Missing CSP Header" in out


# ---------------------------------------------------------------------------
# Per-finding sections
# ---------------------------------------------------------------------------


def test_render_html_report_has_pre_block_per_finding_with_code_examples():
    findings = [
        _make_finding(
            title="With examples",
            code_examples={
                "nginx": "add_header X-Frame-Options \"DENY\";",
                "apache": "Header always set X-Frame-Options \"DENY\"",
            },
        ),
    ]
    out = render_html_report(findings, "example.com")
    # Must have at least one pre block containing the nginx config
    assert 'add_header X-Frame-Options' in out
    assert "<pre" in out
    assert "Header always set X-Frame-Options" in out


def test_render_html_report_includes_attack_scenario():
    findings = [
        _make_finding(
            attack_scenario=(
                "1. Attacker hosts a page at evil.example\n"
                "2. Frames target.example in an invisible iframe\n"
                "3. Victim visits evil.example\n"
                "4. Clicks the framed button — account takeover"
            )
        ),
    ]
    out = render_html_report(findings, "example.com")
    assert "Attack scenario" in out
    assert "evil.example" in out
    assert "account takeover" in out
    # Should be in an ordered list
    assert "<ol" in out and "</ol>" in out


def test_render_html_report_omits_attack_scenario_when_missing():
    findings = [_make_finding(attack_scenario=None)]
    out = render_html_report(findings, "example.com")
    # The "Attack scenario" header should not appear
    # (it might appear in the CSS but not in body content)
    body_start = out.find("<body>")
    body = out[body_start:] if body_start != -1 else out
    assert "Attack scenario" not in body


def test_render_html_report_includes_remediation_steps():
    findings = [_make_finding(remediation=["Step one", "Step two", "Step three"])]
    out = render_html_report(findings, "example.com")
    assert "Step one" in out
    assert "Step two" in out
    assert "Step three" in out
    assert "Remediation" in out


def test_render_html_report_includes_reproduction_steps():
    findings = [
        _make_finding(
            reproduction=[
                ReproductionStep(step=1, description="Send OPTIONS preflight", request="curl -X OPTIONS"),
            ]
        ),
    ]
    out = render_html_report(findings, "example.com")
    assert "Send OPTIONS preflight" in out
    assert "curl -X OPTIONS" in out


def test_render_html_report_includes_cwe_and_owasp():
    findings = [_make_finding()]
    out = render_html_report(findings, "example.com")
    assert "CWE-79" in out
    assert "A03:2021" in out
    # CWE link should be present
    assert "cwe.mitre.org" in out


# ---------------------------------------------------------------------------
# Self-containment — no external resources
# ---------------------------------------------------------------------------


def test_render_html_report_is_self_contained():
    """HTML report must not reference any external CSS or JS."""
    out = render_html_report([_make_finding()], "example.com")
    # Look for common external resource markers
    assert "<link" not in out or 'href="http' not in out
    assert "<script src" not in out
    # No CDN URLs
    assert "cdnjs" not in out
    assert "cdn.jsdelivr" not in out
    assert "cdn.tailwindcss" not in out


# ---------------------------------------------------------------------------
# Print-friendliness
# ---------------------------------------------------------------------------


def test_render_html_report_has_print_media_query():
    out = render_html_report([], "example.com")
    assert "@media print" in out


def test_render_html_report_has_dark_mode_support():
    out = render_html_report([], "example.com")
    assert "prefers-color-scheme: dark" in out or "prefers-color-scheme: dark" in out


# ---------------------------------------------------------------------------
# XSS safety — finding fields are escaped
# ---------------------------------------------------------------------------


def test_render_html_report_escapes_user_data():
    findings = [
        _make_finding(
            title="<script>alert(1)</script>",
            summary="Summary <img src=x onerror=alert(1)>",
        ),
    ]
    out = render_html_report(findings, "example.com")
    # The literal <script> from the title should not be present unescaped
    # outside of the document's own scripts (there are none).
    assert "<script>alert(1)</script>" not in out.replace("</body>", "PLACEHOLDER")
    # The escaped form should be present
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out


# ---------------------------------------------------------------------------
# write_html_report — file output
# ---------------------------------------------------------------------------


def test_write_html_report_creates_file(tmp_path: Path):
    findings = [_make_finding()]
    p = write_html_report(findings, "example.com", tmp_path)
    assert p.exists()
    assert p.name == "report.html"
    assert p.parent == tmp_path
    content = p.read_text()
    assert "example.com" in content


def test_write_html_report_creates_parent_dir(tmp_path: Path):
    findings = [_make_finding()]
    nested = tmp_path / "subdir" / "report"
    p = write_html_report(findings, "example.com", nested)
    assert p.exists()
    assert p.name == "report.html"


# ---------------------------------------------------------------------------
# HTML is wired into write_report (markdown.py)
# ---------------------------------------------------------------------------


def test_write_report_includes_html(tmp_path: Path):
    from redveil.reporting.markdown import write_report
    findings = [_make_finding()]
    written = write_report(findings, "example.com", tmp_path)
    # Should include the HTML output key
    assert any("html" in str(k) for k in written.keys())
    assert any(str(v).endswith(".html") for v in written.values())
