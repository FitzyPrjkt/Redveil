"""Tests for Markdown + JSON report rendering."""
from __future__ import annotations

import json
from pathlib import Path

from redveil.findings.confidence import Confidence
from redveil.findings.finding import CheckRef, Finding, TargetRef
from redveil.findings.severity import Severity
from redveil.reporting.json_report import render_findings_json, write_findings_json
from redveil.reporting.markdown import render_finding, render_summary, write_report


def _make_finding(sev=Severity.MEDIUM, conf=Confidence.HIGH, **overrides) -> Finding:
    defaults = {
        "check": CheckRef(id="test-check", name="Test Check", category="disclosure"),
        "title": "Test finding",
        "severity": sev,
        "confidence": conf,
        "target": TargetRef(host="example.com", endpoint="/test", method="GET", parameter="q"),
        "summary": "Test summary",
        "technical_explanation": "Test technical",
        "impact": "Test impact",
        "remediation": ["Fix A", "Fix B"],
        "cwe": ["CWE-79"],
        "owasp": ["A03:2021"],
        "evidence_ids": ["EV-001"],
    }
    defaults.update(overrides)
    return Finding(**defaults)


def test_render_summary_empty():
    out = render_summary([], "example.com")
    assert "# redveil Security Assessment" in out
    assert "0" in out or "no findings" in out.lower() or "Findings:** 0" in out


def test_render_summary_groups_by_severity():
    findings = [
        _make_finding(sev=Severity.CRITICAL, title="Critical issue"),
        _make_finding(sev=Severity.HIGH, title="High issue"),
        _make_finding(sev=Severity.MEDIUM, title="Medium issue"),
    ]
    out = render_summary(findings, "example.com")
    assert "CRITICAL" in out
    assert "HIGH" in out
    assert "MEDIUM" in out
    assert "Critical issue" in out


def test_render_finding_includes_required_sections():
    f = _make_finding()
    out = render_finding(f)
    assert f.title in out
    assert f.id in out
    assert "## Summary" in out
    assert "## Technical explanation" in out
    assert "## Impact" in out
    assert "## Remediation" in out
    assert "CWE-79" in out


def test_render_finding_with_reproduction():
    from redveil.findings.finding import ReproductionStep
    f = _make_finding(reproduction=[
        ReproductionStep(step=1, description="Send payload", request="curl /test?q=x"),
    ])
    out = render_finding(f)
    assert "Send payload" in out
    assert "curl /test?q=x" in out


def test_render_findings_json_shape():
    findings = [_make_finding()]
    out = render_findings_json(findings, "example.com")
    data = json.loads(out)
    assert data["tool"] == "redveil"
    assert data["target"] == "example.com"
    assert data["findings_count"] == 1
    assert len(data["findings"]) == 1
    assert data["findings"][0]["title"] == "Test finding"


def test_write_findings_json(tmp_path: Path):
    findings = [_make_finding()]
    p = write_findings_json(findings, "example.com", tmp_path)
    assert p.exists()
    assert p.name == "findings.json"
    data = json.loads(p.read_text())
    assert data["findings_count"] == 1


def test_write_report_full(tmp_path: Path):
    findings = [_make_finding(), _make_finding(sev=Severity.HIGH, title="Second")]
    written = write_report(findings, "example.com", tmp_path)
    assert (tmp_path / "summary.md").exists()
    assert (tmp_path / "findings.json").exists()
    findings_dir = tmp_path / "findings"
    assert findings_dir.exists()
    md_files = list(findings_dir.glob("*.md"))
    assert len(md_files) == 2
