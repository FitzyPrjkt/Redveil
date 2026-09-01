"""Tests for Finding model."""
from __future__ import annotations

import json
from datetime import datetime

from redveil.findings.confidence import Confidence
from redveil.findings.finding import CheckRef, Finding, FindingStatus, ReproductionStep, TargetRef
from redveil.findings.severity import Severity


def _make_finding(**overrides) -> Finding:
    defaults = {
        "check": CheckRef(id="test-check", name="Test", category="disclosure"),
        "title": "Test finding",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "target": TargetRef(host="example.com", endpoint="/test", method="GET"),
        "summary": "Test summary",
        "technical_explanation": "Test technical",
        "impact": "Test impact",
    }
    defaults.update(overrides)
    return Finding(**defaults)


def test_finding_id_format():
    f = _make_finding()
    assert f.id.startswith("WPOC-")
    assert len(f.id) == len("WPOC-") + 6


def test_finding_serialization_roundtrip():
    f = _make_finding(evidence_ids=["EV-123"], cwe=["CWE-79"])
    d = f.to_dict()
    assert d["id"] == f.id
    assert d["severity"] == "medium"
    assert d["confidence"] == "high"
    assert d["cwe"] == ["CWE-79"]
    json_str = json.dumps(d)
    parsed = json.loads(json_str)
    assert parsed["id"] == f.id


def test_finding_default_status():
    f = _make_finding()
    assert f.status == FindingStatus.DISCOVERED


def test_finding_discovered_at_default():
    f = _make_finding()
    assert isinstance(f.discovered_at, datetime)
    assert f.discovered_at.tzinfo is not None


def test_severity_from_cvss():
    assert Severity.from_cvss(9.5) == Severity.CRITICAL
    assert Severity.from_cvss(7.0) == Severity.HIGH
    assert Severity.from_cvss(5.0) == Severity.MEDIUM
    assert Severity.from_cvss(1.0) == Severity.LOW
    assert Severity.from_cvss(0.0) == Severity.INFO


def test_reproduction_step():
    step = ReproductionStep(step=1, description="Send request", request="curl ...")
    assert step.step == 1
    assert step.request == "curl ..."
