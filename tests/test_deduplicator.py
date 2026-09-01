"""Tests for finding deduplication."""
from __future__ import annotations

from redveil.findings.confidence import Confidence
from redveil.findings.deduplicator import FindingDeduplicator
from redveil.findings.finding import CheckRef, Finding, TargetRef
from redveil.findings.severity import Severity


def _make_finding(fp: str, **overrides) -> Finding:
    defaults = {
        "check": CheckRef(id="test", name="Test"),
        "title": "Test",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "target": TargetRef(host="example.com", endpoint="/test"),
        "summary": "s",
        "technical_explanation": "t",
        "impact": "i",
        "fingerprint": fp,
        "evidence_ids": [],
    }
    defaults.update(overrides)
    return Finding(**defaults)


def test_first_finding_added():
    dedup = FindingDeduplicator()
    f = _make_finding("fp-1", evidence_ids=["EV-1"])
    out = dedup.add(f)
    assert out.id == f.id
    assert "EV-1" in out.evidence_ids
    assert len(dedup) == 1


def test_same_fingerprint_merges_evidence():
    dedup = FindingDeduplicator()
    f1 = _make_finding("fp-1", evidence_ids=["EV-1"])
    f2 = _make_finding("fp-1", evidence_ids=["EV-2"])
    dedup.add(f1)
    merged = dedup.add(f2)
    assert "EV-1" in merged.evidence_ids
    assert "EV-2" in merged.evidence_ids
    assert len(dedup) == 1


def test_different_fingerprint_creates_new():
    dedup = FindingDeduplicator()
    f1 = _make_finding("fp-1")
    f2 = _make_finding("fp-2")
    dedup.add(f1)
    dedup.add(f2)
    assert len(dedup) == 2


def test_no_fingerprint_adds_each_time():
    dedup = FindingDeduplicator()
    f1 = _make_finding(None)
    f2 = _make_finding(None)
    dedup.add(f1)
    dedup.add(f2)
    # Both added since no fingerprint
    assert len(dedup) == 2


def test_all_returns_deduplicated_list():
    dedup = FindingDeduplicator()
    dedup.add(_make_finding("fp-1"))
    dedup.add(_make_finding("fp-1"))
    dedup.add(_make_finding("fp-2"))
    assert len(dedup.all()) == 2


def test_clear_resets():
    dedup = FindingDeduplicator()
    dedup.add(_make_finding("fp-1"))
    dedup.clear()
    assert len(dedup) == 0
