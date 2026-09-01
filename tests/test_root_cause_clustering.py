"""Tests for Wave 5: Root-cause clustering."""
from __future__ import annotations
import pytest
from redveil.findings.deduplicator import FindingDeduplicator
from redveil.findings.finding import (
    CheckRef, Finding, FindingStatus, ReproductionStep, TargetRef,
)
from redveil.findings.severity import Severity
from redveil.findings.confidence import Confidence


def _make_finding(
    endpoint: str,
    root_cause: str | None = None,
    severity: Severity = Severity.MEDIUM,
    confidence: Confidence = Confidence.MEDIUM,
    fingerprint: str | None = None,
) -> Finding:
    return Finding(
        check=CheckRef(id="test-check", name="Test"),
        title=f"Test finding on {endpoint}",
        severity=severity,
        confidence=confidence,
        status=FindingStatus.CONFIRMED,
        target=TargetRef(host="example.com", endpoint=endpoint, method="GET"),
        summary="x", technical_explanation="y", impact="z",
        remediation=["fix"],
        cwe=["CWE-1004"],
        owasp=["A05:2021"],
        root_cause=root_cause,
        fingerprint=fingerprint or f"fp-{endpoint}",
    )


# ---------------------------------------------------------------------------
# Two-level dedup: fingerprint (per-endpoint) + root_cause (cluster)
# ---------------------------------------------------------------------------


def test_fingerprint_dedup_per_endpoint():
    """Same fingerprint → merged (per-endpoint dedup)."""
    dedup = FindingDeduplicator()
    a = _make_finding(endpoint="/api", fingerprint="fp-1")
    b = _make_finding(endpoint="/api", fingerprint="fp-1")
    dedup.add(a)
    merged = dedup.add(b)
    # Two findings, one merged
    assert len(dedup) == 1


def test_root_cause_clustering():
    """Two findings on different endpoints with same root_cause → one cluster."""
    dedup = FindingDeduplicator()
    a = _make_finding(endpoint="/", root_cause="missing-csp", fingerprint="fp-a")
    b = _make_finding(endpoint="/api", root_cause="missing-csp", fingerprint="fp-b")
    c = _make_finding(endpoint="/admin", root_cause="missing-csp", fingerprint="fp-c")
    dedup.add(a)
    dedup.add(b)
    cluster = dedup.add(c)
    assert cluster.cluster_size == 3
    assert "/" in cluster.affected_endpoints
    assert "/api" in cluster.affected_endpoints
    assert "/admin" in cluster.affected_endpoints
    assert len(dedup) == 1  # three findings merged into one cluster


def test_no_root_cause_means_no_clustering():
    """Findings without root_cause are deduped per-endpoint only."""
    dedup = FindingDeduplicator()
    a = _make_finding(endpoint="/", fingerprint="fp-a")
    b = _make_finding(endpoint="/api", fingerprint="fp-b")
    dedup.add(a)
    dedup.add(b)
    assert len(dedup) == 2  # not clustered


def test_different_root_causes_not_merged():
    dedup = FindingDeduplicator()
    a = _make_finding(endpoint="/", root_cause="missing-csp", fingerprint="fp-a")
    b = _make_finding(endpoint="/", root_cause="weak-token", fingerprint="fp-b")
    dedup.add(a)
    dedup.add(b)
    assert len(dedup) == 2  # different root causes


def test_cluster_keeps_highest_severity():
    """When clustering, prefer the higher-severity member as the head."""
    dedup = FindingDeduplicator()
    low = _make_finding(endpoint="/", root_cause="x", severity=Severity.LOW, fingerprint="fp-1")
    high = _make_finding(endpoint="/api", root_cause="x", severity=Severity.HIGH, fingerprint="fp-2")
    dedup.add(low)
    cluster = dedup.add(high)
    assert cluster.severity == Severity.HIGH
    assert cluster.cluster_size == 2


def test_cluster_size_grows():
    dedup = FindingDeduplicator()
    dedup.add(_make_finding(endpoint="/a", root_cause="x", fingerprint="fp-1"))
    r1 = dedup.add(_make_finding(endpoint="/b", root_cause="x", fingerprint="fp-2"))
    assert r1.cluster_size == 2
    r2 = dedup.add(_make_finding(endpoint="/c", root_cause="x", fingerprint="fp-3"))
    assert r2.cluster_size == 3
    r3 = dedup.add(_make_finding(endpoint="/d", root_cause="x", fingerprint="fp-4"))
    assert r3.cluster_size == 4


def test_clustering_can_be_disabled():
    dedup = FindingDeduplicator(cluster_by_root_cause=False)
    a = _make_finding(endpoint="/", root_cause="x", fingerprint="fp-a")
    b = _make_finding(endpoint="/api", root_cause="x", fingerprint="fp-b")
    dedup.add(a)
    dedup.add(b)
    # Without clustering, the two findings stay separate (different fingerprints)
    assert len(dedup) == 2


def test_all_returns_cluster_head_only():
    """A clustered finding shows up once in .all()."""
    dedup = FindingDeduplicator()
    dedup.add(_make_finding(endpoint="/", root_cause="x", fingerprint="fp-1"))
    dedup.add(_make_finding(endpoint="/api", root_cause="x", fingerprint="fp-2"))
    dedup.add(_make_finding(endpoint="/admin", root_cause="x", fingerprint="fp-3"))
    findings = dedup.all()
    assert len(findings) == 1
    assert findings[0].cluster_size == 3
