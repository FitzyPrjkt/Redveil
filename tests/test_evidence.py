"""Tests for Evidence model and fingerprinting."""
from __future__ import annotations

from redveil.evidence.evidence import Evidence, ObservationKind
from redveil.http.request import Request
from redveil.http.response import Response


def _make_evidence(**overrides) -> Evidence:
    defaults = {
        "request": Request(method="GET", url="https://example.com/test"),
        "kind": ObservationKind.HEADER_MISSING,
        "endpoint": "/test",
        "method": "GET",
        "observation": "missing header",
    }
    defaults.update(overrides)
    return Evidence(**defaults)


def test_evidence_id_format():
    e = _make_evidence()
    assert e.id.startswith("EV-")
    assert len(e.id) == len("EV-") + 8


def test_evidence_fingerprint_stable():
    e1 = _make_evidence(endpoint="/foo", parameter="q", input_used="abc")
    e2 = _make_evidence(endpoint="/foo", parameter="q", input_used="abc")
    assert e1.fingerprint == e2.fingerprint
    assert len(e1.fingerprint) == 16


def test_evidence_fingerprint_differs_by_endpoint():
    e1 = _make_evidence(endpoint="/foo")
    e2 = _make_evidence(endpoint="/bar")
    assert e1.fingerprint != e2.fingerprint


def test_evidence_fingerprint_differs_by_parameter():
    e1 = _make_evidence(parameter="q", input_used="x")
    e2 = _make_evidence(parameter="r", input_used="x")
    assert e1.fingerprint != e2.fingerprint


def test_evidence_fingerprint_differs_by_input():
    e1 = _make_evidence(input_used="hello")
    e2 = _make_evidence(input_used="world")
    assert e1.fingerprint != e2.fingerprint


def test_evidence_fingerprint_input_truncated_to_200():
    e1 = _make_evidence(input_used="a" * 200)
    e2 = _make_evidence(input_used="a" * 300)
    assert e1.fingerprint == e2.fingerprint  # both truncated to 200


def test_evidence_with_response():
    resp = Response(
        request_id="req-1",
        status_code=200,
        body="ok",
        elapsed_ms=12.5,
    )
    e = _make_evidence(response=resp, status_code=200)
    assert e.response is not None
    assert e.status_code == 200
