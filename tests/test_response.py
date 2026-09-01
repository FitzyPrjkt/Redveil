"""Tests for the internal ``Response`` model."""

from __future__ import annotations

import hashlib

from redveil.http.response import Response


def _make(body: str = "<html>hi</html>") -> Response:
    return Response(
        request_id="req-abc123",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body=body,
        body_excerpt=body[:500],
        elapsed_ms=12.5,
    )


def test_response_body_sha256_is_stable() -> None:
    body = "hello world"
    r1 = _make(body)
    r2 = _make(body)
    assert r1.body_sha256 == r2.body_sha256
    assert r1.body_sha256 == hashlib.sha256(body.encode()).hexdigest()


def test_response_body_sha256_changes_with_body() -> None:
    r1 = _make("a")
    r2 = _make("b")
    assert r1.body_sha256 != r2.body_sha256


def test_response_body_length_matches_encoded_size() -> None:
    body = "héllo"  # multibyte
    r = _make(body)
    assert r.body_length == len(body.encode("utf-8"))


def test_response_body_excerpt_is_bounded() -> None:
    big = "x" * 10_000
    r = Response(
        request_id="req-1",
        status_code=200,
        body=big,
        body_excerpt=big[:500],
        elapsed_ms=1.0,
    )
    assert len(r.body_excerpt) == 500
    assert len(r.body) == 10_000


def test_response_defaults() -> None:
    r = Response(
        request_id="req-1",
        status_code=204,
        elapsed_ms=3.0,
    )
    assert r.headers == {}
    assert r.body == ""
    assert r.body_excerpt == ""
    assert r.body_truncated is False
    assert r.remote_addr is None
    assert r.redirect_chain == []
    assert r.error is None
