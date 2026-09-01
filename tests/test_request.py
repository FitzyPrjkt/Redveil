"""Tests for the internal ``Request`` model."""

from __future__ import annotations

import re

from redveil.http.request import Request

_REQUEST_ID_RE = re.compile(r"^req-[0-9a-f]{12}$")


def test_request_gets_unique_request_id() -> None:
    r1 = Request(method="GET", url="https://example.com/")
    r2 = Request(method="GET", url="https://example.com/")
    assert r1.request_id != r2.request_id
    assert _REQUEST_ID_RE.match(r1.request_id)
    assert _REQUEST_ID_RE.match(r2.request_id)


def test_request_to_curl_basic() -> None:
    req = Request(method="GET", url="https://example.com/api/v1")
    out = req.to_curl(redact_secrets=False)
    assert out.startswith("curl -X GET")
    assert "https://example.com/api/v1" in out


def test_request_to_curl_with_headers_and_body() -> None:
    req = Request(
        method="POST",
        url="https://example.com/api/v1/users",
        headers={"Content-Type": "application/json", "X-Trace": "abc"},
        body='{"name":"alice"}',
    )
    out = req.to_curl(redact_secrets=False)
    assert "curl -X POST" in out
    assert "Content-Type: application/json" in out
    assert "X-Trace: abc" in out
    assert "--data-raw" in out
    assert '{"name":"alice"}' in out


def test_request_to_curl_redacts_authorization() -> None:
    req = Request(
        method="GET",
        url="https://example.com/",
        headers={"Authorization": "Bearer supersecret"},
    )
    out = req.to_curl(redact_secrets=True)
    assert "supersecret" not in out
    assert "[REDACTED]" in out


def test_request_to_curl_redacts_cookie_header() -> None:
    req = Request(
        method="GET",
        url="https://example.com/",
        headers={"Cookie": "session=supersecret"},
    )
    out = req.to_curl(redact_secrets=True)
    assert "supersecret" not in out
    assert "[REDACTED]" in out


def test_request_to_curl_includes_query_params() -> None:
    req = Request(
        method="GET",
        url="https://example.com/search",
        params={"q": "test", "page": "2"},
    )
    out = req.to_curl(redact_secrets=False)
    assert "https://example.com/search?q=test&page=2" in out


def test_request_defaults() -> None:
    req = Request(method="GET", url="https://example.com/")
    assert req.headers == {}
    assert req.params == {}
    assert req.body is None
    assert req.body_truncated is False
    assert req.cookies == {}
    assert req.auth_principal is None
    assert req.purpose == "discovery"
