"""Tests for evidence sanitization (secret redaction)."""
from __future__ import annotations

from redveil.evidence.evidence import Evidence, ObservationKind
from redveil.evidence.sanitizer import (
    _redact_headers,
    _redact_text,
    sanitize_evidence,
    sanitize_request,
    sanitize_response,
)
from redveil.http.request import Request
from redveil.http.response import Response


def test_redact_jwt():
    # JWT is 3 base64url segments separated by dots. Token is signature-valid format.
    text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    out = _redact_text(text)
    assert "[JWT_REDACTED]" in out
    assert "eyJ" not in out


def test_redact_aws_access_key():
    out = _redact_text("AKIAIOSFODNN7EXAMPLE")
    assert "[AWS_ACCESS_KEY_REDACTED]" in out


def test_redact_github_token():
    out = _redact_text("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
    assert "[GITHUB_TOKEN_REDACTED]" in out


def test_redact_stripe_key():
    out = _redact_text("sk_live_ABCDEFGHIJKLMNOPQRSTUV")
    assert "[STRIPE_KEY_REDACTED]" in out


def test_redact_credit_card():
    out = _redact_text("card: 4111 1111 1111 1111")
    assert "[CC_REDACTED]" in out


def test_redact_email():
    out = _redact_text("contact alice@example.com for details")
    assert "[EMAIL_REDACTED]" in out
    assert "alice@" not in out


def test_no_redact_for_normal_text():
    text = "Hello world, this is a normal log message."
    assert _redact_text(text) == text


def test_redact_sensitive_header_authorization():
    headers = {"Authorization": "Bearer abc123", "Content-Type": "text/html"}
    out = _redact_headers(headers)
    assert out["Authorization"] == "[REDACTED]"
    assert out["Content-Type"] == "text/html"


def test_redact_sensitive_header_cookie():
    headers = {"Cookie": "session=secret123", "User-Agent": "test"}
    out = _redact_headers(headers)
    assert out["Cookie"] == "[REDACTED]"
    assert out["User-Agent"] == "test"


def test_redact_sensitive_header_case_insensitive():
    headers = {"authorization": "Bearer xyz", "AUTHORIZATION": "Bearer abc"}
    out = _redact_headers(headers)
    assert all(v == "[REDACTED]" for v in out.values())


def test_sanitize_request_redacts_cookies():
    req = Request(
        method="GET",
        url="https://example.com/",
        headers={"Authorization": "Bearer xyz"},
        cookies={"session": "abc123"},
        body="user=alice&token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    )
    out = sanitize_request(req)
    assert out.headers["Authorization"] == "[REDACTED]"
    assert out.cookies == {"session": "[REDACTED]"}
    assert "eyJ" not in (out.body or "")


def test_sanitize_response_redacts_body_and_headers():
    resp = Response(
        request_id="req-1",
        status_code=200,
        elapsed_ms=10.0,
        headers={"Set-Cookie": "session=abc; HttpOnly"},
        body="token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
    )
    out = sanitize_response(resp)
    assert out.headers["Set-Cookie"] == "[REDACTED]"
    assert "ghp_" not in out.body
    assert "[GITHUB_TOKEN_REDACTED]" in out.body


def test_sanitize_evidence_full_chain():
    req = Request(
        method="GET",
        url="https://example.com/",
        headers={"Authorization": "Bearer abc"},
    )
    ev = Evidence(
        request=req,
        kind=ObservationKind.HEADER_PRESENT,
        endpoint="/",
        method="GET",
        input_used="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    )
    out = sanitize_evidence(ev)
    assert out.request.headers["Authorization"] == "[REDACTED]"
    assert "[JWT_REDACTED]" in out.input_used
    # Original untouched
    assert ev.input_used.startswith("eyJ")
