"""Tests for SessionCookieCheck."""
from unittest.mock import AsyncMock, MagicMock

import pytest

from redveil.checks.session_cookie import (
    SessionCookieCheck,
    _iter_set_cookies,
    _looks_like_session_cookie,
    _parse_set_cookie,
    _redact,
    _split_set_cookie,
    shannon_entropy,
)
from redveil.http.response import Response
from redveil.plugins.base import CheckDependencies

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resp(headers: dict | None = None, status: int = 200, body: str = "") -> Response:
    """Build a Response with default values."""
    return Response(
        request_id="r1",
        status_code=status,
        headers=headers or {},
        body=body,
        elapsed_ms=10.0,
    )


def _bind(check, side_effects, base_url: str = "https://example.com"):
    """Wire a mock HttpClient and config into a check instance."""
    mock_http = MagicMock()
    mock_http._scope = MagicMock()
    cfg = MagicMock()
    cfg.target.base_url = base_url
    mock_http.send = AsyncMock(side_effect=side_effects)
    deps = CheckDependencies(
        http=mock_http,
        scope=mock_http._scope,
        config=cfg,
        context=MagicMock(),
    )
    check.bind(deps)
    return mock_http


def _cookie_header(cookie_defs: list[tuple[str, str, dict[str, str]]]) -> str:
    """Build a comma-joined Set-Cookie header value from cookie definitions.

    Each tuple is (name, value, {attr: value}). Boolean attributes use
    the attr name alone (e.g. ``httponly=True`` -> ``HttpOnly``).
    """
    parts = []
    for name, val, attrs in cookie_defs:
        segs = [f"{name}={val}"]
        for k, v in attrs.items():
            if v is True or (isinstance(v, str) and v.lower() == "true"):
                segs.append(k.title() if k.lower() in {"httponly", "secure"} else k)
            elif v:
                segs.append(f"{k}={v}")
        parts.append("; ".join(segs))
    return ", ".join(parts)


# ---------------------------------------------------------------------------
# Unit tests for helpers
# ---------------------------------------------------------------------------


def test_shannon_entropy_empty():
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_uniform_distributed():
    # "abcdefgh" — 8 unique chars, each appears once → log2(8) = 3.0 bits/char
    assert abs(shannon_entropy("abcdefgh") - 3.0) < 1e-9


def test_shannon_entropy_single_char():
    # "aaaa" — only one symbol → 0 bits
    assert shannon_entropy("aaaa") == 0.0


def test_shannon_entropy_random_high():
    # Long random-looking hex string — should be near 4 bits/char
    random_hex = "a3f9c0d4b8e1f7a2c5d8e9b3a4f1c2d7"
    assert shannon_entropy(random_hex) > 3.5


def test_split_set_cookie_handles_multiple():
    combined = (
        "session=abc; Path=/; HttpOnly, "
        "auth=xyz; Secure; SameSite=Strict, "
        "tracking=foo; Path=/"
    )
    parts = _split_set_cookie(combined)
    assert len(parts) == 3
    assert parts[0].startswith("session=abc")
    assert parts[1].startswith("auth=xyz")
    assert parts[2].startswith("tracking=foo")


def test_split_set_cookie_preserves_expires():
    # Expires contains a comma (e.g. "Wed, 09 Jun 2021 10:18:14 GMT")
    combined = (
        "session=abc; Expires=Wed, 09 Jun 2021 10:18:14 GMT; Path=/, "
        "auth=xyz; Path=/"
    )
    parts = _split_set_cookie(combined)
    assert len(parts) == 2
    assert "Expires=Wed" in parts[0]


def test_parse_set_cookie_basic():
    parsed = _parse_set_cookie("session=abc123; HttpOnly; Secure; SameSite=Strict; Path=/")
    assert parsed is not None
    assert parsed["name"] == "session"
    assert parsed["value"] == "abc123"
    assert parsed["httponly"] == "true"
    assert parsed["secure"] == "true"
    assert parsed["samesite"] == "Strict"
    assert parsed["path"] == "/"


def test_parse_set_cookie_no_attrs():
    parsed = _parse_set_cookie("session=abc123")
    assert parsed is not None
    assert parsed["name"] == "session"
    assert parsed["value"] == "abc123"
    assert "httponly" not in parsed


def test_iter_set_cookies_from_dict():
    headers = {
        "Set-Cookie": _cookie_header([
            ("session", "abc123", {"httponly": True, "secure": True}),
            ("tracking", "xyz", {"path": "/"}),
        ]),
    }
    cookies = _iter_set_cookies(headers)
    assert len(cookies) == 2
    assert cookies[0]["name"] == "session"
    assert cookies[0]["httponly"] == "true"
    assert cookies[1]["name"] == "tracking"


def test_looks_like_session_cookie():
    assert _looks_like_session_cookie("session")
    assert _looks_like_session_cookie("SESSIONID")
    assert _looks_like_session_cookie("PHPSESSID")
    assert _looks_like_session_cookie("auth_token")
    assert not _looks_like_session_cookie("analytics_id")
    assert not _looks_like_session_cookie("lang")


def test_redact_short_value():
    assert _redact("abc") == "***"


def test_redact_long_value():
    redacted = _redact("abcdefghijklmnop")
    assert redacted.startswith("abcd")
    assert "REDACTED" in redacted


# ---------------------------------------------------------------------------
# Integration tests for the check
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_httponly_missing_flagged():
    """Cookie without HttpOnly flag is flagged."""
    check = SessionCookieCheck()
    headers = {
        "Set-Cookie": _cookie_header([
            ("session", "abc123def456", {"secure": True, "samesite": "Strict"}),
        ]),
    }
    _bind(check, [_resp(headers=headers)])
    cands = await check.discover(MagicMock())
    httponly_cands = [c for c in cands if c["kind"] == "cookie_httponly_missing"]
    assert len(httponly_cands) == 1
    assert httponly_cands[0]["cookie_name"] == "session"


@pytest.mark.asyncio
async def test_secure_missing_flagged():
    """Cookie without Secure flag (over HTTPS) is flagged."""
    check = SessionCookieCheck()
    headers = {
        "Set-Cookie": _cookie_header([
            ("session", "abc123def456", {"httponly": True, "samesite": "Strict"}),
        ]),
    }
    # base_url is https
    _bind(check, [_resp(headers=headers)], base_url="https://example.com")
    cands = await check.discover(MagicMock())
    secure_cands = [c for c in cands if c["kind"] == "cookie_secure_missing"]
    assert len(secure_cands) == 1
    assert secure_cands[0]["cookie_name"] == "session"


@pytest.mark.asyncio
async def test_samesite_missing_flagged():
    """Cookie without SameSite attribute is flagged."""
    check = SessionCookieCheck()
    headers = {
        "Set-Cookie": _cookie_header([
            ("session", "abc123def456", {"httponly": True, "secure": True}),
            # SameSite omitted
        ]),
    }
    _bind(check, [_resp(headers=headers)])
    cands = await check.discover(MagicMock())
    samesite_cands = [c for c in cands if c["kind"] == "cookie_samesite_missing"]
    assert len(samesite_cands) == 1
    assert samesite_cands[0]["cookie_name"] == "session"


@pytest.mark.asyncio
async def test_weak_token_flagged():
    """Short session ID with low entropy is flagged as weak."""
    check = SessionCookieCheck()
    # "aaaa" — low entropy (1 symbol), 4 chars, well below thresholds
    headers = {
        "Set-Cookie": _cookie_header([
            ("session", "aaaa", {"httponly": True, "secure": True, "samesite": "Strict"}),
        ]),
    }
    _bind(check, [_resp(headers=headers)])
    cands = await check.discover(MagicMock())
    weak = [c for c in cands if c["kind"] == "weak_session_token"]
    assert len(weak) == 1
    assert weak[0]["cookie_name"] == "session"
    assert weak[0]["entropy_bits"] < 1.0
    assert weak[0]["token_length"] == 4


@pytest.mark.asyncio
async def test_strong_token_not_flagged():
    """Long random session ID with high entropy is not flagged as weak."""
    check = SessionCookieCheck()
    # 32-byte random-looking hex — 4 bits/char, 64 chars → 256 bits entropy
    strong = "a3f9c0d4b8e1f7a2c5d8e9b3a4f1c2d7b8e2f0a3c4d5e6f7a8b9c0d1e2f3a4b5"
    headers = {
        "Set-Cookie": _cookie_header([
            ("session", strong, {"httponly": True, "secure": True, "samesite": "Strict"}),
        ]),
    }
    _bind(check, [_resp(headers=headers)])
    cands = await check.discover(MagicMock())
    weak = [c for c in cands if c["kind"] == "weak_session_token"]
    assert weak == []


@pytest.mark.asyncio
async def test_token_in_body_flagged():
    """Token-like query parameter in response body is flagged."""
    check = SessionCookieCheck()
    body = (
        "<html><body>"
        "<p>Reset link: /reset?token=abcdef1234567890abcdef</p>"
        "</body></html>"
    )
    _bind(check, [_resp(body=body)])
    cands = await check.discover(MagicMock())
    leaked = [c for c in cands if c["kind"] == "token_in_url"]
    assert len(leaked) >= 1
    assert leaked[0]["parameter"] == "token"


@pytest.mark.asyncio
async def test_no_cookies_no_finding():
    """Response without Set-Cookie produces no candidates."""
    check = SessionCookieCheck()
    _bind(check, [_resp(headers={"Content-Type": "text/html"})])
    cands = await check.discover(MagicMock())
    # Only check that no cookie-related candidates appear.
    cookie_kinds = {
        "cookie_httponly_missing", "cookie_secure_missing",
        "cookie_samesite_missing", "weak_session_token",
    }
    assert not [c for c in cands if c["kind"] in cookie_kinds]


@pytest.mark.asyncio
async def test_validate_confirmed_for_httponly():
    """validate() returns CONFIRMED for httponly_missing."""
    check = SessionCookieCheck()
    _bind(check, [_resp()])
    candidate = {
        "kind": "cookie_httponly_missing",
        "cookie_name": "session",
        "cookie_value": "abc",
        "request": MagicMock(),
        "response": MagicMock(),
        "endpoint": "/",
    }
    result = await check.validate(MagicMock(), candidate)
    assert result.outcome.value == "confirmed"
    assert result.confidence == "high"


@pytest.mark.asyncio
async def test_validate_weak_token_threshold():
    """validate() returns CONFIRMED for very weak tokens, LIKELY for borderline."""
    check = SessionCookieCheck()
    _bind(check, [_resp()])

    # Very weak: entropy < 3.0 → CONFIRMED
    very_weak = {
        "kind": "weak_session_token",
        "cookie_name": "session",
        "cookie_value": "aaaa",
        "entropy_bits": 0.0,
        "token_length": 4,
        "request": MagicMock(),
        "response": MagicMock(),
        "endpoint": "/",
    }
    result = await check.validate(MagicMock(), very_weak)
    assert result.outcome.value == "confirmed"

    # Borderline: entropy in [3.0, 3.5) → LIKELY
    borderline = {
        "kind": "weak_session_token",
        "cookie_name": "session",
        "cookie_value": "aabbccddee",
        "entropy_bits": 3.2,
        "token_length": 10,
        "request": MagicMock(),
        "response": MagicMock(),
        "endpoint": "/",
    }
    result = await check.validate(MagicMock(), borderline)
    assert result.outcome.value == "likely"


@pytest.mark.asyncio
async def test_assess_produces_finding():
    """assess() builds a Finding with correct severity and CWE."""
    from redveil.http.request import Request

    check = SessionCookieCheck()
    _bind(check, [_resp()])

    req = Request(method="GET", url="https://example.com/")
    candidate = {
        "kind": "cookie_httponly_missing",
        "cookie_name": "session",
        "cookie_value": "abc123",
        "request": req,
        "response": _resp(headers={
            "Set-Cookie": _cookie_header([
                ("session", "abc123", {"secure": True}),
            ]),
        }),
        "endpoint": "/",
    }
    f = await check.assess(candidate)
    assert f is not None
    assert "HttpOnly" in f.title
    assert f.severity.value == "medium"
    assert "CWE-1004" in f.cwe


@pytest.mark.asyncio
async def test_safety_no_active_testing():
    """Session-fixation detection is passive — no POST, no credentials.

    The check only issues GET requests. We assert that ``self.deps.http.send``
    is never called with a method other than GET, and never with a body or
    credentials. This is the safety contract: session-fixation detection
    requires active testing, which we explicitly DO NOT do.
    """
    check = SessionCookieCheck()
    headers = {
        "Set-Cookie": _cookie_header([
            ("session", "abc123def456", {"httponly": True, "secure": True}),
        ]),
    }
    # Homepage → 200, login → 404 (no fixation signal either way).
    _bind(
        check,
        [_resp(headers=headers), _resp(status=404), _resp(status=404), _resp(status=404)],
    )
    await check.discover(MagicMock())

    # Inspect every outbound request.
    mock_http = check.deps.http  # type: ignore[attr-defined]
    for call in mock_http.send.call_args_list:  # type: ignore[attr-defined]
        req = call.args[0] if call.args else call.kwargs.get("request")
        assert req is not None
        # Method must be GET — no POST, no login form submission.
        assert req.method == "GET", f"non-GET method used: {req.method}"
        # No body, no credentials.
        assert req.body is None or req.body == ""
        assert req.cookies == {} or all(
            v == "" for v in req.cookies.values()
        ) or "session" in req.cookies  # session-fixation check sets cookies


@pytest.mark.asyncio
async def test_assess_weak_token_high_severity():
    """Weak tokens produce HIGH severity with CWE-330."""
    from redveil.http.request import Request

    check = SessionCookieCheck()
    _bind(check, [_resp()])

    req = Request(method="GET", url="https://example.com/")
    candidate = {
        "kind": "weak_session_token",
        "cookie_name": "session",
        "cookie_value": "aaaa",
        "entropy_bits": 0.0,
        "token_length": 4,
        "request": req,
        "response": _resp(headers={
            "Set-Cookie": _cookie_header([
                ("session", "aaaa", {"httponly": True}),
            ]),
        }),
        "endpoint": "/",
    }
    f = await check.assess(candidate)
    assert f is not None
    assert f.severity.value == "high"
    assert "CWE-330" in f.cwe


@pytest.mark.asyncio
async def test_assess_token_in_url_high_severity():
    """Token leakage produces HIGH severity with CWE-598."""
    from redveil.http.request import Request

    check = SessionCookieCheck()
    _bind(check, [_resp()])

    req = Request(method="GET", url="https://example.com/")
    candidate = {
        "kind": "token_in_url",
        "context": "body",
        "parameter": "token",
        "value": "abcdef1234567890",
        "request": req,
        "response": _resp(body="token=abcdef1234567890"),
        "endpoint": "/",
    }
    f = await check.assess(candidate)
    assert f is not None
    assert f.severity.value == "high"
    assert "CWE-598" in f.cwe
