"""Vector-based tests for SessionCookieCheck.

Each test focuses on one subkind of finding produced by the new vector-based
implementation:

  - Browser vector: xss_steals_session, csrf_via_xss, httponly_missing_no_xss,
    samesite_missing
  - Network vector: secure_missing_over_https
  - Server vector:  weak_token, token_in_response_body

Plus pure unit tests for the helper functions (entropy, cookie-name matching,
Set-Cookie parsing).
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from redveil.checks.session_cookie import (
    SessionCookieCheck,
    _is_session_cookie_name,
    _parse_set_cookie,
    shannon_entropy,
)
from redveil.http.request import Request
from redveil.http.response import Response
from redveil.plugins.base import CheckDependencies

# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------


def _make_response(
    headers: dict | None = None,
    body: str = "<html></html>",
    status: int = 200,
    elapsed_ms: float = 10.0,
) -> Response:
    return Response(
        request_id="r1",
        status_code=status,
        headers=headers or {},
        body=body,
        elapsed_ms=elapsed_ms,
    )


def _bind(
    check,
    side_effects,
    base_url: str = "https://example.com",
):
    mock_http = MagicMock()
    mock_http._scope = MagicMock()
    cfg = MagicMock()
    cfg.target.base_url = base_url
    cfg.authorization.active_testing = False
    cfg.authorization.acknowledged_safety_terms = False
    mock_http.send = AsyncMock(side_effect=side_effects)
    deps = CheckDependencies(
        http=mock_http,
        scope=mock_http._scope,
        config=cfg,
        context=MagicMock(),
    )
    check.bind(deps)
    return mock_http


def _set_cookie(name: str, value: str, attrs: dict | None = None) -> str:
    """Build a single Set-Cookie header value (no comma-separated multiple)."""
    parts = [f"{name}={value}"]
    for k, v in (attrs or {}).items():
        if v is True:
            parts.append(k)
        elif v is False or v is None:
            continue
        else:
            parts.append(f"{k}={v}")
    return "; ".join(parts)


# ---------------------------------------------------------------------------
# Pure helper unit tests
# ---------------------------------------------------------------------------


def test_shannon_entropy_low():
    assert shannon_entropy("aaaaaa") == pytest.approx(0.0)
    # "abc" — 3 distinct chars, each appearing once → log2(3) ≈ 1.585
    assert shannon_entropy("abc") == pytest.approx(1.585, abs=0.01)


def test_shannon_entropy_high():
    # 32 distinct chars → entropy = log2(32) = 5.0 bits/char
    assert shannon_entropy("Yk7_q2vN3xMzP9bL4cVwR8jT6sH1dF0gA") > 4.5


def test_parse_set_cookie_extracts_attrs():
    parsed = _parse_set_cookie(
        "session=abc; Path=/; HttpOnly; Secure; SameSite=Strict"
    )
    assert parsed is not None
    assert parsed["name"] == "session"
    assert parsed["value"] == "abc"
    assert parsed["httponly"] == "true"
    assert parsed["secure"] == "true"
    assert parsed["samesite"] == "Strict"
    assert parsed["path"] == "/"


def test_identify_session_cookie_name():
    assert _is_session_cookie_name("session") is True
    # Case-insensitive matching
    assert _is_session_cookie_name("PHPSESSID") is True
    # Analytics cookie shouldn't match
    assert _is_session_cookie_name("_ga") is False
    # "csrftoken" contains "token" which is in the session-name list → matches
    assert _is_session_cookie_name("csrftoken") is True


# ---------------------------------------------------------------------------
# Browser vector — XSS chain
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_browser_xss_steals_session_httponly_missing():
    """HttpOnly missing + XSS reflection → xss_steals_session (CRITICAL)."""
    check = SessionCookieCheck()

    headers = {
        "Set-Cookie": _set_cookie("session", "abc", {"Path": "/"}),
    }
    home = _make_response(headers=headers, body="<html>welcome</html>")

    # Canary probe (?q=redveilXSSProbe12345) reflects the canary unescaped
    reflected_body = "<html>q=redveilXSSProbe12345</html>"
    canary_probe = _make_response(body=reflected_body)

    _bind(check, [home, canary_probe])

    cands = await check.discover(MagicMock())
    xss_cands = [c for c in cands if c["subkind"] == "xss_steals_session"]
    assert len(xss_cands) == 1
    cand = xss_cands[0]
    assert cand["vector"] == "browser"
    assert cand["cookie_name"] == "session"

    # Validate() should report CONFIRMED / high confidence.
    v = await check.validate(MagicMock(), cand)
    assert v is not None
    assert v.outcome.value == "confirmed"
    assert v.confidence == "high"

    # assess() should produce CRITICAL with the right title prefix.
    finding = await check.assess(cand)
    assert finding is not None
    assert finding.severity.value == "critical"
    assert "Session Token Exposed via Browser Vector" in finding.title


@pytest.mark.asyncio
async def test_browser_csrf_via_xss_samesite_none():
    """SameSite=None + XSS reflection → csrf_via_xss (HIGH)."""
    check = SessionCookieCheck()

    headers = {
        "Set-Cookie": _set_cookie(
            "session", "abc", {"Path": "/", "SameSite": "None"}
        ),
    }
    home = _make_response(headers=headers)
    reflected = _make_response(body="q=redveilXSSProbe12345 is reflected")

    _bind(check, [home, reflected])

    cands = await check.discover(MagicMock())
    csrf_cands = [c for c in cands if c["subkind"] == "csrf_via_xss"]
    assert len(csrf_cands) == 1
    cand = csrf_cands[0]
    assert cand["vector"] == "browser"

    v = await check.validate(MagicMock(), cand)
    assert v.outcome.value == "confirmed"
    assert v.confidence == "high"

    finding = await check.assess(cand)
    assert finding is not None
    assert finding.severity.value == "high"


@pytest.mark.asyncio
async def test_browser_no_xss_httponly_missing_low_severity():
    """HttpOnly missing but no XSS observed → LOW hardening gap."""
    check = SessionCookieCheck()

    headers = {
        "Set-Cookie": _set_cookie("session", "abc123def456ghi", {"Path": "/"}),
    }
    home = _make_response(headers=headers)

    # Provide six probe responses — none reflect the canary. Body must not
    # contain "redveilXSSProbe12345" for any of the candidate params.
    no_reflect = _make_response(body="<html>no reflection here</html>")
    _bind(check, [home, no_reflect, no_reflect, no_reflect, no_reflect, no_reflect, no_reflect])

    cands = await check.discover(MagicMock())
    low_cands = [
        c for c in cands if c["subkind"] == "httponly_missing_no_xss"
    ]
    assert len(low_cands) == 1
    cand = low_cands[0]
    assert cand["vector"] == "browser"

    finding = await check.assess(cand)
    assert finding is not None
    assert finding.severity.value == "low"


# ---------------------------------------------------------------------------
# Network vector — MITM
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_network_https_cookie_no_secure():
    """HTTPS site, cookie missing Secure flag → secure_missing_over_https (HIGH)."""
    check = SessionCookieCheck()

    headers = {
        "Set-Cookie": _set_cookie(
            "session",
            "abc123def456ghi",
            {"Path": "/", "HttpOnly": True},
        ),
    }
    home = _make_response(headers=headers)
    no_reflect = _make_response(body="<html>safe</html>")
    _bind(check, [home, no_reflect, no_reflect, no_reflect, no_reflect, no_reflect, no_reflect])

    cands = await check.discover(MagicMock())
    mitm_cands = [
        c for c in cands if c["subkind"] == "secure_missing_over_https"
    ]
    assert len(mitm_cands) == 1
    cand = mitm_cands[0]
    assert cand["vector"] == "network"

    v = await check.validate(MagicMock(), cand)
    assert v.outcome.value == "confirmed"
    assert v.confidence == "high"

    finding = await check.assess(cand)
    assert finding is not None
    assert finding.severity.value == "high"


@pytest.mark.asyncio
async def test_network_no_findings_when_secure_set():
    """HTTPS + Secure + HttpOnly + strong token → no high/critical findings."""
    check = SessionCookieCheck()

    strong_token = "Yk7_q2vN3xMzP9bL4cVwR8jT6sH1dF0gA"
    headers = {
        "Set-Cookie": _set_cookie(
            "session",
            strong_token,
            {
                "Path": "/",
                "HttpOnly": True,
                "Secure": True,
                "SameSite": "Strict",
            },
        ),
    }
    home = _make_response(headers=headers)
    no_reflect = _make_response(body="<html>safe</html>")
    _bind(check, [home, no_reflect, no_reflect, no_reflect, no_reflect, no_reflect, no_reflect])

    cands = await check.discover(MagicMock())

    # No critical/high-severity subkinds should appear.
    bad_subkinds = {
        "xss_steals_session",
        "csrf_via_xss",
        "secure_missing_over_https",
        "weak_token",
        "token_in_response_body",
    }
    bad = [c for c in cands if c["subkind"] in bad_subkinds]
    assert bad == [], f"unexpected findings: {[c['subkind'] for c in bad]}"


# ---------------------------------------------------------------------------
# Server vector — weak token
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_server_weak_token_low_entropy():
    """Short / low-entropy token → weak_token (HIGH, CONFIRMED)."""
    check = SessionCookieCheck()

    # "abcdef" — 8 chars, all lowercase letters. Entropy = log2(6) ≈ 2.585 bits/char,
    # well below the 3.0 bits/char threshold. Also length < 16.
    headers = {
        "Set-Cookie": _set_cookie("session", "abcdef", {"Path": "/"}),
    }
    home = _make_response(headers=headers)
    no_reflect = _make_response(body="<html>safe</html>")
    _bind(check, [home, no_reflect, no_reflect, no_reflect, no_reflect, no_reflect, no_reflect])

    cands = await check.discover(MagicMock())
    weak_cands = [c for c in cands if c["subkind"] == "weak_token"]
    assert len(weak_cands) == 1
    cand = weak_cands[0]
    assert cand["vector"] == "server"

    v = await check.validate(MagicMock(), cand)
    assert v.outcome.value == "confirmed"
    assert v.confidence == "high"

    finding = await check.assess(cand)
    assert finding is not None
    assert finding.severity.value == "high"


@pytest.mark.asyncio
async def test_server_strong_token_no_finding():
    """High-entropy long token → no weak_token finding."""
    check = SessionCookieCheck()

    strong_token = "Yk7_q2vN3xMzP9bL4cVwR8jT6sH1dF0gA"
    headers = {
        "Set-Cookie": _set_cookie(
            "session",
            strong_token,
            {
                "Path": "/",
                "HttpOnly": True,
                "Secure": True,
                "SameSite": "Strict",
            },
        ),
    }
    home = _make_response(headers=headers)
    no_reflect = _make_response(body="<html>safe</html>")
    _bind(check, [home, no_reflect, no_reflect, no_reflect, no_reflect, no_reflect, no_reflect])

    cands = await check.discover(MagicMock())
    weak_cands = [c for c in cands if c["subkind"] == "weak_token"]
    assert weak_cands == []


# ---------------------------------------------------------------------------
# Server vector — token in response body
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_server_token_in_response_body():
    """Token-like parameter in response body → token_in_response_body (HIGH)."""
    check = SessionCookieCheck()

    body = (
        "<html>Reset link: /reset?token=eyJhbGciOiJIUzI1NiJ9.payload.sig</html>"
    )
    home = _make_response(body=body)
    # No Set-Cookie header — so the probe is skipped and we only do leakage scan.
    _bind(check, [home])

    cands = await check.discover(MagicMock())
    body_cands = [c for c in cands if c["subkind"] == "token_in_response_body"]
    assert len(body_cands) >= 1
    cand = body_cands[0]
    assert cand["vector"] == "server"
    assert cand["parameter"] == "token"

    v = await check.validate(MagicMock(), cand)
    assert v.outcome.value == "confirmed"
    assert v.confidence == "high"

    finding = await check.assess(cand)
    assert finding is not None
    assert finding.severity.value == "high"


# ---------------------------------------------------------------------------
# Integration: no cookies at all
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_session_cookies_clean():
    """No Set-Cookie + no token-like parameter in body → no candidates at all."""
    check = SessionCookieCheck()

    home = _make_response(
        headers={"Content-Type": "text/html"},
        body="<html>plain page with no tokens or sessions</html>",
    )
    _bind(check, [home])

    cands = await check.discover(MagicMock())
    # No subkinds at all should appear — no cookies set, no token pattern in body.
    assert cands == []