"""Tests for SecurityHeadersCheck."""
from unittest.mock import AsyncMock, MagicMock

import pytest

from redveil.checks.headers_security import SecurityHeadersCheck
from redveil.http.response import Response
from redveil.plugins.base import CheckDependencies


def _resp(headers: dict, status: int = 200, body: str = ""):
    return Response(request_id="r1", status_code=status, headers=headers, body=body, elapsed_ms=10.0)


def _bind(check, headers):
    mock_http = MagicMock()
    mock_http._scope = MagicMock()
    mock_http.send = AsyncMock(return_value=_resp(headers))
    cfg = MagicMock()
    cfg.target.base_url = "https://example.com"
    deps = CheckDependencies(http=mock_http, scope=mock_http._scope, config=cfg, context=MagicMock())
    check.bind(deps)
    return mock_http


@pytest.mark.asyncio
async def test_missing_x_frame_options_flagged():
    check = SecurityHeadersCheck()
    _bind(check, {"Content-Type": "text/html"})
    cands = await check.discover(MagicMock())
    headers = [c["header"] for c in cands]
    assert "x-frame-options" in headers


@pytest.mark.asyncio
async def test_present_x_frame_options_denied_not_flagged():
    check = SecurityHeadersCheck()
    _bind(check, {
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
    })
    cands = await check.discover(MagicMock())
    headers = [c["header"] for c in cands]
    assert "x-frame-options" not in headers
    assert "x-content-type-options" not in headers


@pytest.mark.asyncio
async def test_csp_wildcard_is_high():
    check = SecurityHeadersCheck()
    _bind(check, {"Content-Security-Policy": "*"})
    cands = await check.discover(MagicMock())
    csp_cands = [c for c in cands if c["header"] == "content-security-policy"]
    assert len(csp_cands) == 1
    assert csp_cands[0]["issue"] == "wildcard"
    assert csp_cands[0]["severity"].value == "high"


@pytest.mark.asyncio
async def test_hsts_short_max_age_low():
    check = SecurityHeadersCheck()
    _bind(check, {"Strict-Transport-Security": "max-age=300"})
    cands = await check.discover(MagicMock())
    hsts = [c for c in cands if c["header"] == "strict-transport-security"]
    assert len(hsts) == 1
    assert hsts[0]["issue"] == "short_max_age"


@pytest.mark.asyncio
async def test_validate_returns_confirmed():
    check = SecurityHeadersCheck()
    _bind(check, {})
    candidate = {"header": "x-frame-options", "value": None, "issue": "missing", "severity": None}
    result = await check.validate(MagicMock(), candidate)
    assert result.outcome.value == "confirmed"


@pytest.mark.asyncio
async def test_assess_produces_finding():
    check = SecurityHeadersCheck()
    _bind(check, {})
    from redveil.findings.severity import Severity
    candidate = {"header": "x-frame-options", "value": None, "issue": "missing", "severity": Severity.MEDIUM}
    finding = await check.assess(candidate)
    assert finding is not None
    assert "X-Frame-Options" in finding.title
