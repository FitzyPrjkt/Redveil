"""Tests for ReflectedXSSCheck."""
from unittest.mock import AsyncMock, MagicMock

import pytest

from redveil.checks.xss import _CANARIES, ReflectedXSSCheck
from redveil.http.response import Response
from redveil.plugins.base import CheckDependencies


def _resp(body: str = "", status: int = 200, headers: dict = None):
    return Response(request_id="r1", status_code=status, headers=headers or {"content-type": "text/html"}, body=body, elapsed_ms=10.0)


def _bind(check, side_effects, active: bool = True, ack: bool = True):
    mock_http = MagicMock()
    mock_http._scope = MagicMock()
    cfg = MagicMock()
    cfg.target.base_url = "https://example.com"
    cfg.authorization.active_testing = active
    cfg.authorization.acknowledged_safety_terms = ack
    cfg.authorization.out_of_band_callback_domain = None
    mock_http.send = AsyncMock(side_effect=side_effects)
    deps = CheckDependencies(http=mock_http, scope=mock_http._scope, config=cfg, context=MagicMock())
    check.bind(deps)
    return mock_http


@pytest.mark.asyncio
async def test_active_required():
    check = ReflectedXSSCheck()
    _bind(check, [], active=False)
    cands = await check.discover(MagicMock())
    assert cands == []


@pytest.mark.asyncio
async def test_acknowledgement_required():
    check = ReflectedXSSCheck()
    _bind(check, [], active=True, ack=False)
    cands = await check.discover(MagicMock())
    assert cands == []


@pytest.mark.asyncio
async def test_reflected_canary_detected():
    check = ReflectedXSSCheck()
    canary = _CANARIES[0]
    # First: homepage with no params. Then: requests for each param that gets canary reflected.
    homepage = _resp('<html><a href="/?q=foo">x</a></html>')
    canary_resp = _resp(f'<html>You searched for: {canary}</html>')
    side_effects = [homepage] + [canary_resp] * 25 + [_resp(status=404)] * 10
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    assert len(cands) >= 1
    assert any(c["parameter"] == "q" for c in cands)


@pytest.mark.asyncio
async def test_no_reflection_no_finding():
    check = ReflectedXSSCheck()
    homepage = _resp('<html><a href="/?q=foo">x</a></html>')
    safe = _resp('<html>You searched for: safe_value</html>')
    side_effects = [homepage] + [safe] * 25 + [_resp(status=404)] * 10
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    assert all(c["parameter"] != "q" for c in cands if "parameter" in c)


@pytest.mark.asyncio
async def test_validate_confirmed_for_unescaped():
    check = ReflectedXSSCheck()
    candidate = {"parameter": "q", "canary": "abc", "reflected_count": 3, "escaped": False}
    result = await check.validate(MagicMock(), candidate)
    assert result.outcome.value == "confirmed"


@pytest.mark.asyncio
async def test_validate_likely_for_escaped():
    check = ReflectedXSSCheck()
    candidate = {"parameter": "q", "canary": "abc", "reflected_count": 1, "escaped": True}
    result = await check.validate(MagicMock(), candidate)
    assert result.outcome.value == "likely"


@pytest.mark.asyncio
async def test_assess_produces_finding():
    check = ReflectedXSSCheck()
    _bind(check, [_resp("<html></html>")])
    candidate = {
        "endpoint": "/", "parameter": "q", "method": "GET",
        "canary": "redveilXSSProbe12345", "reflected_count": 1, "escaped": False,
        "request": MagicMock(url="https://example.com/?q=redveilXSSProbe12345"),
    }
    f = await check.assess(candidate)
    assert f is not None
    assert f.severity.value == "high"
    assert "CWE-79" in f.cwe


def test_safety_no_executable_payloads():
    """The canary strings must not contain any executable JavaScript."""
    for c in _CANARIES:
        for bad in ["<script", "</script", "onerror", "onload", "javascript:", "alert(", "eval(", "document.cookie"]:
            assert bad not in c.lower(), f"canary {c!r} contains forbidden {bad!r}"


@pytest.mark.asyncio
async def test_skips_404():
    check = ReflectedXSSCheck()
    homepage = _resp('<html><a href="/?q=foo">x</a></html>')
    notfound = _resp("not found", status=404)
    side_effects = [homepage] + [notfound] * 25
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    assert all(c.get("parameter") != "q" for c in cands if "parameter" in c)
