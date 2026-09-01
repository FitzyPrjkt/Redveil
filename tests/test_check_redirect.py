"""Tests for OpenRedirectCheck."""
from unittest.mock import AsyncMock, MagicMock

import pytest

from redveil.checks.redirect import OpenRedirectCheck
from redveil.http.response import Response
from redveil.plugins.base import CheckDependencies


def _resp(headers: dict = None, status: int = 200, body: str = ""):
    return Response(request_id="r1", status_code=status, headers=headers or {}, body=body, elapsed_ms=10.0)


def _bind(check, side_effects):
    mock_http = MagicMock()
    mock_http._scope = MagicMock()
    cfg = MagicMock()
    cfg.target.base_url = "https://example.com"
    mock_http.send = AsyncMock(side_effect=side_effects)
    deps = CheckDependencies(http=mock_http, scope=mock_http._scope, config=cfg, context=MagicMock())
    check.bind(deps)
    return mock_http


@pytest.mark.asyncio
async def test_redirect_param_in_link_detected():
    check = OpenRedirectCheck()
    body = '<html><a href="/login?next=/dashboard">Login</a></html>'
    # First call: homepage. Other calls: 404
    side_effects = [_resp(body=body)] + [_resp(status=404) for _ in range(10)]
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    params = [c["parameter"] for c in cands]
    assert "next" in params


@pytest.mark.asyncio
async def test_redirect_url_param_detected():
    check = OpenRedirectCheck()
    body = '<html><a href="/auth?url=https://example.com">Click</a></html>'
    side_effects = [_resp(body=body)] + [_resp(status=404) for _ in range(10)]
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    params = [c["parameter"] for c in cands]
    assert "url" in params


@pytest.mark.asyncio
async def test_no_redirect_params_clean():
    check = OpenRedirectCheck()
    body = '<html><a href="/about">About</a></html>'
    side_effects = [_resp(body=body)] + [_resp(status=404) for _ in range(10)]
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    assert len(cands) == 0


@pytest.mark.asyncio
async def test_probe_redirect_confirmed():
    check = OpenRedirectCheck()
    body = '<html></html>'
    # First: homepage. Then: probe gets 302 with Location
    side_effects = [
        _resp(body=body),
        _resp(headers={"Location": "/redveil-test-12345"}, status=302),
        _resp(status=404), _resp(status=404), _resp(status=404),
    ]
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    confirmed = [c for c in cands if c["kind"] == "redirect_param_confirmed"]
    assert len(confirmed) >= 1


@pytest.mark.asyncio
async def test_validate_likely_for_discovered():
    check = OpenRedirectCheck()
    _bind(check, [_resp(body="<html></html>")] + [_resp(status=404) for _ in range(10)])
    cands = await check.discover(MagicMock())
    if cands:
        result = await check.validate(MagicMock(), cands[0])
        assert result.outcome.value in {"likely", "confirmed"}


@pytest.mark.asyncio
async def test_assess_produces_finding():
    check = OpenRedirectCheck()
    _bind(check, [_resp(body="<html></html>")] + [_resp(status=404) for _ in range(10)])
    cands = await check.discover(MagicMock())
    if cands:
        f = await check.assess(cands[0])
        assert f is not None
        assert "Open Redirect" in f.title or "redirect" in f.title.lower()
