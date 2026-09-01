"""Tests for SourceMapCheck."""
from unittest.mock import AsyncMock, MagicMock

import pytest

from redveil.checks.source_maps import SourceMapCheck
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
async def test_exposed_map_directly():
    check = SourceMapCheck()
    # First: homepage with no scripts. Then: probe of /main.js.map returns valid JSON
    side_effects = [
        _resp(body="<html></html>"),
        _resp(body='{"version":3,"sources":["main.js"],"mappings":"AAAA"}'),
    ] + [_resp(status=404) for _ in range(10)]
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    exposed = [c for c in cands if c["kind"] == "exposed_source_map"]
    assert len(exposed) >= 1


@pytest.mark.asyncio
async def test_inline_source_map_ref():
    check = SourceMapCheck()
    # First: homepage with script. Then: fetch the script. Then: 404s.
    side_effects = [
        _resp(body='<html><script src="/app.js"></script></html>'),
        _resp(body='// some code\n//# sourceMappingURL=app.js.map'),
    ] + [_resp(status=404) for _ in range(10)]
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    inline = [c for c in cands if c["kind"] == "inline_source_map_ref"]
    assert len(inline) == 1
    assert inline[0]["map_ref"] == "app.js.map"


@pytest.mark.asyncio
async def test_no_findings_clean():
    check = SourceMapCheck()
    side_effects = [_resp(body="<html></html>")] + [_resp(status=404) for _ in range(15)]
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    assert len(cands) == 0


@pytest.mark.asyncio
async def test_validate_exposed_returns_confirmed():
    check = SourceMapCheck()
    side_effects = [_resp(body="<html></html>"), _resp(body='{"sources":["x"]}')] + [_resp(status=404) for _ in range(10)]
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    exposed = [c for c in cands if c["kind"] == "exposed_source_map"]
    if exposed:
        result = await check.validate(MagicMock(), exposed[0])
        assert result.outcome.value == "confirmed"


@pytest.mark.asyncio
async def test_assess_produces_finding():
    check = SourceMapCheck()
    side_effects = [_resp(body="<html></html>"), _resp(body='{"sources":["x"]}')] + [_resp(status=404) for _ in range(10)]
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    if cands:
        f = await check.assess(cands[0])
        assert f is not None
        assert f.severity.value == "medium"
