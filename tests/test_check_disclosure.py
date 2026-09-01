"""Tests for InfoDisclosureCheck."""
from unittest.mock import AsyncMock, MagicMock

import pytest

from redveil.checks.disclosure import InfoDisclosureCheck
from redveil.http.response import Response
from redveil.plugins.base import CheckDependencies


def _resp(headers: dict = None, status: int = 200, body: str = ""):
    return Response(request_id="r1", status_code=status, headers=headers or {}, body=body, elapsed_ms=10.0)


def _bind(check, side_effects):
    """side_effects: list of (headers, body) tuples or Response objects."""
    mock_http = MagicMock()
    mock_http._scope = MagicMock()
    cfg = MagicMock()
    cfg.target.base_url = "https://example.com"

    def to_resp(se):
        if isinstance(se, Response):
            return se
        return _resp(headers=se[0], body=se[1])

    mock_http.send = AsyncMock(side_effect=[to_resp(se) for se in side_effects])
    deps = CheckDependencies(http=mock_http, scope=mock_http._scope, config=cfg, context=MagicMock())
    check.bind(deps)
    return mock_http


@pytest.mark.asyncio
async def test_server_version_flagged():
    check = InfoDisclosureCheck()
    _bind(check, [({"Server": "nginx/1.18.0", "Content-Type": "text/html"}, "<html></html>")])
    cands = await check.discover(MagicMock())
    kinds = [c["kind"] for c in cands]
    assert "version_banner" in kinds


@pytest.mark.asyncio
async def test_x_powered_by_flagged():
    check = InfoDisclosureCheck()
    _bind(check, [({"X-Powered-By": "Express"}, "<html></html>")])
    cands = await check.discover(MagicMock())
    kinds = [c["kind"] for c in cands]
    assert "info_header" in kinds


@pytest.mark.asyncio
async def test_stack_trace_flagged_high():
    check = InfoDisclosureCheck()
    body = "Traceback (most recent call last):\n  File x.py"
    _bind(check, [({}, body)])
    cands = await check.discover(MagicMock())
    stack = [c for c in cands if c["kind"] == "stack_trace"]
    assert len(stack) == 1
    assert stack[0]["severity"].value == "high"


@pytest.mark.asyncio
async def test_db_error_flagged():
    check = InfoDisclosureCheck()
    body = "Error: SQLSTATE[HY000]: General error"
    _bind(check, [({}, body)])
    cands = await check.discover(MagicMock())
    db = [c for c in cands if c["kind"] == "db_error"]
    assert len(db) == 1


@pytest.mark.asyncio
async def test_html_comment_with_todo_flagged():
    check = InfoDisclosureCheck()
    body = "<html><!-- TODO: remove this debug code --></html>"
    _bind(check, [({}, body)])
    cands = await check.discover(MagicMock())
    cm = [c for c in cands if c["kind"] == "html_comment"]
    assert len(cm) == 1


@pytest.mark.asyncio
async def test_exposed_env_file_flagged():
    check = InfoDisclosureCheck()
    # First call: homepage, subsequent: debug paths
    side_effects = [({}, "<html></html>")] + [(_resp(headers={}, body="KEY=value")) for _ in range(20)]
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    env = [c for c in cands if c["kind"] == "exposed_env"]
    assert len(env) >= 1


@pytest.mark.asyncio
async def test_no_findings_clean_target():
    check = InfoDisclosureCheck()
    side_effects = [({"Content-Type": "text/html"}, "<html>clean</html>")] + [
        _resp(headers={}, body="", status=404) for _ in range(20)
    ]
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    assert len(cands) == 0


@pytest.mark.asyncio
async def test_assess_produces_finding():
    check = InfoDisclosureCheck()
    _bind(check, [({"Server": "nginx/1.18.0"}, "<html></html>")])
    cands = await check.discover(MagicMock())
    f = await check.assess(cands[0])
    assert f is not None
    assert f.severity.value == "medium"
