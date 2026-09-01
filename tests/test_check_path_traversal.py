"""Tests for PathTraversalCheck — CRITICAL SAFETY TESTS."""
from unittest.mock import AsyncMock, MagicMock

import pytest

from redveil.checks.path_traversal import (
    _FILE_PARAMS,
    _FORBIDDEN_FILES,
    _TRAVERSAL_SEQUENCES,
    PathTraversalCheck,
)
from redveil.http.response import Response
from redveil.plugins.base import CheckDependencies


def _resp(body: str = "", status: int = 200, elapsed_ms: float = 10.0):
    return Response(request_id="r1", status_code=status, headers={}, body=body, elapsed_ms=elapsed_ms)


def _bind(check, side_effects, active: bool = True, ack: bool = True):
    mock_http = MagicMock()
    mock_http._scope = MagicMock()
    cfg = MagicMock()
    cfg.target.base_url = "https://example.com"
    cfg.authorization.active_testing = active
    cfg.authorization.acknowledged_safety_terms = ack
    mock_http.send = AsyncMock(side_effect=side_effects)
    deps = CheckDependencies(http=mock_http, scope=mock_http._scope, config=cfg, context=MagicMock())
    check.bind(deps)
    return mock_http


@pytest.mark.asyncio
async def test_active_required():
    check = PathTraversalCheck()
    _bind(check, [], active=False)
    cands = await check.discover(MagicMock())
    assert cands == []


@pytest.mark.asyncio
async def test_acknowledgement_required():
    check = PathTraversalCheck()
    _bind(check, [], active=True, ack=False)
    cands = await check.discover(MagicMock())
    assert cands == []


@pytest.mark.asyncio
async def test_no_different_response_no_finding():
    check = PathTraversalCheck()
    # Baseline and traversal get same response → no finding
    same = _resp(body="not found", status=404)
    _bind(check, [same] * 500)
    cands = await check.discover(MagicMock())
    assert cands == []


@pytest.mark.asyncio
async def test_different_status_detected():
    check = PathTraversalCheck()
    # Baseline: 404. Traversal: 200. → finding
    base = _resp(body="not found", status=404)
    hit = _resp(body="real file content", status=200)
    side_effects = []
    for _ in _FILE_PARAMS:
        side_effects.append(base)  # baseline
        side_effects.append(hit)   # traversal matches → break
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    assert len(cands) >= 1


@pytest.mark.asyncio
async def test_assess_produces_finding():
    check = PathTraversalCheck()
    _bind(check, [_resp()])
    candidate = {
        "endpoint": "/", "parameter": "file", "method": "GET",
        "payload": "../redveil_canary_abc123.txt", "canary": "redveil_canary_abc123.txt",
        "baseline_status": 404, "baseline_length": 9,
        "canary_status": 200, "canary_length": 100,
        "behavior": "different_status",
        "request": MagicMock(url="https://example.com/?file=../redveil_canary_abc123.txt"),
    }
    f = await check.assess(candidate)
    assert f is not None
    assert f.severity.value == "high"
    assert "CWE-22" in f.cwe


def test_safety_no_real_files_in_sequences():
    """The traversal sequences must NEVER reference real files. Canary is substituted at runtime."""
    for seq in _TRAVERSAL_SEQUENCES:
        for bad in _FORBIDDEN_FILES:
            # Allow only if the bad substring is in the {canary} placeholder, not in the literal
            assert bad not in seq, f"sequence {seq!r} references {bad!r}"


def test_safety_placeholder_format():
    """Every traversal sequence must have a {canary} placeholder for the unique filename."""
    for seq in _TRAVERSAL_SEQUENCES:
        assert "{canary}" in seq, f"sequence {seq!r} missing {{canary}} placeholder"


def test_safety_canary_is_unique_random():
    """Verify the canary is unique per call (use secrets.token_hex for randomness)."""
    from redveil.checks.path_traversal import _generate_traversal_payloads
    p1, c1 = _generate_traversal_payloads()
    p2, c2 = _generate_traversal_payloads()
    assert c1 != c2, "canary should be unique per call"
    assert "redveil_canary_" in c1
    assert len(c1) > len("redveil_canary_") + 8  # hex suffix
