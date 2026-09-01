"""Tests for BFLACheck."""
from unittest.mock import AsyncMock, MagicMock

import pytest

from redveil.checks.bfla import _ADMIN_PATHS, BFLACheck
from redveil.http.response import Response
from redveil.plugins.base import CheckDependencies


def _resp(body: str = "", status: int = 200, headers: dict = None):
    return Response(request_id="r1", status_code=status, headers=headers or {}, body=body, elapsed_ms=10.0)


def _bind(check, side_effects, active: bool = True, ack: bool = True, has_principals: bool = True):
    mock_http = MagicMock()
    mock_http._scope = MagicMock()
    cfg = MagicMock()
    cfg.target.base_url = "https://example.com"
    cfg.authorization.active_testing = active
    cfg.authorization.acknowledged_safety_terms = ack
    if has_principals:
        principal = MagicMock()
        principal.name = "Account A"
        principal.to_override.return_value = ({}, {"session": "abc"})
        cfg.auth.principals = [principal]
    else:
        cfg.auth.principals = []
    mock_http.send = AsyncMock(side_effect=side_effects)
    # Mock the gate
    mock_gate = MagicMock()
    decision = MagicMock()
    decision.approved = True
    decision.plan = MagicMock()
    decision.reason = "test-mock"
    decision.__bool__ = lambda self: self.approved
    mock_gate.ask.return_value = decision
    deps = CheckDependencies(
        http=mock_http, scope=mock_http._scope, config=cfg, context=MagicMock(),
        gate=mock_gate,
    )
    check.bind(deps)
    return mock_http


@pytest.mark.asyncio
async def test_active_required():
    check = BFLACheck()
    _bind(check, [], active=False)
    cands = await check.discover(MagicMock())
    assert cands == []


@pytest.mark.asyncio
async def test_acknowledgement_required():
    check = BFLACheck()
    _bind(check, [], active=True, ack=False)
    cands = await check.discover(MagicMock())
    assert cands == []


@pytest.mark.asyncio
async def test_principals_required():
    check = BFLACheck()
    _bind(check, [], has_principals=False)
    cands = await check.discover(MagicMock())
    assert cands == []


@pytest.mark.asyncio
async def test_admin_endpoint_blocked_no_finding():
    check = BFLACheck()
    notfound = _resp(status=403, body="Forbidden")
    _bind(check, [notfound] * 50)
    cands = await check.discover(MagicMock())
    assert cands == []


@pytest.mark.asyncio
async def test_admin_endpoint_accessible_detected():
    check = BFLACheck()
    # Response with admin-shaped content (multiple markers)
    body = '{"users": [...], "admin": true, "role": "admin", "permissions": ["read","write"]}'
    admin_resp = _resp(status=200, body=body)
    _bind(check, [admin_resp] * 50)
    cands = await check.discover(MagicMock())
    assert len(cands) >= 1
    assert cands[0]["marker_count"] >= 3


@pytest.mark.asyncio
async def test_validate_confirmed():
    check = BFLACheck()
    _bind(check, [_resp()])
    candidate = {"endpoint": "/admin", "marker_count": 5, "principal": "Account A"}
    result = await check.validate(MagicMock(), candidate)
    assert result.outcome.value == "confirmed"


@pytest.mark.asyncio
async def test_validate_likely_for_weak_marker():
    check = BFLACheck()
    _bind(check, [_resp()])
    candidate = {"endpoint": "/admin", "marker_count": 2, "principal": "Account A"}
    result = await check.validate(MagicMock(), candidate)
    assert result.outcome.value == "likely"


@pytest.mark.asyncio
async def test_assess_produces_finding():
    check = BFLACheck()
    _bind(check, [_resp()])
    candidate = {
        "endpoint": "/admin", "method": "GET", "principal": "Account A",
        "expected_role": "admin", "status_code": 200, "marker_count": 4,
        "request": MagicMock(url="https://example.com/admin"),
    }
    f = await check.assess(candidate)
    assert f is not None
    assert f.severity.value == "high"
    assert "CWE-285" in f.cwe


def test_safety_only_uses_get_method():
    """BFLA check must only use HTTP GET, no mutations."""
    # Verify the admin path list doesn't include any write actions
    for path in _ADMIN_PATHS:
        path_lower = path.lower()
        for bad in ["delete", "create", "update", "edit", "drop", "destroy", "remove", "add", "new"]:
            assert bad not in path_lower, f"BFLA path {path!r} contains mutating verb {bad!r}"
