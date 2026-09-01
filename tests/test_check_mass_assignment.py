"""Tests for MassAssignmentCheck."""
from unittest.mock import AsyncMock, MagicMock

import pytest

from redveil.checks.mass_assignment import MassAssignmentCheck
from redveil.http.response import Response
from redveil.plugins.base import CheckDependencies


def _resp(body: str = "", status: int = 200, headers: dict = None):
    return Response(request_id="r1", status_code=status, headers=headers or {"content-type": "application/json"}, body=body, elapsed_ms=10.0)


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
async def test_no_endpoint_no_finding():
    check = MassAssignmentCheck()
    notfound = _resp(status=404, body="not found")
    _bind(check, [notfound] * 30)
    cands = await check.discover(MagicMock())
    assert cands == []


@pytest.mark.asyncio
async def test_safe_response_no_finding():
    check = MassAssignmentCheck()
    safe = _resp(status=200, body='{"name": "alice", "email": "alice@example.com"}')
    _bind(check, [safe] * 30)
    cands = await check.discover(MagicMock())
    assert cands == []


@pytest.mark.asyncio
async def test_is_admin_field_flagged():
    check = MassAssignmentCheck()
    body = '{"name": "alice", "is_admin": false, "role": "user"}'
    resp = _resp(status=200, body=body)
    _bind(check, [resp] * 30)
    cands = await check.discover(MagicMock())
    sensitive_fields = {c["field"] for c in cands}
    assert "is_admin" in sensitive_fields
    assert "role" in sensitive_fields


@pytest.mark.asyncio
async def test_balance_field_flagged():
    check = MassAssignmentCheck()
    body = '{"name": "alice", "balance": 1000, "credit_limit": 5000}'
    resp = _resp(status=200, body=body)
    _bind(check, [resp] * 30)
    cands = await check.discover(MagicMock())
    sensitive_fields = {c["field"] for c in cands}
    assert "balance" in sensitive_fields
    assert "credit_limit" in sensitive_fields


@pytest.mark.asyncio
async def test_nested_fields_walked():
    check = MassAssignmentCheck()
    body = '{"user": {"name": "alice", "is_admin": false, "tenant_id": "t1"}}'
    resp = _resp(status=200, body=body)
    _bind(check, [resp] * 30)
    cands = await check.discover(MagicMock())
    fields = {c["field"] for c in cands}
    assert "is_admin" in fields
    assert "tenant_id" in fields


@pytest.mark.asyncio
async def test_validate_likely():
    check = MassAssignmentCheck()
    _bind(check, [_resp()])
    from redveil.findings.severity import Severity
    candidate = {"endpoint": "/api/me", "field": "is_admin", "sensitivity": "admin", "severity": Severity.HIGH}
    result = await check.validate(MagicMock(), candidate)
    assert result.outcome.value in {"likely", "confirmed"}


@pytest.mark.asyncio
async def test_assess_produces_finding():
    check = MassAssignmentCheck()
    _bind(check, [_resp()])
    from redveil.findings.severity import Severity
    candidate = {
        "endpoint": "/api/me", "method": "GET", "field": "is_admin",
        "field_path": "is_admin", "sensitivity": "admin", "severity": Severity.HIGH,
        "request": MagicMock(url="https://example.com/api/me"),
    }
    f = await check.assess(candidate)
    assert f is not None
    assert f.severity.value == "high"
    assert "CWE-915" in f.cwe


def test_safety_no_write_methods():
    """Mass assignment check is passive — only GET requests."""
    # The check code uses Request(method="GET", ...) — verify by inspection
    import inspect

    from redveil.checks.mass_assignment import MassAssignmentCheck
    source = inspect.getsource(MassAssignmentCheck.discover)
    # Only "GET" should appear as method
    assert "method=\"GET\"" in source
    # No POST, PUT, PATCH, DELETE
    for bad in ["method=\"POST\"", "method=\"PUT\"", "method=\"PATCH\"", "method=\"DELETE\""]:
        assert bad not in source, f"MassAssignmentCheck uses {bad}"
