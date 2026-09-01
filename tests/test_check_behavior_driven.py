"""Tests for the BehaviorModel-driven checks (BFLA via behavior + Session Invalidation)."""
import pytest
from unittest.mock import AsyncMock, MagicMock
from redveil.checks.bfla_behavior import BFLABehaviorCheck
from redveil.checks.session_invalidation import SessionInvalidationCheck
from redveil.attack_surface.identity import Identity, AuthMethod
from redveil.attack_surface.model import ApplicationModel
from redveil.http.response import Response
from redveil.http.request import Request
from redveil.plugins.base import CheckDependencies


def _resp(status=200, body="", headers=None, elapsed=10.0):
    return Response(
        request_id="r", status_code=status, headers=headers or {}, body=body, elapsed_ms=elapsed,
    )


def _bind(check, side_effects, with_model=True, active=True, ack=True):
    """Bind a check with mock http + config + optionally an ApplicationModel."""
    mock_http = MagicMock()
    mock_http._scope = MagicMock()
    cfg = MagicMock()
    cfg.target.base_url = "https://example.com"
    cfg.authorization.active_testing = active
    cfg.authorization.acknowledged_safety_terms = ack
    cfg.auth.principals = []
    mock_http.send = AsyncMock(side_effect=side_effects)
    deps = CheckDependencies(
        http=mock_http,
        scope=mock_http._scope,
        config=cfg,
        context=MagicMock(),
    )
    check.bind(deps)
    if with_model:
        # Inject an ApplicationModel
        from redveil.attack_surface.model import ApplicationModel
        model = ApplicationModel(base_url="https://example.com")
        model.add_identity(Identity(name="alice", role="user", auth_method=AuthMethod.COOKIE, cookies={"session": "abc"}))
        deps.application_model = model
    return mock_http


# ---------------------------------------------------------------------------
# BFLABehaviorCheck
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bfla_active_required():
    check = BFLABehaviorCheck()
    _bind(check, [], active=False)
    cands = await check.discover(MagicMock())
    assert cands == []


@pytest.mark.asyncio
async def test_bfla_no_model_no_findings():
    check = BFLABehaviorCheck()
    _bind(check, [], with_model=False)
    cands = await check.discover(MagicMock())
    assert cands == []


@pytest.mark.asyncio
async def test_bfla_admin_endpoint_accessible():
    check = BFLABehaviorCheck()
    # 200 OK on /admin → finding
    side_effects = [_resp(status=200, body="admin panel")]
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    assert len(cands) >= 1
    assert any(c["endpoint"] == "/admin" for c in cands)


@pytest.mark.asyncio
async def test_bfla_admin_endpoint_blocked():
    check = BFLABehaviorCheck()
    side_effects = [_resp(status=403) for _ in range(30)]
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    assert all(c.get("actual_status") != 200 for c in cands)


@pytest.mark.asyncio
async def test_bfla_assess_produces_finding():
    check = BFLABehaviorCheck()
    _bind(check, [_resp()])
    candidate = {
        "endpoint": "/admin",
        "url": "https://example.com/admin",
        "principal": "alice",
        "expected_signal": "403 or 401",
        "actual_status": 200,
        "request": MagicMock(url="https://example.com/admin"),
        "response": _resp(status=200),
        "hypothesis": MagicMock(),
    }
    f = await check.assess(candidate)
    assert f is not None
    assert f.severity.value == "high"
    assert "CWE-285" in f.cwe


def test_bfla_safety_no_mutating_methods():
    """The BFLA check must use only GET, never POST/PUT/DELETE."""
    import inspect
    src = inspect.getsource(BFLABehaviorCheck.discover)
    assert 'method="GET"' in src or "method='GET'" in src
    for bad in ['method="POST"', 'method="PUT"', 'method="PATCH"', 'method="DELETE"']:
        assert bad not in src, f"BFLA uses {bad}"


# ---------------------------------------------------------------------------
# SessionInvalidationCheck
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_session_invalidation_active_required():
    check = SessionInvalidationCheck()
    _bind(check, [], active=False)
    cands = await check.discover(MagicMock())
    assert cands == []


@pytest.mark.asyncio
async def test_session_invalidation_no_model():
    check = SessionInvalidationCheck()
    _bind(check, [], with_model=False)
    cands = await check.discover(MagicMock())
    assert cands == []


@pytest.mark.asyncio
async def test_session_invalidation_properly_invalidated():
    """Logout followed by probe → 401 = OK, no finding."""
    check = SessionInvalidationCheck()
    # 1. Auth probe: 200
    # 2. Logout: 200
    # 3. Post-logout probe: 401
    side_effects = [
        _resp(status=200, body="welcome"),  # auth probe
        _resp(status=200, body="ok"),         # logout
        _resp(status=401, body="unauth"),     # post-logout probe
    ]
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    assert cands == []


@pytest.mark.asyncio
async def test_session_invalidation_NOT_invalidated_detected():
    """Logout followed by probe → 200 = BUG, session still valid."""
    check = SessionInvalidationCheck()
    # All return 200 → session not invalidated
    side_effects = [
        _resp(status=200, body="welcome"),
        _resp(status=200, body="ok"),
        _resp(status=200, body="still here"),
    ]
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    assert len(cands) >= 1
    c = cands[0]
    assert c["status_after_logout"] == 200
    assert c["principal"] == "alice"


@pytest.mark.asyncio
async def test_session_invalidation_assess_produces_finding():
    check = SessionInvalidationCheck()
    _bind(check, [_resp()])
    candidate = {
        "principal": "alice",
        "logout_path": "/logout",
        "probe_path": "/api/me",
        "status_after_logout": 200,
        "request": MagicMock(url="https://example.com/api/me"),
        "response": _resp(status=200),
    }
    f = await check.assess(candidate)
    assert f is not None
    assert f.severity.value == "high"
    assert "CWE-613" in f.cwe or "CWE-384" in f.cwe


def test_session_invalidation_safety_no_destructive_methods():
    """The session-invalidation check may POST to /logout, but never DELETE/modify data."""
    import inspect
    src = inspect.getsource(SessionInvalidationCheck.discover)
    # Should use POST for logout
    assert 'method="POST"' in src
    # No DELETE, PUT (other than POST) for actual content mutation
    for bad in ['method="DELETE"', 'method="PUT"', 'method="PATCH"']:
        assert bad not in src, f"Session check uses {bad}"
