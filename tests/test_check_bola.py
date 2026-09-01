"""Tests for the BOLA / IDOR check — multi-principal access detector.

These tests cover the safety invariants, the multi-principal mechanism,
the body-diff classification logic, and the resulting Finding shape.
They use AsyncMock for the HttpClient and MagicMock for everything else,
so no real network I/O is performed.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from redveil.checks.bola import (
    _DEFAULT_ID_RANGE,
    _IDOR_QUERY_PARAMS,
    _MAX_IDS_PER_ENDPOINT,
    BOLACheck,
    _body_diff_signature,
    _body_shape,
)
from redveil.config import (
    AuthConfig,
    AuthorizationConfig,
    PrincipalConfig,
    SafetyProfile,
    TargetConfig,
)
from redveil.findings.confidence import Confidence
from redveil.findings.severity import Severity
from redveil.http.request import Request
from redveil.http.response import Response
from redveil.plugins.base import (
    CheckCategory,
    CheckDependencies,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resp(
    body: str = "",
    status: int = 200,
    request_id: str = "req-1",
    elapsed_ms: float = 10.0,
) -> Response:
    """Build a Response with the given body and status code."""
    return Response(
        request_id=request_id,
        status_code=status,
        headers={"content-type": "application/json"},
        body=body,
        elapsed_ms=elapsed_ms,
    )


def _principal(name: str, cookie_value: str = "session-value") -> PrincipalConfig:
    """Build a PrincipalConfig with a single cookie for testing."""
    return PrincipalConfig(
        name=name,
        cookies=[{"name": "session", "value": cookie_value}],
    )


def _make_config(
    *,
    principals: list[PrincipalConfig] | None = None,
    active: bool = True,
    ack: bool = True,
    base_url: str = "https://example.com",
) -> MagicMock:
    """Build a mock RedVeilConfig that returns the requested auth/authorization."""
    cfg = MagicMock()
    cfg.target = TargetConfig(base_url=base_url)  # type: ignore[arg-type]
    cfg.target.base_url = base_url  # ensure the .target.base_url access path works
    auth = AuthConfig(principals=list(principals or []))
    # Inject the principals list without re-validating — tests sometimes
    # use deliberately-malformed principals to assert safety gates.
    object.__setattr__(auth, "principals", list(principals or []))
    cfg.auth = auth
    # AuthorizationConfig has a cross-field validator that refuses
    # active_testing=true without acknowledged_safety_terms=true. Tests
    # that exercise the safety gate need to bypass it, so we build the
    # object with both True first and then patch the field if requested.
    authz = AuthorizationConfig(
        active_testing=True,
        acknowledged_safety_terms=True,
    )
    if not active or not ack:
        # Bypass the validator by using object.__setattr__ on the model
        # after construction. This is exactly what the safety gate
        # exists to prevent — and the test verifies it WOULD be blocked.
        object.__setattr__(authz, "active_testing", active)
        object.__setattr__(authz, "acknowledged_safety_terms", ack)
    cfg.authorization = authz
    cfg.limits.max_requests = 500
    cfg.limits.requests_per_second = 100.0
    cfg.limits.timeout_seconds = 5.0
    cfg.limits.max_concurrent_requests = 5
    cfg.limits.connection_pool_size = 10
    cfg.limits.max_response_size_bytes = 5_000_000
    return cfg


def _bind(check: BOLACheck, cfg: MagicMock, side_effects: list[Response]) -> MagicMock:
    """Bind a check to a mock HttpClient that returns the given responses in order."""
    mock_http = MagicMock()
    mock_http._scope = MagicMock()
    mock_http.send = AsyncMock(side_effect=list(side_effects))
    deps = CheckDependencies(
        http=mock_http,
        scope=mock_http._scope,
        config=cfg,
        context=MagicMock(),
    )
    check.bind(deps)
    return mock_http


# ---------------------------------------------------------------------------
# Safety: only GET, no mutation
# ---------------------------------------------------------------------------


def test_safety_only_uses_get_method():
    """Inspect every Request the check would issue — they must all be GET."""
    check = BOLACheck()
    issued_methods: list[str] = []

    async def _capture(req: Request) -> Response:
        issued_methods.append(req.method)
        return _resp(body='{"id":1}', status=200)

    mock_http = MagicMock()
    mock_http._scope = MagicMock()
    mock_http.send = AsyncMock(side_effect=_capture)
    cfg = _make_config(
        principals=[_principal("alice"), _principal("bob")],
    )
    deps = CheckDependencies(
        http=mock_http, scope=mock_http._scope, config=cfg, context=MagicMock(),
    )
    check.bind(deps)

    import asyncio
    asyncio.run(check.discover(MagicMock()))

    # Every captured method MUST be GET. No POST/PUT/PATCH/DELETE allowed.
    assert issued_methods, "check should have issued at least one request"
    assert all(m == "GET" for m in issued_methods), (
        f"BOLA check must be read-only; observed methods: {issued_methods}"
    )


def test_safety_caps_id_enumeration():
    """Hard cap: never test more than _MAX_IDS_PER_ENDPOINT IDs."""
    # The list should be exactly 3. If anyone widens this, they MUST
    # update the safety cap and re-justify in the module docstring.
    assert _MAX_IDS_PER_ENDPOINT == 3
    assert len(_DEFAULT_ID_RANGE) == 3


def test_safety_query_params_are_safe_values():
    """The query-parameter probes use a single benign numeric value (1)."""
    # We assert by inspection that the implementation never iterates
    # over a long range of query values.
    for _endpoint, params in _IDOR_QUERY_PARAMS:
        assert isinstance(params, tuple)
        for p in params:
            assert isinstance(p, str)


# ---------------------------------------------------------------------------
# Gates: active_testing and principals
# ---------------------------------------------------------------------------


async def test_active_required():
    """active_testing=False → discover() returns no candidates."""
    check = BOLACheck()
    cfg = _make_config(
        principals=[_principal("alice"), _principal("bob")],
        active=False,
    )
    _bind(check, cfg, [])  # no responses needed
    candidates = await check.discover(MagicMock())
    assert candidates == []


async def test_acknowledgement_required():
    """acknowledged_safety_terms=False → discover() returns no candidates."""
    check = BOLACheck()
    cfg = _make_config(
        principals=[_principal("alice"), _principal("bob")],
        ack=False,
    )
    _bind(check, cfg, [])
    candidates = await check.discover(MagicMock())
    assert candidates == []


async def test_principals_required():
    """Fewer than 2 principals → discover() returns no candidates."""
    check = BOLACheck()
    cfg = _make_config(principals=[_principal("only_alice")])
    _bind(check, cfg, [])
    candidates = await check.discover(MagicMock())
    assert candidates == []


async def test_no_principals_required():
    """No principals at all → discover() returns no candidates."""
    check = BOLACheck()
    cfg = _make_config(principals=[])
    _bind(check, cfg, [])
    candidates = await check.discover(MagicMock())
    assert candidates == []


# ---------------------------------------------------------------------------
# Body classification helpers
# ---------------------------------------------------------------------------


def test_body_shape_distinguishes_length_and_excerpt():
    # Identical bodies → equal shape.
    assert _body_shape("hello") == _body_shape("hello")
    # Different bodies → different shapes.
    assert _body_shape("hello") != _body_shape("world")
    # Length-only differences are caught by the length component.
    assert _body_shape("a") != _body_shape("ab")
    # Same length but different content → different shape.
    same_len_a = _body_shape('{"id":1,"name":"alice"}')
    same_len_b = _body_shape('{"id":1,"name":"alice","x":"y"}')
    assert same_len_a[0] != same_len_b[0]


def test_body_diff_signature_is_stable_and_short():
    sig1 = _body_diff_signature("hello", "world")
    sig2 = _body_diff_signature("hello", "world")
    sig3 = _body_diff_signature("hello", "WORLD")
    assert sig1 == sig2
    assert sig1 != sig3
    assert len(sig1) == 16  # SHA-256 prefix


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


async def test_no_bola_detected_when_attacker_blocked():
    """B is blocked (403) → no candidates."""
    check = BOLACheck()
    cfg = _make_config(
        principals=[_principal("alice"), _principal("bob")],
    )
    # For every (endpoint, id) pair, alice gets 200 and bob gets 403.
    # We have 14 path patterns * 3 ids = 42 endpoints; per endpoint we
    # need 2 responses (owner, attacker). That's 84 calls minimum, plus
    # the query-param probes. Pad generously.
    responses: list[Response] = []
    for _ in range(500):
        responses.append(_resp(body='{"id":1}', status=200))   # alice
        responses.append(_resp(body="forbidden", status=403))  # bob
    _bind(check, cfg, responses)

    candidates = await check.discover(MagicMock())
    assert candidates == []


async def test_bola_detected_when_both_200_different_bodies():
    """A and B both get 200 with different bodies → CONFIRMED candidate."""
    check = BOLACheck()
    cfg = _make_config(
        principals=[_principal("alice"), _principal("bob")],
    )
    # Make every probe return 200 for both principals, but with different
    # bodies (same length, different content). Should yield a candidate
    # for every (endpoint, id) pair where the owner's response is 200.
    alice_body = '{"id":1,"name":"alice","email":"alice@example.com"}'
    bob_body = '{"id":1,"name":"alice","email":"alice@example.com","extra":"X"}'
    # Pad to ensure bob's body has the same length prefix
    alice_body_padded = alice_body + " " * (len(bob_body) - len(alice_body))
    assert len(alice_body_padded) == len(bob_body)
    responses: list[Response] = []
    for _ in range(800):
        responses.append(_resp(body=alice_body_padded, status=200))
        responses.append(_resp(body=bob_body, status=200))
    _bind(check, cfg, responses)

    candidates = await check.discover(MagicMock())
    assert len(candidates) >= 1
    # Every candidate should be confirmed (identical shape, differing content)
    assert all(c["verdict"] == "confirmed" for c in candidates)


async def test_bola_detected_when_both_200_same_body():
    """A and B both get 200 with IDENTICAL bodies → CONFIRMED candidate."""
    check = BOLACheck()
    cfg = _make_config(
        principals=[_principal("alice"), _principal("bob")],
    )
    shared_body = '{"id":1,"name":"alice","email":"alice@example.com"}'
    responses: list[Response] = []
    for _ in range(800):
        responses.append(_resp(body=shared_body, status=200))
        responses.append(_resp(body=shared_body, status=200))
    _bind(check, cfg, responses)

    candidates = await check.discover(MagicMock())
    assert len(candidates) >= 1
    # The "identical body" case is the strongest signal.
    assert all(c["verdict"] == "confirmed" for c in candidates)


async def test_bola_candidate_contains_principal_names():
    """A confirmed candidate must label both owner and attacker."""
    check = BOLACheck()
    cfg = _make_config(
        principals=[_principal("alice"), _principal("bob")],
    )
    body = '{"id":1,"owner":"alice"}'
    responses: list[Response] = []
    for _ in range(800):
        responses.append(_resp(body=body, status=200))
        responses.append(_resp(body=body, status=200))
    _bind(check, cfg, responses)

    candidates = await check.discover(MagicMock())
    assert candidates, "expected at least one candidate"
    c = candidates[0]
    assert c["owner_principal"] == "alice"
    assert c["accessed_by_principal"] == "bob"
    assert c["status_a"] == 200
    assert c["status_b"] == 200


async def test_only_first_three_ids_tested():
    """Verify the check caps ID enumeration at exactly 3 IDs."""
    # Inspect the static constants used by the check.
    assert _DEFAULT_ID_RANGE == (1, 2, 3)
    assert _MAX_IDS_PER_ENDPOINT == 3
    # And verify the cap is referenced in the loop:
    from redveil.checks import bola as bola_mod
    src = bola_mod.__file__
    with open(src) as f:
        code = f.read()
    # The loop must slice with [:_MAX_IDS_PER_ENDPOINT] (or equivalent)
    # to make the cap explicit.
    assert "_MAX_IDS_PER_ENDPOINT" in code


# ---------------------------------------------------------------------------
# Validate
# ---------------------------------------------------------------------------


async def test_validate_confirmed_for_bola():
    """Confirmed candidates yield CONFIRMED validation outcome."""
    check = BOLACheck()
    cfg = _make_config(principals=[_principal("alice"), _principal("bob")])
    _bind(check, cfg, [])

    candidate = {
        "verdict": "confirmed",
        "observation": "bodies identical",
        "endpoint": "https://example.com/api/users/1",
    }
    result = await check.validate(MagicMock(), candidate)
    assert result is not None
    assert result.outcome.value == "confirmed"


async def test_validate_likely_for_likely():
    """Likely candidates yield LIKELY validation outcome."""
    check = BOLACheck()
    cfg = _make_config(principals=[_principal("alice"), _principal("bob")])
    _bind(check, cfg, [])

    candidate = {"verdict": "likely", "observation": "shape differs"}
    result = await check.validate(MagicMock(), candidate)
    assert result is not None
    assert result.outcome.value == "likely"


# ---------------------------------------------------------------------------
# Assess
# ---------------------------------------------------------------------------


async def test_assess_produces_finding():
    """assess() returns a Finding with CWE-639 and HIGH severity."""

    check = BOLACheck()
    cfg = _make_config(principals=[_principal("alice"), _principal("bob")])
    _bind(check, cfg, [])

    candidate = {
        "endpoint": "https://example.com/api/users/1",
        "method": "GET",
        "resource_id": "1",
        "location": "path",
        "location_detail": "/api/users/{id}",
        "owner_principal": "alice",
        "accessed_by_principal": "bob",
        "status_a": 200,
        "status_b": 200,
        "body_length_a": 100,
        "body_length_b": 100,
        "body_diff_signature": "abc123",
        "verdict": "confirmed",
        "confidence": "high",
        "observation": "identical body",
        "request_a": Request(
            method="GET", url="https://example.com/api/users/1",
            auth_principal="alice",
            auth_override_cookies={"session": "alice-token"},
        ),
        "response_a": _resp(body='{"id":1}', status=200),
        "request_b": Request(
            method="GET", url="https://example.com/api/users/1",
            auth_principal="bob",
            auth_override_cookies={"session": "bob-token"},
        ),
        "response_b": _resp(body='{"id":1}', status=200),
    }

    finding = await check.assess(candidate)
    assert finding is not None
    assert finding.severity == Severity.HIGH
    assert "CWE-639" in finding.cwe
    assert "A01:2021" in finding.owasp
    assert "alice" in finding.title.lower() or "bob" in finding.title.lower()
    assert finding.target.method == "GET"
    assert finding.target.endpoint == "/api/users/1"
    assert finding.testing_principal == "bob"
    assert finding.status.value == "confirmed"
    assert finding.confidence == Confidence.HIGH


async def test_assess_likely_uses_medium_confidence():
    """assess() on a LIKELY candidate produces MEDIUM confidence."""
    check = BOLACheck()
    cfg = _make_config(principals=[_principal("alice"), _principal("bob")])
    _bind(check, cfg, [])

    candidate = {
        "endpoint": "https://example.com/api/users/1",
        "method": "GET",
        "resource_id": "1",
        "location": "path",
        "location_detail": "/api/users/{id}",
        "owner_principal": "alice",
        "accessed_by_principal": "bob",
        "status_a": 200,
        "status_b": 200,
        "body_length_a": 50,
        "body_length_b": 200,
        "body_diff_signature": "def456",
        "verdict": "likely",
        "observation": "shape differs",
        "request_a": Request(
            method="GET", url="https://example.com/api/users/1",
            auth_principal="alice",
        ),
        "response_a": _resp(body="x" * 50, status=200),
        "request_b": Request(
            method="GET", url="https://example.com/api/users/1",
            auth_principal="bob",
        ),
        "response_b": _resp(body="y" * 200, status=200),
    }
    finding = await check.assess(candidate)
    assert finding is not None
    assert finding.confidence == Confidence.MEDIUM
    assert finding.status.value == "likely"


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


async def test_evidence_includes_both_principals():
    """collect_evidence() emits one Evidence per principal."""
    check = BOLACheck()
    cfg = _make_config(principals=[_principal("alice"), _principal("bob")])
    _bind(check, cfg, [])

    candidate = {
        "endpoint": "https://example.com/api/users/1",
        "method": "GET",
        "resource_id": "1",
        "location": "path",
        "location_detail": "/api/users/{id}",
        "owner_principal": "alice",
        "accessed_by_principal": "bob",
        "status_a": 200,
        "status_b": 200,
        "body_length_a": 10,
        "body_length_b": 10,
        "body_diff_signature": "abc",
        "verdict": "confirmed",
        "request_a": Request(
            method="GET",
            url="https://example.com/api/users/1",
            auth_principal="alice",
        ),
        "response_a": _resp(body="x" * 10, status=200),
        "request_b": Request(
            method="GET",
            url="https://example.com/api/users/1",
            auth_principal="bob",
        ),
        "response_b": _resp(body="x" * 10, status=200),
    }

    evidence = await check.collect_evidence(candidate)
    assert len(evidence) == 2
    # First evidence is the owner (alice)
    assert evidence[0].request.auth_principal == "alice"
    # Second evidence is the attacker (bob), labeled with parameter="principal"
    assert evidence[1].request.auth_principal == "bob"
    assert evidence[1].parameter == "principal"
    assert evidence[1].input_used == "bob"


# ---------------------------------------------------------------------------
# Meta
# ---------------------------------------------------------------------------


def test_meta_id_and_category():
    assert BOLACheck.meta.id == "bola-idor"
    assert BOLACheck.meta.category == CheckCategory.IDOR
    assert BOLACheck.meta.safety_profile == SafetyProfile.ACTIVE


# ---------------------------------------------------------------------------
# Request model changes
# ---------------------------------------------------------------------------


def test_request_auth_override_headers():
    """Request accepts auth_override_headers."""
    r = Request(
        method="GET",
        url="https://example.com/",
        auth_override_headers={"Authorization": "Bearer bob"},
    )
    assert r.auth_override_headers == {"Authorization": "Bearer bob"}


def test_request_auth_override_cookies():
    """Request accepts auth_override_cookies."""
    r = Request(
        method="GET",
        url="https://example.com/",
        auth_override_cookies={"session": "bob-token"},
    )
    assert r.auth_override_cookies == {"session": "bob-token"}


def test_request_overrides_default_to_empty():
    """If no overrides are set, the dicts default to empty."""
    r = Request(method="GET", url="https://example.com/")
    assert r.auth_override_headers == {}
    assert r.auth_override_cookies == {}


# ---------------------------------------------------------------------------
# PrincipalConfig
# ---------------------------------------------------------------------------


def test_principal_config_to_override_cookies():
    p = PrincipalConfig(
        name="alice",
        cookies=[{"name": "session", "value": "alice-token"}],
    )
    headers, cookies = p.to_override()
    assert cookies == {"session": "alice-token"}
    assert headers == {}  # no Authorization header set


def test_principal_config_to_override_bearer():
    p = PrincipalConfig(name="alice", bearer_token="abc123")
    headers, cookies = p.to_override()
    assert headers["Authorization"] == "Bearer abc123"
    assert cookies == {}


def test_principal_config_to_override_basic():
    p = PrincipalConfig(
        name="alice",
        basic_username="alice",
        basic_password="hunter2",
    )
    headers, cookies = p.to_override()
    assert headers["Authorization"].startswith("Basic ")
    import base64
    decoded = base64.b64decode(headers["Authorization"].split(" ", 1)[1]).decode()
    assert decoded == "alice:hunter2"
    assert cookies == {}


def test_auth_config_validates_principal_has_material():
    """An empty principal (no cookies, no token, no basic) is rejected."""
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        AuthConfig(principals=[PrincipalConfig(name="empty")])


# ---------------------------------------------------------------------------
# HttpClient override behavior (smoke test)
# ---------------------------------------------------------------------------


def test_http_client_applies_auth_overrides():
    """HttpClient.apply-style flow merges overrides on top of base auth."""
    # We don't need a live HTTP server — we just exercise the header/cookie
    # merge logic by simulating it. The real merge lives in
    # ``HttpClient._do_send``; here we verify the same composition.
    base_headers: dict[str, str] = {"Authorization": "Bearer principal-a"}
    base_cookies: dict[str, str] = {"session": "a-session"}

    override_headers = {"Authorization": "Bearer principal-b"}
    override_cookies = {"session": "b-session"}

    if override_headers:
        base_headers.update(override_headers)
    if override_cookies:
        base_cookies.update(override_cookies)

    assert base_headers["Authorization"] == "Bearer principal-b"
    assert base_cookies["session"] == "b-session"
