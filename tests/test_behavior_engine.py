"""Tests for the Behavior Engine foundation modules."""
from __future__ import annotations
import pytest
from redveil.attack_surface.endpoint import Endpoint
from redveil.attack_surface.parameter import Parameter, ParamLocation
from redveil.attack_surface.identity import Identity, AuthMethod
from redveil.attack_surface.object import Object
from redveil.attack_surface.trust_boundaries import (
    TrustBoundary, ANONYMOUS_TO_USER, USER_TO_ADMIN, TENANT_A_TO_TENANT_B,
)
from redveil.attack_surface.model import ApplicationModel
from redveil.behavior.state import SessionState, State, StateHistory
from redveil.behavior.transitions import Transition, TransitionKind, DEFAULT_TRANSITIONS
from redveil.behavior.hypotheses import Hypothesis, InvariantKind
from redveil.behavior.planner import TestPlan, TestStep, plan_for_hypothesis
from redveil.behavior.differential import DifferentialResult, compute_differential
from redveil.behavior.model import BehaviorModel
from redveil.http.response import Response


# ---------------------------------------------------------------------------
# attack_surface
# ---------------------------------------------------------------------------


def test_endpoint_signature():
    ep = Endpoint(method="GET", path="/api/users/{id}")
    assert ep.signature == "GET /api/users/{id}"
    ep2 = Endpoint(method="get", path="/api/users/{id}")
    assert ep == ep2  # method comparison is case-insensitive


def test_endpoint_with_params():
    ep = Endpoint(method="GET", path="/api/users")
    p = Parameter(name="q", location=ParamLocation.QUERY)
    new_ep = ep.with_params([p])
    assert new_ep.has_parameters
    assert new_ep.parameters[0].name == "q"


def test_parameter_is_security_relevant():
    p_safe = Parameter(name="limit", location=ParamLocation.QUERY)
    p_risky = Parameter(name="user_id", location=ParamLocation.PATH)
    p_token = Parameter(name="apikey", location=ParamLocation.QUERY)
    assert not p_safe.is_security_relevant
    assert p_risky.is_security_relevant
    assert p_token.is_security_relevant


def test_identity_to_override_bearer():
    i = Identity(
        name="alice",
        role="user",
        auth_method=AuthMethod.BEARER,
        bearer_token="tok123",
    )
    headers, cookies = i.to_override()
    assert headers["Authorization"] == "Bearer tok123"
    assert cookies == {}


def test_identity_to_override_basic():
    import base64
    i = Identity(
        name="alice",
        auth_method=AuthMethod.BASIC,
        basic_user="alice",
        basic_pass="secret",
    )
    headers, cookies = i.to_override()
    expected = "Basic " + base64.b64encode(b"alice:secret").decode()
    assert headers["Authorization"] == expected


def test_object_ownership():
    obj = Object(type="order", id="123", owner_id="alice")
    assert obj.is_owned_by("alice")
    assert not obj.is_owned_by("bob")


def test_trust_boundary_allowed():
    b = TrustBoundary(name="test", from_zone="u", to_zone="a", allowed=frozenset({"admin"}))
    assert b.is_allowed("admin")
    assert not b.is_allowed("user")


def test_application_model_add_and_query():
    m = ApplicationModel(target_name="test", base_url="https://test")
    m.add_endpoint(Endpoint(method="GET", path="/api/users"))
    m.add_identity(Identity(name="alice", role="user"))
    m.add_object(Object(type="order", id="1", owner_id="alice"))
    m.add_object(Object(type="order", id="2", owner_id="bob"))
    m.add_trust_boundary(USER_TO_ADMIN)

    assert m.summary() == {
        "endpoints": 1, "identities": 1, "objects": 2, "trust_boundaries": 1,
    }
    assert m.get_endpoint("GET", "/api/users") is not None
    assert len(m.find_objects_owned_by("alice")) == 1
    assert len(m.find_objects_not_owned_by("alice")) == 1


# ---------------------------------------------------------------------------
# behavior.state
# ---------------------------------------------------------------------------


def test_state_history_transitions():
    h = StateHistory()
    h.append(State(session_state=SessionState.ANONYMOUS, identity="alice"))
    h.append(State(session_state=SessionState.AUTHENTICATED, identity="alice"))
    h.append(State(session_state=SessionState.INVALIDATED, identity="alice"))

    assert h.has_transition(SessionState.ANONYMOUS, SessionState.AUTHENTICATED)
    assert h.has_transition(SessionState.AUTHENTICATED, SessionState.INVALIDATED)
    assert not h.has_transition(SessionState.ANONYMOUS, SessionState.ELEVATED)


# ---------------------------------------------------------------------------
# behavior.hypotheses
# ---------------------------------------------------------------------------


def test_hypothesis_creation():
    h = Hypothesis(
        id="bola-orders-1",
        invariant=InvariantKind.OBJECT_OWNERSHIP,
        statement="User B should not access User A's order 1",
        target_endpoint=("GET", "/api/orders/{id}"),
        target_object=("order", "1"),
        target_identity="alice",
        second_identity="bob",
    )
    assert h.invariant == InvariantKind.OBJECT_OWNERSHIP
    assert h.target_identity == "alice"
    assert h.second_identity == "bob"


# ---------------------------------------------------------------------------
# behavior.planner
# ---------------------------------------------------------------------------


def test_plan_bola_produces_two_steps():
    model = ApplicationModel(base_url="https://x")
    model.add_identity(Identity(name="alice", role="user"))
    model.add_identity(Identity(name="bob", role="user"))
    model.add_object(Object(type="order", id="1", owner_id="alice"))
    model.add_endpoint(Endpoint(method="GET", path="/api/orders/{id}"))

    hyp = Hypothesis(
        id="bola-1",
        invariant=InvariantKind.OBJECT_OWNERSHIP,
        statement="bob should not see alice's order",
        target_endpoint=("GET", "/api/orders/{id}"),
        target_object=("order", "1"),
        target_identity="alice",
        second_identity="bob",
    )
    plan = plan_for_hypothesis(hyp, model)
    assert not plan.is_empty
    assert len(plan.steps) == 2  # owner baseline + attacker test
    assert plan.steps[0].identity == "alice"
    assert plan.steps[1].identity == "bob"


def test_plan_bfla_single_step():
    model = ApplicationModel(base_url="https://x")
    model.add_identity(Identity(name="alice", role="user"))

    hyp = Hypothesis(
        id="bfla-1",
        invariant=InvariantKind.FUNCTION_LEVEL_AUTHZ,
        statement="alice (user) should not hit admin endpoint",
        target_endpoint=("GET", "/api/admin/users"),
        second_identity="alice",
    )
    plan = plan_for_hypothesis(hyp, model)
    assert not plan.is_empty
    assert plan.steps[0].identity == "alice"


def test_plan_returns_empty_for_incomplete_inputs():
    model = ApplicationModel()
    hyp = Hypothesis(
        id="x", invariant=InvariantKind.OBJECT_OWNERSHIP, statement="x",
    )
    plan = plan_for_hypothesis(hyp, model)
    assert plan.is_empty


# ---------------------------------------------------------------------------
# behavior.differential
# ---------------------------------------------------------------------------


def _resp(status=200, body="ok", elapsed=10.0):
    return Response(
        request_id="r", status_code=status, headers={}, body=body, elapsed_ms=elapsed,
    )


def test_differential_status_diff():
    baseline = _resp(status=200)
    controlled = _resp(status=403)
    diff = compute_differential(baseline, controlled)
    assert diff.status_diff == 403 - 200  # 203
    assert diff.is_meaningful()


def test_differential_body_diff():
    baseline = _resp(body="alice owns this")
    controlled = _resp(body="bob owns this")
    diff = compute_differential(baseline, controlled)
    assert diff.body_content_diff
    assert diff.is_meaningful()


def test_differential_no_meaningful_diff():
    baseline = _resp(status=200, body="ok", elapsed=10.0)
    controlled = _resp(status=200, body="ok", elapsed=11.0)
    diff = compute_differential(baseline, controlled)
    assert not diff.is_meaningful()


def test_differential_timing_threshold():
    baseline = _resp(elapsed=50.0)
    controlled = _resp(elapsed=3000.0)  # 2.95s diff
    diff = compute_differential(baseline, controlled)
    assert diff.timing_diff_ms > 1000.0
    assert diff.is_meaningful()


# ---------------------------------------------------------------------------
# behavior.model
# ---------------------------------------------------------------------------


def test_behavior_model_declare_hypothesis():
    model = ApplicationModel(base_url="https://x")
    model.add_identity(Identity(name="alice"))
    bm = BehaviorModel(application_model=model)
    hyp = bm.declare_hypothesis(
        id="x",
        invariant=InvariantKind.OBJECT_OWNERSHIP,
        statement="alice can only see her own data",
    )
    assert hyp.id == "x"
    assert hyp.invariant == InvariantKind.OBJECT_OWNERSHIP


def test_behavior_model_plan():
    model = ApplicationModel(base_url="https://x")
    model.add_identity(Identity(name="alice"))
    bm = BehaviorModel(application_model=model)
    hyp = bm.declare_hypothesis(
        id="x",
        invariant=InvariantKind.OBJECT_OWNERSHIP,
        statement="x",
    )
    plan = bm.plan(hyp)
    # Empty because no target_endpoint/object provided, but the plan was built
    assert plan.hypothesis == hyp


def test_behavior_model_state_recording():
    model = ApplicationModel()
    bm = BehaviorModel(application_model=model)
    bm.record_state(State(session_state=SessionState.ANONYMOUS))
    bm.record_state(State(session_state=SessionState.AUTHENTICATED))
    assert bm.current_state() == SessionState.AUTHENTICATED
    assert bm.current_state(identity="alice") == SessionState.UNKNOWN
