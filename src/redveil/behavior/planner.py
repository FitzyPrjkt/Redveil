"""Planner — given a Hypothesis, produce a Test Plan.

A Test Plan is a sequence of (request, expected_signal) steps that, when
executed against the target, will either confirm or refute the Hypothesis.

The Planner is currently a skeleton. Each InvariantKind has a planner
function that builds the test plan. Future expansion: each check can
register its own planner for custom hypothesis kinds.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

from redveil.attack_surface.model import ApplicationModel
from redveil.behavior.hypotheses import Hypothesis, InvariantKind
from redveil.behavior.state import SessionState
from redveil.http.request import Request


@dataclass
class TestStep:
    """One step in a Test Plan."""
    request: Request
    expected_signal: str  # what we expect to see in the response (for differential)
    identity: str | None = None  # which identity to send as
    description: str = ""


@dataclass
class TestPlan:
    """A complete plan to test a Hypothesis.

    The engine executes these steps in order, capturing each response.
    After execution, the responses are diffed against expectations and
    the Hypothesis is marked confirmed/refuted.
    """
    hypothesis: Hypothesis
    steps: list[TestStep] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_empty(self) -> bool:
        return len(self.steps) == 0


def _resolve_path(base_url: str, path_template: str, obj_id: str | None) -> str:
    """Resolve a path template like '/api/orders/{id}' into a full URL."""
    if obj_id and "{" in path_template:
        path = path_template.replace("{id}", obj_id)
    elif obj_id:
        sep = "" if path_template.endswith("/") else "/"
        path = f"{path_template}{sep}{obj_id}"
    else:
        path = path_template
    base = base_url.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return f"{base}{path}"


def plan_for_hypothesis(
    hypothesis: Hypothesis, model: ApplicationModel
) -> TestPlan:
    """Build a Test Plan for the given Hypothesis using the Application Model.

    This is the entry point. Each InvariantKind has its own planner.
    """
    if hypothesis.invariant == InvariantKind.OBJECT_OWNERSHIP:
        return _plan_bola(hypothesis, model)
    if hypothesis.invariant == InvariantKind.FUNCTION_LEVEL_AUTHZ:
        return _plan_bfla(hypothesis, model)
    if hypothesis.invariant == InvariantKind.SESSION_INVALIDATION:
        return _plan_session_invalidation(hypothesis, model)
    if hypothesis.invariant == InvariantKind.TENANT_ISOLATION:
        return _plan_tenant_isolation(hypothesis, model)
    # Default: empty plan
    return TestPlan(hypothesis=hypothesis)


# -- individual planners ------------------------------------------------


def _plan_bola(hyp: Hypothesis, model: ApplicationModel) -> TestPlan:
    """Plan a BOLA test: principal B requests principal A's object."""
    if not (hyp.target_endpoint and hyp.target_object and hyp.target_identity and hyp.second_identity):
        return TestPlan(hypothesis=hyp)

    method, path_template = hyp.target_endpoint
    _, obj_id = hyp.target_object
    url = _resolve_path(model.base_url or "http://x", path_template, obj_id)

    # Step 1: Principal A (owner) requests their own object → expect 200
    step_owner = TestStep(
        request=Request(method=method, url=url, purpose="bola_baseline"),
        expected_signal="200 with object body",
        identity=hyp.target_identity,
        description=f"Owner {hyp.target_identity} requests {hyp.target_object[0]} {obj_id} (baseline)",
    )

    # Step 2: Principal B (attacker) requests A's object → expect 403/404
    step_attacker = TestStep(
        request=Request(method=method, url=url, purpose="bola_test"),
        expected_signal="403 or 404 (BOLA protection)",
        identity=hyp.second_identity,
        description=f"Attacker {hyp.second_identity} requests {hyp.target_object[0]} {obj_id} (test)",
    )

    return TestPlan(
        hypothesis=hyp,
        steps=[step_owner, step_attacker],
        metadata={"comparison": "status_code_diff_or_body_diff"},
    )


def _plan_bfla(hyp: Hypothesis, model: ApplicationModel) -> TestPlan:
    """Plan a BFLA test: low-privilege principal hits admin endpoint."""
    if not (hyp.target_endpoint and hyp.second_identity):
        return TestPlan(hypothesis=hyp)

    method, path_template = hyp.target_endpoint
    url = _resolve_path(model.base_url or "http://x", path_template, None)

    step = TestStep(
        request=Request(method=method, url=url, purpose="bfla_test"),
        expected_signal="403 or 401 (admin-only protection)",
        identity=hyp.second_identity,
        description=f"Low-privilege {hyp.second_identity} requests admin endpoint {path_template}",
    )

    return TestPlan(hypothesis=hyp, steps=[step])


def _plan_session_invalidation(hyp: Hypothesis, model: ApplicationModel) -> TestPlan:
    """Plan a session-invalidation test: after logout, the session should be dead."""
    base = model.base_url or "http://x"
    logout_url = f"{base.rstrip('/')}/auth/logout"
    return TestPlan(
        hypothesis=hyp,
        steps=[
            TestStep(
                request=Request(method="POST", url=logout_url, purpose="logout"),
                expected_signal="200 or 302",
                identity=hyp.target_identity,
                description="Trigger logout",
            ),
        ],
        metadata={"note": "session invalidation is multi-step; see transitions"},
    )


def _plan_tenant_isolation(hyp: Hypothesis, model: ApplicationModel) -> TestPlan:
    """Plan a tenant isolation test: tenant B cannot access tenant A's resource."""
    return TestPlan(hypothesis=hyp, steps=[])
