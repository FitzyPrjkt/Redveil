"""BehaviorModel — the reasoning layer that ties model + state + hypotheses + planner together.

A BehaviorModel wraps an ApplicationModel and provides high-level methods
that checks can use to declare and test hypotheses without writing the
test logic themselves. This is the public API for plugins.

The current implementation is a skeleton. As we add more checks, they
declare their hypotheses here; the engine plans + executes + diffs.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Callable

from redveil.attack_surface.model import ApplicationModel
from redveil.behavior.differential import DifferentialResult, compute_differential
from redveil.behavior.hypotheses import Hypothesis, InvariantKind
from redveil.behavior.planner import TestPlan, plan_for_hypothesis
from redveil.behavior.state import SessionState, State, StateHistory
from redveil.http.request import Request
from redveil.http.response import Response


@dataclass
class BehaviorModel:
    """The reasoning layer for security testing.

    Holds the ApplicationModel + StateHistory and exposes high-level
    methods for checks to declare and execute hypotheses.
    """
    application_model: ApplicationModel
    state_history: StateHistory = field(default_factory=StateHistory)
    # The HTTP client is injected at runtime (not at construction) so the
    # BehaviorModel can be created during config loading without deps.
    _http: Any = field(default=None, repr=False)

    def attach_http(self, http) -> None:
        """Inject the HTTP client (used by execute_plan)."""
        self._http = http

    # -- state tracking -------------------------------------------------

    def record_state(self, state: State) -> None:
        """Append a State to the history (e.g., after observing a response)."""
        self.state_history.append(state)

    def current_state(self, identity: str | None = None) -> SessionState:
        """Return the most recent SessionState (optionally for a specific identity)."""
        for s in reversed(self.state_history.states):
            if identity is None or s.identity == identity:
                return s.session_state
        return SessionState.UNKNOWN

    # -- hypotheses ------------------------------------------------------

    def declare_hypothesis(
        self,
        id: str,
        invariant: InvariantKind,
        statement: str,
        target_endpoint: tuple[str, str] | None = None,
        target_object: tuple[str, str] | None = None,
        target_identity: str | None = None,
        second_identity: str | None = None,
    ) -> Hypothesis:
        """Declare a hypothesis to be tested.

        Returns the Hypothesis. The caller can then call `plan(hypothesis)`
        to get a TestPlan, or `execute(hypothesis)` to plan + run + diff.
        """
        return Hypothesis(
            id=id,
            invariant=invariant,
            statement=statement,
            target_endpoint=target_endpoint,
            target_object=target_object,
            target_identity=target_identity,
            second_identity=second_identity,
        )

    def plan(self, hypothesis: Hypothesis) -> TestPlan:
        """Build a Test Plan for a Hypothesis."""
        return plan_for_hypothesis(hypothesis, self.application_model)

    async def execute(self, hypothesis: Hypothesis) -> list[DifferentialResult]:
        """Plan + execute + return differential results.

        Each step is sent via the HTTP client. The responses are diffed
        against the expected signal. The caller interprets the results.
        """
        plan = self.plan(hypothesis)
        results: list[DifferentialResult] = []
        if plan.is_empty or self._http is None:
            return results
        baseline_resp: Response | None = None
        for i, step in enumerate(plan.steps):
            try:
                resp = await self._http.send(step.request)
            except Exception:
                continue
            if i == 0:
                baseline_resp = resp
            else:
                if baseline_resp is not None:
                    diff = compute_differential(
                        baseline_resp, resp, expected_signal=step.expected_signal
                    )
                    results.append(diff)
        return results
