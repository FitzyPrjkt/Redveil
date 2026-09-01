"""Tests for Wave 7: Risk model + ActionGate + progressive validation."""
from __future__ import annotations
import io
import pytest
from redveil.validation.risk import (
    Risk, ActionPlan, ProgressiveLevel, ValidationStep, CATEGORY_RISK,
)
from redveil.validation.gate import ActionGate, GateMode, GateDecision


# ---------------------------------------------------------------------------
# Risk enum
# ---------------------------------------------------------------------------


def test_risk_ordering():
    """Risks are ordered so we can compare."""
    assert Risk.NONE < Risk.LOW
    assert Risk.LOW < Risk.MEDIUM
    assert Risk.MEDIUM < Risk.HIGH
    assert Risk.HIGH < Risk.BLOCKED


def test_risk_blocked_is_sentinel():
    """BLOCKED is far above HIGH to ensure it's never accidentally approved."""
    assert Risk.BLOCKED > Risk.HIGH
    assert Risk.BLOCKED.value > 90


# ---------------------------------------------------------------------------
# ActionPlan
# ---------------------------------------------------------------------------


def test_action_plan_is_safe_to_auto_approve():
    """NONE and LOW risk plans can run without user confirmation."""
    p_none = ActionPlan(action_id="x", description="x", risk=Risk.NONE,
                        target="https://t.com", purpose="x", expected_effect="x")
    p_low = ActionPlan(action_id="x", description="x", risk=Risk.LOW,
                       target="https://t.com", purpose="x", expected_effect="x")
    p_med = ActionPlan(action_id="x", description="x", risk=Risk.MEDIUM,
                       target="https://t.com", purpose="x", expected_effect="x")
    assert p_none.is_safe_to_auto_approve()
    assert p_low.is_safe_to_auto_approve()
    assert not p_med.is_safe_to_auto_approve()


def test_action_plan_destructive_never_safe():
    """Even a NONE risk plan with destructive=True is not auto-safe."""
    p = ActionPlan(action_id="x", description="x", risk=Risk.NONE,
                   target="https://t.com", purpose="x", expected_effect="x",
                   destructive=True)
    assert not p.is_safe_to_auto_approve()


def test_action_plan_render_for_user():
    """The render format includes key fields: risk, target, purpose, limits."""
    plan = ActionPlan(
        action_id="bola-orders-1",
        description="request order as principal B",
        risk=Risk.MEDIUM,
        target="https://target.example.com/api/orders/1",
        purpose="verify principal B can access principal A's order",
        expected_effect="403 or 404 (object ownership enforced)",
        potential_side_effects=("logged in access.log",),
        max_requests=2,
        timeout_seconds=10.0,
    )
    rendered = plan.render_for_user()
    assert "MEDIUM" in rendered
    assert "https://target.example.com/api/orders/1" in rendered
    assert "verify principal B" in rendered
    assert "logged in access.log" in rendered
    assert "y/N" in rendered


# ---------------------------------------------------------------------------
# Category → Risk mapping
# ---------------------------------------------------------------------------


def test_category_risk_xss_is_low():
    assert CATEGORY_RISK["xss"] == Risk.LOW
    assert CATEGORY_RISK["sqli"] == Risk.LOW
    assert CATEGORY_RISK["ssrf"] == Risk.LOW


def test_category_risk_bola_is_medium():
    """Multi-principal auth tests are medium risk."""
    assert CATEGORY_RISK["idor"] == Risk.MEDIUM
    assert CATEGORY_RISK["bfla"] == Risk.MEDIUM


def test_category_risk_passive_categories_are_none():
    assert CATEGORY_RISK["headers"] == Risk.NONE
    assert CATEGORY_RISK["cors"] == Risk.NONE
    assert CATEGORY_RISK["disclosure"] == Risk.LOW


# ---------------------------------------------------------------------------
# ProgressiveLevel
# ---------------------------------------------------------------------------


def test_validation_step_can_run_when_preconditions_met():
    step = ValidationStep(
        level=ProgressiveLevel.LEVEL_2,
        plan=ActionPlan(action_id="x", description="x", risk=Risk.MEDIUM,
                        target="https://t.com", purpose="x", expected_effect="x"),
        preconditions=("passive_observation_complete", "low_impact_probes_complete"),
    )
    evidence = {"passive_observation_complete": True, "low_impact_probes_complete": True}
    assert step.can_run(evidence)


def test_validation_step_cannot_run_when_preconditions_missing():
    step = ValidationStep(
        level=ProgressiveLevel.LEVEL_2,
        plan=ActionPlan(action_id="x", description="x", risk=Risk.MEDIUM,
                        target="https://t.com", purpose="x", expected_effect="x"),
        preconditions=("low_impact_probes_complete",),
    )
    evidence = {}  # missing precondition
    assert not step.can_run(evidence)


# ---------------------------------------------------------------------------
# ActionGate — modes
# ---------------------------------------------------------------------------


def test_gate_non_interactive_auto_approves():
    gate = ActionGate(mode=GateMode.NON_INTERACTIVE)
    plan = ActionPlan(action_id="x", description="x", risk=Risk.HIGH,
                      target="https://t.com", purpose="x", expected_effect="x")
    decision = gate.ask(plan)
    assert decision
    assert "non-interactive" in decision.reason


def test_gate_strict_denies_medium():
    """Strict mode: auto-deny MEDIUM+ regardless of pre-approval."""
    gate = ActionGate(mode=GateMode.STRICT)
    plan = ActionPlan(action_id="x", description="x", risk=Risk.MEDIUM,
                      target="https://t.com", purpose="x", expected_effect="x")
    decision = gate.ask(plan)
    assert not decision
    assert "strict" in decision.reason


def test_gate_strict_allows_low():
    gate = ActionGate(mode=GateMode.STRICT)
    plan = ActionPlan(action_id="x", description="x", risk=Risk.LOW,
                      target="https://t.com", purpose="x", expected_effect="x")
    decision = gate.ask(plan)
    assert decision


def test_gate_blocks_destructive_in_non_interactive_even_with_unlock():
    """Destructive actions are NEVER auto-approved, even with allow_destructive=True.
    Each one needs explicit user confirmation per-action — no Y-to-all."""
    gate = ActionGate(mode=GateMode.NON_INTERACTIVE)
    plan = ActionPlan(
        action_id="x", description="x", risk=Risk.LOW,
        target="https://t.com", purpose="x", expected_effect="x",
        destructive=True,
    )
    # allow_destructive=True but mode is non-interactive → still denied
    decision = gate.ask(plan, allow_destructive=True)
    assert not decision
    assert "non-interactive" in decision.reason


def test_gate_destructive_requires_explicit_i_accept_risk():
    """Destructive in interactive mode requires 'I-accept-risk' string."""
    fake_stdin = io.StringIO("y\n")  # plain 'y' should NOT work
    fake_stdout = io.StringIO()
    gate = ActionGate(
        mode=GateMode.INTERACTIVE, stdin=fake_stdin, stdout=fake_stdout,
    )
    plan = ActionPlan(
        action_id="x", description="x", risk=Risk.MEDIUM,
        target="https://t.com", purpose="x", expected_effect="x",
        destructive=True,
    )
    decision = gate.ask(plan, allow_destructive=True)
    assert not decision  # 'y' alone is not enough


def test_gate_destructive_approved_with_explicit_string():
    """Destructive in interactive mode approved only with 'I-accept-risk'."""
    fake_stdin = io.StringIO("I-accept-risk\n")
    fake_stdout = io.StringIO()
    gate = ActionGate(
        mode=GateMode.INTERACTIVE, stdin=fake_stdin, stdout=fake_stdout,
    )
    plan = ActionPlan(
        action_id="x", description="x", risk=Risk.MEDIUM,
        target="https://t.com", purpose="x", expected_effect="x",
        destructive=True,
    )
    decision = gate.ask(plan, allow_destructive=True)
    assert decision


def test_gate_no_y_to_all():
    """Two destructive actions in a row: each must be confirmed separately."""
    fake_stdin = io.StringIO("I-accept-risk\nn\n")  # first yes, second no
    fake_stdout = io.StringIO()
    gate = ActionGate(
        mode=GateMode.INTERACTIVE, stdin=fake_stdin, stdout=fake_stdout,
    )
    plan1 = ActionPlan(action_id="1", description="d1", risk=Risk.HIGH,
                       target="https://t.com", purpose="x", expected_effect="x",
                       destructive=True)
    plan2 = ActionPlan(action_id="2", description="d2", risk=Risk.HIGH,
                       target="https://t.com", purpose="x", expected_effect="x",
                       destructive=True)
    d1 = gate.ask(plan1, allow_destructive=True)
    d2 = gate.ask(plan2, allow_destructive=True)
    assert d1  # first approved
    assert not d2  # second denied (user said n)
    # The gate prompts for BOTH, no batch approval
    assert len(gate.history) == 2


def test_gate_blocks_destructive_when_unlock_disabled():
    """When allow_destructive=False, destructive is always denied."""
    gate = ActionGate(mode=GateMode.INTERACTIVE,
                      stdin=io.StringIO("I-accept-risk\n"),
                      stdout=io.StringIO())
    plan = ActionPlan(
        action_id="x", description="x", risk=Risk.MEDIUM,
        target="https://t.com", purpose="x", expected_effect="x",
        destructive=True,
    )
    decision = gate.ask(plan, allow_destructive=False)
    assert not decision
    assert "allow_destructive" in decision.reason


def test_gate_blocks_risk_blocked_sentinel():
    """Risk.BLOCKED is the sentinel that always denies."""
    gate = ActionGate(mode=GateMode.NON_INTERACTIVE)
    plan = ActionPlan(action_id="x", description="x", risk=Risk.BLOCKED,
                      target="https://t.com", purpose="x", expected_effect="x")
    decision = gate.ask(plan, allow_destructive=True)
    assert not decision


def test_gate_interactive_yes_approves():
    """In interactive mode, 'y' from stdin = approve."""
    fake_stdin = io.StringIO("y\n")
    fake_stdout = io.StringIO()
    gate = ActionGate(
        mode=GateMode.INTERACTIVE, stdin=fake_stdin, stdout=fake_stdout,
    )
    plan = ActionPlan(action_id="x", description="x", risk=Risk.MEDIUM,
                      target="https://t.com", purpose="x", expected_effect="x")
    decision = gate.ask(plan)
    assert decision
    assert "approved" in decision.reason
    # The plan was rendered to stdout
    assert "MEDIUM" in fake_stdout.getvalue()


def test_gate_interactive_no_denies():
    fake_stdin = io.StringIO("n\n")
    fake_stdout = io.StringIO()
    gate = ActionGate(
        mode=GateMode.INTERACTIVE, stdin=fake_stdin, stdout=fake_stdout,
    )
    plan = ActionPlan(action_id="x", description="x", risk=Risk.MEDIUM,
                      target="https://t.com", purpose="x", expected_effect="x")
    decision = gate.ask(plan)
    assert not decision


def test_gate_interactive_default_deny_on_empty_input():
    """In interactive mode, default (empty input) = deny."""
    fake_stdin = io.StringIO("\n")  # just newline
    fake_stdout = io.StringIO()
    gate = ActionGate(
        mode=GateMode.INTERACTIVE, stdin=fake_stdin, stdout=fake_stdout,
    )
    plan = ActionPlan(action_id="x", description="x", risk=Risk.MEDIUM,
                      target="https://t.com", purpose="x", expected_effect="x")
    decision = gate.ask(plan)
    assert not decision


def test_gate_history_is_recorded():
    gate = ActionGate(mode=GateMode.NON_INTERACTIVE)
    for _ in range(3):
        plan = ActionPlan(action_id="x", description="x", risk=Risk.LOW,
                          target="https://t.com", purpose="x", expected_effect="x")
        gate.ask(plan)
    assert len(gate.history) == 3


# ---------------------------------------------------------------------------
# Integration: the gate does NOT bypass safety
# ---------------------------------------------------------------------------


def test_gate_approval_does_not_imply_no_limits():
    """The gate approves, but the engine still enforces scope + limits.
    This is a documentation test: the gate never claims to bypass safety.
    """
    plan = ActionPlan(
        action_id="x", description="x", risk=Risk.MEDIUM,
        target="https://t.com", purpose="x", expected_effect="x",
        max_requests=2,
        timeout_seconds=10.0,
    )
    rendered = plan.render_for_user()
    # The render explicitly mentions the limits
    assert "2 request(s) max" in rendered
    assert "10s timeout" in rendered
    # And explicitly says no destructive operations
    assert "no destructive operations" in rendered
