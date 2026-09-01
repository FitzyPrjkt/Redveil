"""Tests for Wave 12: DestructiveLevel + tiered confirmation."""
import pytest
from redveil.validation.risk import (
    Risk, DestructiveLevel, ActionPlan,
)
from redveil.validation.gate import ActionGate, GateMode, GateDecision
import io


# ---------------------------------------------------------------------------
# DestructiveLevel enum
# ---------------------------------------------------------------------------


def test_destructive_level_ordering():
    assert DestructiveLevel.DATA_EXFILTRATION < DestructiveLevel.DATA_MODIFICATION
    assert DestructiveLevel.DATA_MODIFICATION < DestructiveLevel.DATA_DESTRUCTION
    assert DestructiveLevel.DATA_DESTRUCTION < DestructiveLevel.PERSISTENCE
    assert DestructiveLevel.PERSISTENCE < DestructiveLevel.LATERAL_MOVEMENT
    assert DestructiveLevel.LATERAL_MOVEMENT < DestructiveLevel.TAKEOVER


def test_destructive_level_label():
    assert DestructiveLevel.DATA_DESTRUCTION.label == "Data Destruction"
    assert DestructiveLevel.PERSISTENCE.label == "Persistence"
    assert DestructiveLevel.TAKEOVER.label == "Takeover"


def test_destructive_level_3_plus_requires_typed_confirmation():
    assert not DestructiveLevel.DATA_EXFILTRATION.requires_typed_confirmation
    assert not DestructiveLevel.DATA_MODIFICATION.requires_typed_confirmation
    assert DestructiveLevel.DATA_DESTRUCTION.requires_typed_confirmation
    assert DestructiveLevel.PERSISTENCE.requires_typed_confirmation
    assert DestructiveLevel.TAKEOVER.requires_typed_confirmation


def test_destructive_level_confirmation_prompts():
    assert DestructiveLevel.DATA_DESTRUCTION.confirmation_prompt == "Type CONFIRM to proceed:"
    assert DestructiveLevel.PERSISTENCE.confirmation_prompt == "Type CONFIRM-LEVEL-4 to proceed:"
    assert DestructiveLevel.TAKEOVER.confirmation_prompt == "Type CONFIRM-LEVEL-6 to proceed:"


# ---------------------------------------------------------------------------
# ActionPlan with destructive level
# ---------------------------------------------------------------------------


def test_action_plan_with_destructive_level():
    p = ActionPlan(
        action_id="x", description="x", risk=Risk.HIGH,
        target="https://t.com", purpose="x", expected_effect="x",
        destructive=True, destructive_level=DestructiveLevel.DATA_DESTRUCTION,
    )
    assert p.destructive_level == DestructiveLevel.DATA_DESTRUCTION
    assert p.destructive


def test_action_plan_render_includes_destructive_level():
    p = ActionPlan(
        action_id="x", description="x", risk=Risk.HIGH,
        target="https://t.com", purpose="x", expected_effect="x",
        destructive=True, destructive_level=DestructiveLevel.DATA_DESTRUCTION,
    )
    rendered = p.render_for_user()
    assert "DESTRUCTIVE LEVEL: 3" in rendered
    assert "Data Destruction" in rendered
    assert "Type CONFIRM" in rendered


# ---------------------------------------------------------------------------
# ActionGate tiered confirmation
# ---------------------------------------------------------------------------


def _plan(level: DestructiveLevel | None = None, confirm_word: str = "") -> ActionPlan:
    return ActionPlan(
        action_id="x",
        description="destructive test",
        risk=Risk.HIGH,
        target="https://t.com",
        purpose="x",
        expected_effect="x",
        destructive=True,
        destructive_level=level,
        confirm_word=confirm_word,
    )


def test_gate_tier1_yn_approval():
    """Level 1-2: standard Y/N works."""
    gate = ActionGate(mode=GateMode.INTERACTIVE, stdin=io.StringIO("y\n"), stdout=io.StringIO())
    decision = gate.ask(_plan(level=DestructiveLevel.DATA_EXFILTRATION),
                        allow_destructive=True, max_destructive_level=6)
    assert decision


def test_gate_tier1_yn_denial():
    """Level 1-2: standard N works."""
    gate = ActionGate(mode=GateMode.INTERACTIVE, stdin=io.StringIO("n\n"), stdout=io.StringIO())
    decision = gate.ask(_plan(level=DestructiveLevel.DATA_EXFILTRATION),
                        allow_destructive=True, max_destructive_level=6)
    assert not decision


def test_gate_tier3_requires_typed_confirm():
    """Level 3: plain 'y' is not enough — must type CONFIRM."""
    gate = ActionGate(mode=GateMode.INTERACTIVE, stdin=io.StringIO("y\n"), stdout=io.StringIO())
    decision = gate.ask(_plan(level=DestructiveLevel.DATA_DESTRUCTION),
                        allow_destructive=True, max_destructive_level=6)
    assert not decision
    assert "expected" in decision.reason.lower() or "denied" in decision.reason.lower()


def test_gate_tier3_accepts_confirm():
    """Level 3: typing CONFIRM approves."""
    gate = ActionGate(mode=GateMode.INTERACTIVE, stdin=io.StringIO("CONFIRM\n"), stdout=io.StringIO())
    decision = gate.ask(_plan(level=DestructiveLevel.DATA_DESTRUCTION),
                        allow_destructive=True, max_destructive_level=6)
    assert decision


def test_gate_tier3_accepts_action_word():
    """Level 3: typing the plan's confirm_word (e.g., 'rm-rf') also approves."""
    gate = ActionGate(mode=GateMode.INTERACTIVE, stdin=io.StringIO("rm-rf\n"), stdout=io.StringIO())
    decision = gate.ask(
        _plan(level=DestructiveLevel.DATA_DESTRUCTION, confirm_word="rm-rf"),
        allow_destructive=True, max_destructive_level=6,
    )
    assert decision


def test_gate_tier6_requires_CONFIRM_LEVEL_6():
    """Level 6: must type CONFIRM-LEVEL-6."""
    gate = ActionGate(mode=GateMode.INTERACTIVE, stdin=io.StringIO("CONFIRM\n"), stdout=io.StringIO())
    decision = gate.ask(_plan(level=DestructiveLevel.TAKEOVER),
                        allow_destructive=True, max_destructive_level=6)
    # CONFIRM (level 3) is not enough for level 6
    assert not decision

    gate = ActionGate(mode=GateMode.INTERACTIVE, stdin=io.StringIO("CONFIRM-LEVEL-6\n"), stdout=io.StringIO())
    decision = gate.ask(_plan(level=DestructiveLevel.TAKEOVER),
                        allow_destructive=True, max_destructive_level=6)
    assert decision


def test_gate_max_destructive_level_blocks_higher():
    """Plans above operator's max are denied even with allow_destructive."""
    gate = ActionGate(mode=GateMode.INTERACTIVE, stdin=io.StringIO("CONFIRM\n"), stdout=io.StringIO())
    # max_destructive_level=2: data destruction (level 3) is blocked
    decision = gate.ask(_plan(level=DestructiveLevel.DATA_DESTRUCTION),
                        allow_destructive=True, max_destructive_level=2)
    assert not decision
    assert "exceeds" in decision.reason.lower()


def test_gate_max_destructive_level_allows_lower():
    """Plans at or below max are allowed (subject to per-action confirm)."""
    gate = ActionGate(mode=GateMode.INTERACTIVE, stdin=io.StringIO("CONFIRM\n"), stdout=io.StringIO())
    # max_destructive_level=3: data destruction (level 3) is allowed
    decision = gate.ask(_plan(level=DestructiveLevel.DATA_DESTRUCTION),
                        allow_destructive=True, max_destructive_level=3)
    assert decision


def test_gate_non_interactive_denies_destructive():
    """Even with allow_destructive, non-interactive mode denies destructive."""
    gate = ActionGate(mode=GateMode.NON_INTERACTIVE)
    decision = gate.ask(_plan(level=DestructiveLevel.DATA_EXFILTRATION),
                        allow_destructive=True, max_destructive_level=6)
    assert not decision
    assert "non-interactive" in decision.reason.lower()


# ---------------------------------------------------------------------------
# Config: short form L1-L6
# ---------------------------------------------------------------------------


def test_config_accepts_short_form():
    from redveil.config import RedVeilConfig, TargetConfig, AuthorizationConfig
    cfg = RedVeilConfig(
        target=TargetConfig(base_url="https://x.com"),
        authorization=AuthorizationConfig(
            active_testing=True,
            acknowledged_safety_terms=True,
            allow_destructive=True,
            max_destructive_level="L3",
        ),
    )
    assert cfg.authorization.max_destructive_level == 3


def test_config_accepts_integer():
    from redveil.config import RedVeilConfig, TargetConfig, AuthorizationConfig
    cfg = RedVeilConfig(
        target=TargetConfig(base_url="https://x.com"),
        authorization=AuthorizationConfig(
            active_testing=True,
            acknowledged_safety_terms=True,
            allow_destructive=True,
            max_destructive_level=4,
        ),
    )
    assert cfg.authorization.max_destructive_level == 4


def test_config_rejects_invalid_level():
    from redveil.config import RedVeilConfig, TargetConfig, AuthorizationConfig
    with pytest.raises(Exception):  # ValidationError
        RedVeilConfig(
            target=TargetConfig(base_url="https://x.com"),
            authorization=AuthorizationConfig(
                max_destructive_level=99,
            ),
        )


def test_config_rejects_garbage_string():
    from redveil.config import RedVeilConfig, TargetConfig, AuthorizationConfig
    with pytest.raises(Exception):
        RedVeilConfig(
            target=TargetConfig(base_url="https://x.com"),
            authorization=AuthorizationConfig(
                max_destructive_level="garbage",
            ),
        )
