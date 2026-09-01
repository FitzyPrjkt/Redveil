"""ActionGate — presents action plans and gates active validations.

The gate is the bridge between a check's intent and the orchestrator's
execution. For each MEDIUM or HIGH risk action, the gate:
- Renders a human-readable confirmation prompt (interactive mode)
- OR logs the plan and auto-approves (non-interactive mode, e.g. CI)

The gate NEVER bypasses scope, safety policy, rate limit, or any other
engine-level guard. Approval means "I'm OK with this controlled action
under the engine's existing limits", NOT "do whatever you want".

Three modes:
- interactive: prompt the user, read stdin
- non-interactive: log the plan, auto-approve all (caller's responsibility
  to ensure they're authorized)
- strict: only approve NONE/LOW; require explicit pre-approval for MEDIUM+
  via config file (caller responsibility)
"""
from __future__ import annotations
import logging
import sys
from dataclasses import dataclass
from enum import Enum
from typing import TextIO

from redveil.validation.risk import ActionPlan, Risk


log = logging.getLogger(__name__)


class GateMode(str, Enum):
    INTERACTIVE = "interactive"   # prompt user, read yes/no
    NON_INTERACTIVE = "non_interactive"  # log + auto-approve
    STRICT = "strict"              # log only, auto-deny MEDIUM+


@dataclass
class GateDecision:
    """The result of asking the gate about an action plan."""
    approved: bool
    plan: ActionPlan
    reason: str = ""

    def __bool__(self) -> bool:
        return self.approved


class ActionGate:
    """Presents plans and gates active validations.

    The gate has three modes:
    - INTERACTIVE: prompt the user, default deny (N)
    - NON_INTERACTIVE: auto-approve all (caller must be authorized)
    - STRICT: only auto-approve NONE/LOW; require explicit approval for MEDIUM+

    Usage:
        gate = ActionGate(mode=GateMode.INTERACTIVE)
        plan = ActionPlan(...)
        decision = gate.ask(plan)
        if decision:
            # proceed
        else:
            # skip
    """

    def __init__(
        self,
        mode: GateMode = GateMode.NON_INTERACTIVE,
        stdin: TextIO | None = None,
        stdout: TextIO | None = None,
    ):
        self.mode = mode
        self._stdin = stdin or sys.stdin
        self._stdout = stdout or sys.stdout
        # Log of all decisions (for audit)
        self.history: list[GateDecision] = []

    def ask(self, plan: ActionPlan, allow_destructive: bool = False,
           max_destructive_level: int = 2) -> GateDecision:
        """Ask the gate about an action plan. Returns GateDecision.

        The decision is also appended to self.history for audit.

        Destructive actions (destructive=True or Risk.BLOCKED):
        - allow_destructive=False: ALWAYS denied
        - allow_destructive=True but level > max_destructive_level: denied
        - allow_destructive=True and level <= max_destructive_level:
          requires per-action user confirmation
          - Level 1-2: simple Y/N
          - Level 3+: user must TYPE the action word (or CONFIRM for
            generic plans). This prevents accidental Y presses.

        MEDIUM/HIGH (non-destructive) risk:
        - NON_INTERACTIVE: auto-approve
        - STRICT: deny
        - INTERACTIVE: prompt user

        LOW/NONE: auto-approve in any mode
        """
        # Destructive actions are always denied unless allow_destructive=True
        if plan.destructive or plan.risk == Risk.BLOCKED:
            if not allow_destructive:
                decision = GateDecision(
                    approved=False,
                    plan=plan,
                    reason=(
                        "destructive action: requires "
                        "authorization.allow_destructive=true"
                    ),
                )
                self._log_decision(decision)
                return decision
            # Check the destructive level against the operator's max
            level = (
                int(plan.destructive_level.value)
                if plan.destructive_level is not None
                else 3  # default to "data destruction" if unspecified
            )
            if level > max_destructive_level:
                decision = GateDecision(
                    approved=False,
                    plan=plan,
                    reason=(
                        f"destructive level {level} exceeds operator's "
                        f"max_destructive_level ({max_destructive_level})"
                    ),
                )
                self._log_decision(decision)
                return decision
            # allow_destructive=True + level <= max: per-action approval
            if self.mode == GateMode.NON_INTERACTIVE:
                decision = GateDecision(
                    approved=False,
                    plan=plan,
                    reason=(
                        f"destructive action level {level} in non-interactive "
                        f"mode: denied by default (use --interactive)"
                    ),
                )
                self._log_decision(decision)
                return decision
            # INTERACTIVE: prompt per action with tiered confirmation
            return self._prompt_user_tiered(plan)

        # Non-destructive path
        if self.mode == GateMode.NON_INTERACTIVE:
            decision = GateDecision(
                approved=True,
                plan=plan,
                reason="non-interactive mode: auto-approved",
            )
            self._log_decision(decision)
            return decision

        if self.mode == GateMode.STRICT and plan.risk > Risk.LOW:
            decision = GateDecision(
                approved=False,
                plan=plan,
                reason="strict mode: MEDIUM+ requires explicit pre-approval",
            )
            self._log_decision(decision)
            return decision

        if plan.is_safe_to_auto_approve():
            decision = GateDecision(
                approved=True,
                plan=plan,
                reason=f"interactive mode: {plan.risk.name} risk auto-approved",
            )
            self._log_decision(decision)
            return decision

        return self._prompt_user(plan, emphasize_destructive=False)

    def _prompt_user(self, plan: ActionPlan, emphasize_destructive: bool = False) -> GateDecision:
        """Standard Y/N prompt for non-destructive MEDIUM/HIGH actions."""
        text = plan.render_for_user()
        self._stdout.write(text + "\n")
        self._stdout.flush()
        try:
            response = self._stdin.readline().strip()
        except (EOFError, KeyboardInterrupt):
            response = ""
        approved = response.lower() in ("y", "yes")
        reason_token = "approved" if approved else "denied"
        decision = GateDecision(
            approved=approved,
            plan=plan,
            reason=f"user {reason_token} interactively",
        )
        self._log_decision(decision)
        return decision

    def _prompt_user_tiered(self, plan: ActionPlan) -> GateDecision:
        """Tiered confirmation for destructive actions.

        - Level 1-2: simple Y/N
        - Level 3-4: user must type CONFIRM or the plan's confirm_word
        - Level 5-6: same, but the prompt is more prominent

        The plan's confirm_word (e.g., "rm-rf", "drop-table") makes
        the user consciously type the action. This prevents accidental
        Y presses and forces the user to acknowledge what they're doing.
        """
        level = plan.destructive_level
        level_value = level.value if level else 3
        text = plan.render_for_user()
        self._stdout.write(text + "\n")
        self._stdout.flush()

        # Level 1-2: standard Y/N
        if level_value <= 2:
            try:
                response = self._stdin.readline().strip().lower()
            except (EOFError, KeyboardInterrupt):
                response = ""
            approved = response in ("y", "yes")
            reason_token = "approved" if approved else "denied"
            decision = GateDecision(
                approved=approved, plan=plan,
                reason=f"destructive level {level_value}: user {reason_token}",
            )
            self._log_decision(decision)
            return decision

        # Level 3+: typed confirmation
        # User must type either:
        # - the plan's confirm_word (e.g., "rm-rf", "drop-table"), OR
        # - the level-specific CONFIRM string from DestructiveLevel
        expected_words = set()
        if plan.confirm_word:
            expected_words.add(plan.confirm_word)
        if level:
            # level 3: "CONFIRM"
            # level 4: "CONFIRM-LEVEL-4"
            # etc.
            expected_words.add(level.confirmation_prompt.replace("Type ", "").replace(" to proceed:", ""))

        try:
            response = self._stdin.readline().strip()
        except (EOFError, KeyboardInterrupt):
            response = ""

        approved = response in expected_words
        if approved:
            reason = f"typed confirmation '{response}' for destructive level {level_value}"
        else:
            reason = (
                f"denied: expected one of {sorted(expected_words)!r}, got {response!r}"
            )
        decision = GateDecision(
            approved=approved, plan=plan, reason=reason,
        )
        self._log_decision(decision)
        return decision

    def _log_decision(self, decision: GateDecision) -> None:
        self.history.append(decision)
        if decision.approved:
            log.info(
                "ActionGate APPROVED: %s (risk=%s)",
                decision.plan.description,
                decision.plan.risk.name,
            )
        else:
            log.warning(
                "ActionGate DENIED: %s (reason=%s)",
                decision.plan.description,
                decision.reason,
            )

    def audit_log(self) -> list[dict]:
        """Return the decision history as a JSON-serializable audit log.

        Suitable for inclusion in the report as an appendix so the
        operator has a record of every gate decision made during the scan.
        """
        out: list[dict] = []
        for d in self.history:
            entry = {
                "action_id": d.plan.action_id,
                "description": d.plan.description,
                "risk": d.plan.risk.name,
                "destructive": d.plan.destructive,
                "approved": d.approved,
                "reason": d.reason,
            }
            if d.plan.destructive_level is not None:
                entry["destructive_level"] = d.plan.destructive_level.value
                entry["destructive_label"] = d.plan.destructive_level.label
            if d.plan.confirm_word:
                entry["confirm_word"] = d.plan.confirm_word
            out.append(entry)
        return out
