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

    def ask(self, plan: ActionPlan, allow_destructive: bool = False) -> GateDecision:
        """Ask the gate about an action plan. Returns GateDecision.

        The decision is also appended to self.history for audit.

        Destructive actions (destructive=True or Risk.BLOCKED):
        - allow_destructive=False: ALWAYS denied, regardless of mode
        - allow_destructive=True: requires per-action user confirmation
          in INTERACTIVE mode. In NON_INTERACTIVE mode, ALWAYS denied
          (no batch approval — every destructive action is denied by
          default unless the user explicitly enables a per-action
          confirmation flag, which we intentionally don't expose to
          prevent accidental Y-to-all approvals).

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
            # allow_destructive=True: still require per-action user YES
            # We do NOT auto-approve even in non-interactive mode. Every
            # destructive action needs explicit user input. The only way
            # to bypass is to set a separate per-action confirm flag
            # (intentionally not exposed here to prevent Y-to-all mistakes).
            if self.mode == GateMode.NON_INTERACTIVE:
                decision = GateDecision(
                    approved=False,
                    plan=plan,
                    reason=(
                        "destructive action in non-interactive mode: "
                        "denied by default (use --interactive or set "
                        "GATE_CONFIRM_DESTRUCTIVE_PER_ACTION=true per call)"
                    ),
                )
                self._log_decision(decision)
                return decision
            # INTERACTIVE: prompt per action
            return self._prompt_user(plan, emphasize_destructive=True)

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

        # Auto-approvable risk in interactive mode: still log and approve
        # so the user isn't prompted for trivial actions.
        if plan.is_safe_to_auto_approve():
            decision = GateDecision(
                approved=True,
                plan=plan,
                reason=f"interactive mode: {plan.risk.name} risk auto-approved",
            )
            self._log_decision(decision)
            return decision

        # MEDIUM/HIGH in interactive mode: prompt
        return self._prompt_user(plan, emphasize_destructive=False)

    def _prompt_user(self, plan: ActionPlan, emphasize_destructive: bool = False) -> GateDecision:
        """Prompt the user. Default answer is N (deny).

        For destructive actions, we require a longer, more explicit
        confirmation string ("DESTROY" or similar) to prevent accidental
        Y presses. The user has to read the plan and type the exact
        confirmation word.
        """
        text = plan.render_for_user()
        if emphasize_destructive:
            text += "\n" + (
                "DESTRUCTIVE ACTION: type 'I-accept-risk' to confirm, "
                "anything else to deny:"
            )
        self._stdout.write(text + "\n")
        self._stdout.flush()
        try:
            response = self._stdin.readline().strip()
        except (EOFError, KeyboardInterrupt):
            response = ""
        if emphasize_destructive:
            approved = response == "I-accept-risk"
            reason_token = "explicit 'I-accept-risk' for destructive"
        else:
            approved = response.lower() in ("y", "yes")
            reason_token = "approved" if approved else "denied"
        decision = GateDecision(
            approved=approved,
            plan=plan,
            reason=f"user {reason_token} interactively",
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
