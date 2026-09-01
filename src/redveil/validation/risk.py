"""Risk model — every action has a risk level.

The risk model is separate from the safety profile. A check might be
ACTIVE (gated by authorization) but its actions might still be NONE risk
if they're purely observational. Conversely, a check might be marked
PASSIVE but a specific test it runs might be MEDIUM risk.

Risk levels:
- NONE:        pure observation, no request modification, no side effect
- LOW:         canary probes, header inspection, timing observation
- MEDIUM:      authenticated BOLA, controlled state change, account creation
- HIGH:        multi-step workflow validation, cross-account data comparison
- BLOCKED:     destructive operations, persistence, credential extraction

The ActionGate (validation/gate.py) presents a plan to the user (or logs
it in non-interactive mode) and requires explicit confirmation for
MEDIUM and HIGH risk actions.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Risk(IntEnum):
    """Risk level of an action. Higher = more dangerous.

    Use the integer value for comparison. IntEnum so we can do
    `risk_a > risk_b` and the safety gate can threshold on it.
    """
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    BLOCKED = 99  # sentinel: never execute, even with explicit user approval


@dataclass
class ActionPlan:
    """Structured description of an action a check wants to perform.

    The ActionGate uses this to show the user (or log) what the check
    is about to do, so they can make an informed allow/deny decision.
    """
    action_id: str
    description: str
    risk: Risk
    target: str                          # e.g. "https://target.example.com/api/orders"
    purpose: str                         # plain-language purpose
    expected_effect: str                 # what we expect to see
    potential_side_effects: tuple[str, ...] = ()
    # Hard limits the orchestrator enforces regardless of approval
    max_requests: int = 1
    timeout_seconds: float = 10.0
    # Destructive operations: never executed, even with approval
    destructive: bool = False
    # Additional metadata for the gate
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_safe_to_auto_approve(self) -> bool:
        """True if the gate can auto-approve without user confirmation.

        NONE and LOW risk actions can run automatically. MEDIUM and
        HIGH require explicit user confirmation (or `--yes` flag in
        non-interactive mode).
        """
        return self.risk <= Risk.LOW and not self.destructive

    def render_for_user(self) -> str:
        """Format the plan as a human-readable confirmation prompt.

        Used by the interactive ActionGate. Non-interactive mode just
        logs the same text.
        """
        risk_label = ["NONE", "LOW", "MEDIUM", "HIGH", "BLOCKED"][
            min(int(self.risk) if self.risk < 99 else 4, 4)
        ]
        lines = [
            "",
            "⚠ ACTIVE VALIDATION",
            "",
            f"Risk:        {risk_label}",
            f"Target:      {self.target}",
            f"Purpose:     {self.purpose}",
            f"Action:      {self.description}",
            "",
            "Limits:",
            f"  - {self.max_requests} request(s) max",
            f"  - {self.timeout_seconds:.0f}s timeout",
            f"  - no destructive operations"
            f"{'' if not self.destructive else '  (BLOCKED — destructive flagged)'}",
            "",
            f"Expected effect: {self.expected_effect}",
        ]
        if self.potential_side_effects:
            lines.append("")
            lines.append("Potential side effects:")
            for s in self.potential_side_effects:
                lines.append(f"  - {s}")
        lines.append("")
        lines.append("Proceed with this validation? [y/N]")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Risk classifications for known check categories
# ---------------------------------------------------------------------------


# Standard risk profiles per check category. Used as defaults when a
# check doesn't declare its own risk.
CATEGORY_RISK: dict[str, Risk] = {
    "headers": Risk.NONE,
    "disclosure": Risk.LOW,
    "tls": Risk.NONE,
    "cors": Risk.NONE,
    "methods": Risk.LOW,
    "redirect": Risk.LOW,
    "xss": Risk.LOW,                    # canary probe only
    "sqli": Risk.LOW,                    # time-based, no data extraction
    "ssrf": Risk.LOW,                    # OOB only, no internal IP
    "command_injection": Risk.LOW,        # sleep only, no destructive
    "path_traversal": Risk.LOW,           # canary filename only
    "idor": Risk.MEDIUM,                 # multi-principal auth
    "bfla": Risk.MEDIUM,                 # admin endpoint probing
    "business_logic": Risk.HIGH,         # state-machine validation
    "graphql": Risk.LOW,
    "webhook": Risk.MEDIUM,
    "session": Risk.NONE,
    "auth": Risk.MEDIUM,
    "mass_assignment": Risk.LOW,
    "rate_limit": Risk.LOW,
    "request_smuggling": Risk.LOW,
    "host_header": Risk.LOW,
    "infrastructure": Risk.NONE,
    "exposed_panels": Risk.NONE,
    "debug_interfaces": Risk.NONE,
    "cloud_metadata": Risk.MEDIUM,
    "token_leakage": Risk.NONE,
    "exposed_source_map": Risk.NONE,
    "subdomain_discovery": Risk.NONE,
    "race_condition": Risk.HIGH,
}


# ---------------------------------------------------------------------------
# Progressive validation levels
# ---------------------------------------------------------------------------


class ProgressiveLevel(IntEnum):
    """The level of validation depth.

    LEVEL_0: passive observation only
    LEVEL_1: low-impact probes (canary reflection, timing)
    LEVEL_2: controlled active validation (BOLA, BFLA, state change)
    LEVEL_3: higher-risk validation (race conditions, business logic)
    """
    LEVEL_0 = 0
    LEVEL_1 = 1
    LEVEL_2 = 2
    LEVEL_3 = 3


@dataclass
class ValidationStep:
    """A single step in a progressive validation ladder.

    The orchestrator tracks evidence per hypothesis. If evidence from a
    lower level is insufficient, it may escalate to the next level.
    Each step has a risk and a plan.
    """
    level: ProgressiveLevel
    plan: ActionPlan
    preconditions: tuple[str, ...] = ()  # what evidence is needed to run this

    def can_run(self, current_evidence: dict[str, Any]) -> bool:
        """True if all preconditions are met by current evidence."""
        return all(p in current_evidence for p in self.preconditions)
