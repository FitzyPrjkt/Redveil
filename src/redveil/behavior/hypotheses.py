"""Hypotheses — declarative security invariants the Behavior Engine can test.

A Hypothesis is a statement like: "Object ownership is enforced on /api/orders/{id}".
The engine turns hypotheses into test plans, executes them, and reports
results.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class InvariantKind(str, Enum):
    """The kind of security invariant a Hypothesis tests."""
    OBJECT_OWNERSHIP = "object_ownership"      # BOLA / IDOR
    FUNCTION_LEVEL_AUTHZ = "function_level"     # BFLA
    TENANT_ISOLATION = "tenant_isolation"
    SESSION_INVALIDATION = "session_invalidation"
    WORKFLOW_INTEGRITY = "workflow_integrity"   # business logic
    INPUT_INTERPRETATION = "input_interpretation"  # injection (XSS, SQLi, etc.)
    TRANSPORT_SECURITY = "transport_security"  # Secure flag, HSTS, etc.


@dataclass
class Hypothesis:
    """A testable statement about a security invariant on the target.

    The engine takes a Hypothesis and produces a test plan. The test plan
    generates baseline + controlled requests, observes the differential,
    and decides if the invariant holds.
    """
    id: str
    invariant: InvariantKind
    statement: str
    # The minimal context needed to test this hypothesis. The engine
    # uses these to look up relevant pieces of the ApplicationModel.
    target_endpoint: tuple[str, str] | None = None  # (method, path)
    target_object: tuple[str, str] | None = None    # (type, id)
    target_identity: str | None = None
    second_identity: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    # Metadata for the test plan
    max_requests: int = 5
    safety: str = "passive"  # passive | low_impact | active
    metadata: dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Hypothesis):
            return NotImplemented
        return self.id == other.id
