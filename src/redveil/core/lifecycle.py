"""Scan lifecycle state machine.

Every scan run moves through a fixed sequence of states: discovery, checking,
validation, reporting, then either completed, failed, or aborted. The state
machine guards against illegal transitions (e.g. skipping discovery and
jumping straight to reporting) and provides a single, queryable source of
truth for "where is this scan right now?".

The state machine is deliberately framework-level: plugins never transition
the state machine directly. They emit events; the orchestrator reads those
events and drives the transitions.
"""

from __future__ import annotations

from enum import Enum


class ScanState(str, Enum):
    """Lifecycle states for a single scan run."""

    INITIALIZED = "initialized"
    DISCOVERING = "discovering"
    DISCOVERY_COMPLETE = "discovery_complete"
    CHECKING = "checking"
    VALIDATING = "validating"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"


# Allowed transitions. Used to prevent invalid state changes.
_ALLOWED: dict[ScanState, set[ScanState]] = {
    ScanState.INITIALIZED: {ScanState.DISCOVERING, ScanState.FAILED, ScanState.ABORTED},
    ScanState.DISCOVERING: {ScanState.DISCOVERY_COMPLETE, ScanState.FAILED, ScanState.ABORTED},
    ScanState.DISCOVERY_COMPLETE: {ScanState.CHECKING, ScanState.FAILED, ScanState.ABORTED},
    ScanState.CHECKING: {ScanState.VALIDATING, ScanState.REPORTING, ScanState.FAILED, ScanState.ABORTED},
    ScanState.VALIDATING: {ScanState.REPORTING, ScanState.FAILED, ScanState.ABORTED},
    ScanState.REPORTING: {ScanState.COMPLETED, ScanState.FAILED, ScanState.ABORTED},
    ScanState.COMPLETED: set(),
    ScanState.FAILED: set(),
    ScanState.ABORTED: set(),
}


class InvalidStateTransition(Exception):
    """Raised when code attempts to move the scan to an illegal state."""


def assert_transition(current: ScanState, target: ScanState) -> None:
    """Verify that `current -> target` is a legal transition.

    Raises InvalidStateTransition if not. Terminal states (COMPLETED,
    FAILED, ABORTED) accept no further transitions.
    """
    if target not in _ALLOWED[current]:
        raise InvalidStateTransition(
            f"illegal state transition: {current.value} -> {target.value}"
        )


class ScanContext:
    """Mutable per-scan context (target, config, run_id).

    Holds the scan's run_id, target identity, current lifecycle state,
    and the accumulated list of findings discovered so far. The orchestrator
    owns a single ScanContext per scan.
    """

    def __init__(self, target_name: str, run_id: str):
        self.target_name = target_name
        self.run_id = run_id
        self.state: ScanState = ScanState.INITIALIZED
        self.findings: list = []  # list[Finding] — type erased to avoid import cycle
        self.metadata: dict = {}

    def transition(self, target: ScanState) -> None:
        """Move the scan to `target`, asserting the transition is legal.

        Raises InvalidStateTransition if not. On success, updates `state`.
        """
        assert_transition(self.state, target)
        self.state = target
