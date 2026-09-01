"""State — represents the runtime state of an authenticated session.

The Behavior Engine tracks session state (anonymous, authenticated, elevated)
across the scan. A check that needs to verify "session is invalidated after
logout" can use the State to ask "what state was I in before, and what
state am I in now?"
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class SessionState(str, Enum):
    ANONYMOUS = "anonymous"
    AUTHENTICATED = "authenticated"
    ELEVATED = "elevated"          # authenticated + elevated privilege (e.g. admin)
    EXPIRED = "expired"
    INVALIDATED = "invalidated"    # logged out, session no longer valid
    UNKNOWN = "unknown"


@dataclass
class State:
    """A single observed state of the system, tied to an Identity.

    The Behavior Engine builds a sequence of these as it walks through
    authentication flows. Hypothesis tests can then ask "what changed
    between state N and state N+1?"
    """
    session_state: SessionState
    identity: str | None = None       # which identity observed this state
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    observed_at_endpoint: str | None = None
    notes: str = ""

    def is_authenticated(self) -> bool:
        return self.session_state in {SessionState.AUTHENTICATED, SessionState.ELEVATED}

    def __hash__(self) -> int:
        return hash((self.session_state, self.identity, self.timestamp.isoformat()))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, State):
            return NotImplemented
        return (
            self.session_state == other.session_state
            and self.identity == other.identity
            and self.timestamp == other.timestamp
        )


@dataclass
class StateHistory:
    """A chronological sequence of observed States.

    Used by behavior tests that need to verify state transitions:
    "after logout, session is INVALIDATED" → check the transition
    from AUTHENTICATED to INVALIDATED.
    """
    states: list[State] = field(default_factory=list)

    def append(self, state: State) -> None:
        self.states.append(state)

    def last(self) -> State | None:
        return self.states[-1] if self.states else None

    def find_transition(
        self, from_state: SessionState, to_state: SessionState
    ) -> tuple[State, State] | None:
        """Find the first transition from_state → to_state in history."""
        for i in range(len(self.states) - 1):
            if self.states[i].session_state == from_state and self.states[i + 1].session_state == to_state:
                return self.states[i], self.states[i + 1]
        return None

    def has_transition(
        self, from_state: SessionState, to_state: SessionState
    ) -> bool:
        return self.find_transition(from_state, to_state) is not None
