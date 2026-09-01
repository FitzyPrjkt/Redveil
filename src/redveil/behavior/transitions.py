"""Transitions — explicit state transitions the Behavior Engine can drive.

A Transition is a step the engine can take to move from one SessionState
to another. Currently passive: the transitions describe what to OBSERVE,
not what to perform. A future "active" mode could perform real auth
flows.

Each transition has:
- a name (e.g., "login", "logout", "elevate", "expire")
- a from_state and to_state
- a description of how to detect it
"""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum

from redveil.behavior.state import SessionState


class TransitionKind(str, Enum):
    LOGIN = "login"
    LOGOUT = "logout"
    ELEVATE = "elevate"             # gain higher privilege (rare; usually means role change)
    EXPIRE = "expire"               # natural session expiry
    INVALIDATE = "invalidate"       # server-side session kill
    REFRESH = "refresh"             # session refresh (token rotation)
    # Future: PASSWORD_RESET, MFA_ENROLL, ACCOUNT_LOCKOUT, etc.


@dataclass(frozen=True)
class Transition:
    """A single observable state transition.

    Used by the Behavior Engine to plan what to observe during a scan.
    For example, a "session invalidation" test:
        1. Establish authenticated state (login)
        2. Trigger logout endpoint
        3. Verify the session is now INVALIDATED
        4. Pass: state transitioned from AUTHENTICATED to INVALIDATED
        5. Fail: state still AUTHENTICATED (vulnerability: session not invalidated)
    """
    kind: TransitionKind
    from_state: SessionState
    to_state: SessionState
    description: str = ""

    @property
    def is_security_relevant(self) -> bool:
        return self.kind in {
            TransitionKind.LOGIN,
            TransitionKind.LOGOUT,
            TransitionKind.INVALIDATE,
            TransitionKind.ELEVATE,
        }


# Default transitions the Behavior Engine knows how to plan for
DEFAULT_TRANSITIONS: tuple[Transition, ...] = (
    Transition(
        kind=TransitionKind.LOGIN,
        from_state=SessionState.ANONYMOUS,
        to_state=SessionState.AUTHENTICATED,
        description="Establish an authenticated session by hitting a login endpoint",
    ),
    Transition(
        kind=TransitionKind.LOGOUT,
        from_state=SessionState.AUTHENTICATED,
        to_state=SessionState.INVALIDATED,
        description="Trigger logout and verify the session is invalidated",
    ),
    Transition(
        kind=TransitionKind.INVALIDATE,
        from_state=SessionState.AUTHENTICATED,
        to_state=SessionState.INVALIDATED,
        description="Verify server-side session invalidation on logout / password change",
    ),
    Transition(
        kind=TransitionKind.ELEVATE,
        from_state=SessionState.AUTHENTICATED,
        to_state=SessionState.ELEVATED,
        description="Test privilege escalation paths (rare, often BOLA-adjacent)",
    ),
    Transition(
        kind=TransitionKind.REFRESH,
        from_state=SessionState.AUTHENTICATED,
        to_state=SessionState.AUTHENTICATED,
        description="Session refresh — token rotation or sliding expiration",
    ),
)
