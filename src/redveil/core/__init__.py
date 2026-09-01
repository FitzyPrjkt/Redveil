"""Core orchestration, scope control, event bus, and lifecycle management.

This package owns the central safety rails and event-driven spine of redveil:

* ScopeController — the host/path/method gate that every outbound HTTP
  request must pass through.
* ScopeDecision, ScopeViolation — the decision object and the exception
  raised on out-of-scope attempts.
* EventBus — in-process async pub/sub used by all components.
* ScanContext, ScanState — lifecycle state machine for a single scan run.
* Orchestrator — the plugin sequencing engine.
* RichRenderer — optional Rich console subscriber.

Other modules (HTTP transport, plugins) consume these symbols to ensure no
code path can put a packet on the wire without authorization, and that all
activity is observable via the event bus.
"""

from redveil.core.event_bus import Event, EventBus, EventType
from redveil.core.lifecycle import (
    InvalidStateTransition,
    ScanContext,
    ScanState,
    assert_transition,
)
from redveil.core.orchestrator import Orchestrator, OrchestratorDeps
from redveil.core.renderer import RichRenderer
from redveil.core.scope import ScopeController, ScopeDecision, ScopeViolation

__all__ = [
    "Event",
    "EventBus",
    "EventType",
    "InvalidStateTransition",
    "Orchestrator",
    "OrchestratorDeps",
    "RichRenderer",
    "ScanContext",
    "ScanState",
    "ScopeController",
    "ScopeDecision",
    "ScopeViolation",
    "assert_transition",
]
