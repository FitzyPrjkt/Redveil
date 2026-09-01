"""In-process async pub/sub for scan lifecycle events.

The EventBus is the central nervous system of redveil. Components (plugins,
HTTP transport, orchestrator, renderer) emit strongly categorized events
and subscribe to event streams relevant to them. The bus delivers events
sequentially to preserve log ordering, which is important for deterministic
replay and operator-facing output.

Subscribers are coroutine functions registered via subscribe() (per-type)
or subscribe_all() (catch-all). The bus is intentionally minimal — there
is no replay, filtering, or backpressure machinery. If those become
necessary, they can be added behind the same API.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class EventType(str, Enum):
    """Closed set of event types the framework emits.

    Using a string Enum keeps event types greppable in logs and serialization
    stable across processes. New event types are added by extending this enum;
    plugins should not invent their own (use the `data` dict for payload
    variability instead).
    """

    SCAN_STARTED = "scan_started"
    DISCOVERY_STARTED = "discovery_started"
    DISCOVERY_ENDED = "discovery_ended"
    REQUEST_SENT = "request_sent"
    RESPONSE_RECEIVED = "response_received"
    CHECK_STARTED = "check_started"
    CHECK_ENDED = "check_ended"
    FINDING_DETECTED = "finding_detected"
    VALIDATION_STARTED = "validation_started"
    VALIDATION_ENDED = "validation_ended"
    EVIDENCE_CAPTURED = "evidence_captured"
    FINDING_CONFIRMED = "finding_confirmed"
    REPORT_GENERATED = "report_generated"
    SCAN_FINISHED = "scan_finished"
    ERROR = "error"


@dataclass
class Event:
    """A single event emitted on the bus.

    `type` selects which subscribers receive the event. `data` is a free-form
    dict; subscribers should access only keys they understand and ignore the
    rest. `source` identifies the emitting component (e.g. "cors-policy") for
    log attribution.
    """

    type: EventType
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    data: dict[str, Any] = field(default_factory=dict)
    source: str | None = None  # emitting component name (e.g. "cors-policy")


Subscriber = Callable[[Event], Awaitable[None]]


class EventBus:
    """In-process async pub/sub.

    Subscribers are coroutine functions. publish() awaits delivery to all
    subscribers sequentially (to keep log ordering deterministic). Add
    queue-based fanout later if needed.
    """

    def __init__(self) -> None:
        self._subscribers: dict[EventType, list[Subscriber]] = defaultdict(list)
        self._all_subscribers: list[Subscriber] = []
        self._history: list[Event] = []
        self._lock = asyncio.Lock()

    def subscribe(self, event_type: EventType, fn: Subscriber) -> None:
        """Register a subscriber for a single event type."""
        self._subscribers[event_type].append(fn)

    def subscribe_all(self, fn: Subscriber) -> None:
        """Register a subscriber that receives every event."""
        self._all_subscribers.append(fn)

    async def publish(self, event: Event) -> None:
        """Deliver `event` to all matching subscribers.

        Delivery order is: (1) per-type subscribers in registration order,
        (2) catch-all subscribers in registration order. Delivery is
        sequential to preserve log ordering; an exception in one subscriber
        propagates and halts delivery to subsequent subscribers.
        """
        async with self._lock:
            self._history.append(event)
        # Specific subscribers
        for fn in list(self._subscribers.get(event.type, [])):
            await fn(event)
        # Global subscribers
        for fn in list(self._all_subscribers):
            await fn(event)

    @property
    def history(self) -> list[Event]:
        """Snapshot of all events published so far.

        Returned as a shallow copy so callers can iterate without worrying
        about concurrent mutation.
        """
        return list(self._history)
