"""Tests for the in-process async event bus."""

from __future__ import annotations

import pytest

from redveil.core.event_bus import Event, EventBus, EventType


@pytest.mark.asyncio
async def test_subscribe_invokes_subscriber_on_publish() -> None:
    bus = EventBus()
    received: list[Event] = []

    async def handler(event: Event) -> None:
        received.append(event)

    bus.subscribe(EventType.SCAN_STARTED, handler)
    event = Event(EventType.SCAN_STARTED, source="test")
    await bus.publish(event)

    assert received == [event]


@pytest.mark.asyncio
async def test_subscribe_all_receives_every_event() -> None:
    bus = EventBus()
    received: list[Event] = []

    async def handler(event: Event) -> None:
        received.append(event)

    bus.subscribe_all(handler)
    await bus.publish(Event(EventType.SCAN_STARTED, source="test"))
    await bus.publish(Event(EventType.SCAN_FINISHED, source="test"))
    await bus.publish(Event(EventType.ERROR, source="test"))

    assert [e.type for e in received] == [
        EventType.SCAN_STARTED,
        EventType.SCAN_FINISHED,
        EventType.ERROR,
    ]


@pytest.mark.asyncio
async def test_history_accumulates_published_events() -> None:
    bus = EventBus()
    await bus.publish(Event(EventType.SCAN_STARTED, source="test"))
    await bus.publish(Event(EventType.CHECK_STARTED, source="test"))
    await bus.publish(Event(EventType.SCAN_FINISHED, source="test"))

    history = bus.history
    assert len(history) == 3
    assert [e.type for e in history] == [
        EventType.SCAN_STARTED,
        EventType.CHECK_STARTED,
        EventType.SCAN_FINISHED,
    ]


@pytest.mark.asyncio
async def test_history_returns_a_snapshot_copy() -> None:
    bus = EventBus()
    await bus.publish(Event(EventType.SCAN_STARTED))

    snap = bus.history
    snap.clear()

    assert len(bus.history) == 1


@pytest.mark.asyncio
async def test_multiple_subscribers_to_same_event_all_fire() -> None:
    bus = EventBus()
    a_calls: list[Event] = []
    b_calls: list[Event] = []
    c_calls: list[Event] = []

    async def a(event: Event) -> None:
        a_calls.append(event)

    async def b(event: Event) -> None:
        b_calls.append(event)

    async def c(event: Event) -> None:
        c_calls.append(event)

    bus.subscribe(EventType.FINDING_DETECTED, a)
    bus.subscribe(EventType.FINDING_DETECTED, b)
    bus.subscribe_all(c)

    event = Event(EventType.FINDING_DETECTED, source="test")
    await bus.publish(event)

    assert a_calls == [event]
    assert b_calls == [event]
    assert c_calls == [event]


@pytest.mark.asyncio
async def test_subscriber_is_awaited_as_coroutine() -> None:
    """Verify subscribers are properly awaited (not fired-and-forgotten).

    We use a counter incremented both before and after an asyncio.sleep
    to detect any missed await. If the subscriber is treated as a plain
    callable, the post-sleep counter will read zero when we sample it.
    """
    bus = EventBus()
    pre_sleep = 0
    post_sleep = 0

    async def handler(event: Event) -> None:
        nonlocal pre_sleep, post_sleep
        pre_sleep += 1
        await asyncio_sleep_zero()
        post_sleep += 1

    bus.subscribe(EventType.SCAN_STARTED, handler)
    await bus.publish(Event(EventType.SCAN_STARTED))

    assert pre_sleep == 1
    assert post_sleep == 1


@pytest.mark.asyncio
async def test_subscribers_run_in_registration_order() -> None:
    bus = EventBus()
    order: list[str] = []

    async def first(event: Event) -> None:
        order.append("first")

    async def second(event: Event) -> None:
        order.append("second")

    async def third(event: Event) -> None:
        order.append("third")

    bus.subscribe(EventType.CHECK_STARTED, first)
    bus.subscribe(EventType.CHECK_STARTED, second)
    bus.subscribe(EventType.CHECK_STARTED, third)

    await bus.publish(Event(EventType.CHECK_STARTED))

    assert order == ["first", "second", "third"]


@pytest.mark.asyncio
async def test_specific_subscribers_run_before_global() -> None:
    bus = EventBus()
    order: list[str] = []

    async def specific(event: Event) -> None:
        order.append("specific")

    async def global_(event: Event) -> None:
        order.append("global")

    bus.subscribe(EventType.SCAN_STARTED, specific)
    bus.subscribe_all(global_)

    await bus.publish(Event(EventType.SCAN_STARTED))

    assert order == ["specific", "global"]


async def asyncio_sleep_zero() -> None:
    """Helper that yields to the event loop exactly once."""
    import asyncio

    await asyncio.sleep(0)
