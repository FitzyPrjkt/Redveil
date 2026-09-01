"""Tests for the TokenBucket rate limiter.

These tests verify the three properties that matter:

1. acquire() does not block when tokens are available (cold start is fast).
2. acquire() blocks (approximately) `1/rate` seconds when the bucket is empty.
3. Concurrent acquires share the bucket and don't exceed the configured rate.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from redveil.http.rate_limit import TokenBucket


def test_invalid_rate_rejected() -> None:
    """Rate must be strictly positive."""
    with pytest.raises(ValueError):
        TokenBucket(rate=0)
    with pytest.raises(ValueError):
        TokenBucket(rate=-1)


def test_invalid_capacity_rejected() -> None:
    """Capacity must be positive when supplied."""
    with pytest.raises(ValueError):
        TokenBucket(rate=10, capacity=0)
    with pytest.raises(ValueError):
        TokenBucket(rate=10, capacity=-5)


async def test_acquire_does_not_block_when_tokens_available() -> None:
    """A fresh bucket has `capacity` tokens; first acquires return immediately."""
    bucket = TokenBucket(rate=1, capacity=5)
    start = time.monotonic()
    for _ in range(5):
        await bucket.acquire()
    elapsed = time.monotonic() - start
    # Should be effectively instant. Allow generous slack for CI noise.
    assert elapsed < 0.5, f"first 5 acquires took {elapsed:.3f}s"


async def test_acquire_blocks_when_empty() -> None:
    """After draining the bucket, the next acquire must wait for a refill."""
    # rate=2/s, capacity=1: drain the single token, then the next acquire
    # must wait ~0.5s.
    bucket = TokenBucket(rate=2.0, capacity=1)
    await bucket.acquire()  # consume the starting token
    start = time.monotonic()
    await bucket.acquire()
    elapsed = time.monotonic() - start
    # Expect ~0.5s. Allow a wide window for slow CI.
    assert 0.3 <= elapsed <= 1.5, f"expected ~0.5s wait, got {elapsed:.3f}s"


async def test_capacity_property_reflects_constructor() -> None:
    """The capacity property exposes the configured value."""
    assert TokenBucket(rate=10, capacity=3).capacity == 3.0
    # Default capacity is max(1, int(rate)).
    assert TokenBucket(rate=7, capacity=None).capacity == 7.0
    assert TokenBucket(rate=1, capacity=None).capacity == 1.0


async def test_rate_property_reflects_constructor() -> None:
    """The rate property exposes the configured value as a float."""
    assert TokenBucket(rate=10).rate == 10.0
    assert TokenBucket(rate=2.5, capacity=4).rate == 2.5


async def test_concurrent_acquires_do_not_exceed_rate() -> None:
    """When many tasks acquire concurrently, they share the rate budget.

    With rate=5/s, capacity=5, 20 concurrent acquires take at least 3 seconds
    (drain in 0s, then 15 more at 5/s = 3s).
    """
    bucket = TokenBucket(rate=5.0, capacity=5)
    # Pre-drain.
    for _ in range(5):
        await bucket.acquire()

    start = time.monotonic()

    async def worker() -> None:
        await bucket.acquire()

    await asyncio.gather(*[worker() for _ in range(15)])
    elapsed = time.monotonic() - start

    # The lower bound is `tokens_needed / rate` = 15 / 5 = 3.0s.
    # Allow generous slack on the upper side for slow CI.
    assert elapsed >= 2.5, f"15 acquires at rate 5 took only {elapsed:.3f}s"


async def test_refill_caps_at_capacity() -> None:
    """The bucket never exceeds capacity even after a long idle period."""
    bucket = TokenBucket(rate=10.0, capacity=3)
    # Wait longer than would be needed to refill many tokens.
    await asyncio.sleep(0.5)
    # Should still only have 3 tokens, so 3 quick acquires succeed then the
    # 4th must wait.
    start = time.monotonic()
    for _ in range(3):
        await bucket.acquire()
    assert time.monotonic() - start < 0.2
    # The 4th acquire waits ~0.1s.
    start = time.monotonic()
    await bucket.acquire()
    elapsed = time.monotonic() - start
    assert 0.05 <= elapsed <= 0.5, f"4th acquire took {elapsed:.3f}s"


async def test_available_is_snapshot() -> None:
    """The available property is a non-blocking snapshot of token count."""
    bucket = TokenBucket(rate=10.0, capacity=5)
    # Fresh bucket is full.
    assert bucket.available == pytest.approx(5.0, abs=0.1)
    await bucket.acquire()
    assert bucket.available == pytest.approx(4.0, abs=0.1)
