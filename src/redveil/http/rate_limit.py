"""Async token-bucket rate limiter used by the HTTP transport.

The HttpClient wraps every outbound request in a TokenBucket.acquire() so
that all plugins share a single, predictable rate budget. Concurrent
acquirers are serialized via an asyncio lock so the bucket state stays
consistent under contention.
"""

from __future__ import annotations

import asyncio
import time


class TokenBucket:
    """Async token-bucket rate limiter.

    The bucket holds at most `capacity` tokens and refills at `rate` tokens
    per second. acquire() blocks until a token is available, so callers do
    not need to manage their own throttling.

    Multiple concurrent acquirers share the bucket via an internal lock.
    The lock is held only for the bookkeeping portion of acquire(); the
    actual blocking wait happens outside the lock to avoid head-of-line
    blocking.

    Args:
        rate: Tokens added per second. Must be > 0.
        capacity: Maximum tokens the bucket can hold. Defaults to
            `max(1, int(rate))` — i.e., allow one burst up to one second's
            worth of traffic.
    """

    def __init__(self, rate: float, capacity: int | None = None):
        if rate <= 0:
            raise ValueError("rate must be > 0")
        if capacity is not None and capacity <= 0:
            raise ValueError("capacity must be > 0 or None")
        self._rate = float(rate)
        self._capacity = float(capacity if capacity is not None else max(1, int(rate)))
        # Start full so the first request doesn't have to wait for a refill.
        self._tokens = self._capacity
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Block until a token is available, then consume one."""
        while True:
            # Critical section: refill and try to consume.
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                self._last = now
                self._tokens = min(
                    self._capacity, self._tokens + elapsed * self._rate
                )
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                # Not enough tokens — compute how long to wait outside the
                # lock so concurrent acquirers can also start waiting.
                wait = (1.0 - self._tokens) / self._rate
            await asyncio.sleep(wait)

    @property
    def rate(self) -> float:
        """Configured tokens-per-second refill rate."""
        return self._rate

    @property
    def capacity(self) -> float:
        """Configured maximum bucket size."""
        return self._capacity

    @property
    def available(self) -> float:
        """Approximate current token count. Snapshot only — may race."""
        elapsed = time.monotonic() - self._last
        return min(self._capacity, self._tokens + elapsed * self._rate)
