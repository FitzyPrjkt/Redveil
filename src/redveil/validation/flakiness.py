"""Flakiness detection — measure endpoint stability across multiple samples.

Some endpoints are inherently flaky: they return 200 sometimes, 503 other
times, and the response body changes due to noise (timestamps, CSRF tokens,
session rotation, etc.). A security finding based on a single sample of a
flaky endpoint is unreliable.

The FlakinessDetector probes an endpoint N times and computes:
- median status code
- median response time
- status variance (is the status code stable?)
- body length variance (does the body size change?)
- timing variance (does the response time vary wildly?)

The combined flakiness score is 0.0 (rock-solid) to 1.0 (chaotic).
Checks can use this to:
- Decide whether a single-sample signal is trustworthy
- Add a flakiness signal to the ConfidenceScorer input to reduce
  confidence for findings on flaky endpoints
- Skip a check entirely if the endpoint is too unstable to test
"""
from __future__ import annotations
import asyncio
import statistics
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from redveil.http.response import Response


@dataclass
class FlakinessReport:
    """Statistics from probing an endpoint multiple times."""
    samples_collected: int
    requested_samples: int
    statuses: list[int] = field(default_factory=list)
    body_lengths: list[int] = field(default_factory=list)
    timings_ms: list[float] = field(default_factory=list)

    @property
    def median_status(self) -> int | None:
        if not self.statuses:
            return None
        return int(statistics.median(self.statuses))

    @property
    def median_timing_ms(self) -> float:
        if not self.timings_ms:
            return 0.0
        return statistics.median(self.timings_ms)

    @property
    def status_stable(self) -> bool:
        return len(set(self.statuses)) <= 1

    @property
    def body_stable(self) -> bool:
        if not self.body_lengths:
            return True
        return max(self.body_lengths) - min(self.body_lengths) <= 10

    @property
    def timing_stable(self) -> bool:
        """Stable if median +/- 20% contains all samples."""
        if len(self.timings_ms) < 2:
            return True
        med = self.median_timing_ms
        return all(0.8 * med <= t <= 1.2 * med for t in self.timings_ms)

    @property
    def flakiness_score(self) -> float:
        """0.0 = rock-solid, 1.0 = chaotic.

        Weighted average of:
        - status instability (0.4 weight)
        - body instability (0.3)
        - timing instability (0.3)
        """
        s = 0.0 if self.status_stable else 0.4
        b = 0.0 if self.body_stable else 0.3
        # Timing instability: 0 if stable, scaled by variance
        t = 0.0
        if not self.timing_stable and len(self.timings_ms) >= 2:
            med = self.median_timing_ms
            if med > 0:
                # Normalize variance: (max - min) / median
                rel_var = (max(self.timings_ms) - min(self.timings_ms)) / med
                t = min(0.3, rel_var * 0.3)
        return round(s + b + t, 3)

    def is_reliable(self, threshold: float = 0.3) -> bool:
        """True if the endpoint is stable enough to trust a single sample."""
        return self.flakiness_score <= threshold


# A request function is async (request: Request) -> Response
RequestFn = Callable[[], Awaitable[Response]]


class FlakinessDetector:
    """Probe an endpoint multiple times to measure stability.

    Usage:
        detector = FlakinessDetector()
        report = await detector.probe(
            lambda: http.send(Request(method="GET", url=url, purpose="flakiness_probe"))
        )
        if not report.is_reliable():
            # Endpoint too flaky, downgrade or skip the check
            pass
    """

    async def probe(
        self,
        request_fn: RequestFn,
        samples: int = 5,
        delay_between: float = 0.1,
    ) -> FlakinessReport:
        """Run request_fn `samples` times. Returns aggregated FlakinessReport.

        delay_between: seconds to wait between samples (default 0.1). Set
        higher if the target rate-limits; set to 0 to disable delay.
        """
        statuses: list[int] = []
        body_lengths: list[int] = []
        timings: list[float] = []
        for _ in range(samples):
            try:
                start = time.monotonic()
                resp = await request_fn()
                elapsed = (time.monotonic() - start) * 1000.0
                statuses.append(resp.status_code)
                body_lengths.append(len(resp.body))
                # Use the response's own elapsed if available
                timings.append(resp.elapsed_ms or elapsed)
            except Exception:
                continue
            if delay_between > 0 and samples > 1:
                await asyncio.sleep(delay_between)

        return FlakinessReport(
            samples_collected=len(statuses),
            requested_samples=samples,
            statuses=statuses,
            body_lengths=body_lengths,
            timings_ms=timings,
        )

    async def is_reliable(
        self,
        request_fn: RequestFn,
        samples: int = 5,
        threshold: float = 0.3,
    ) -> bool:
        """Convenience: returns True if endpoint is reliable within threshold."""
        report = await self.probe(request_fn, samples)
        return report.is_reliable(threshold)
