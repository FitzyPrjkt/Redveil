"""Differential analysis — compare baseline vs controlled test responses.

The core of low-false-positive testing. Given a baseline request/response
and a modified request/response, compute what changed:
- status code
- body (length, content, error messages)
- headers
- timing

The hypothesis test passes only if there's a MEANINGFUL difference that
matches the expected attack pattern. A single anomaly is not a finding —
it must be reproducible, consistent, and exploitable.

Each DifferentialResult also carries a list of `Signal` objects — typed
pieces of evidence. The ConfidenceScorer uses these to compute the
final finding confidence.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

from redveil.http.request import Request
from redveil.http.response import Response
from redveil.validation.oracle import Oracle, Signal, SignalKind


@dataclass
class DifferentialResult:
    """The diff between a baseline and a controlled-test response."""
    # Per-attribute differences
    status_diff: int = 0
    body_length_diff: int = 0
    body_content_diff: bool = False
    header_diff: dict[str, tuple[str | None, str | None]] = field(default_factory=dict)
    timing_diff_ms: float = 0.0

    # Was a meaningful difference observed?
    meaningful: bool = False

    # What the test plan was looking for
    expected_signal: str = ""

    # Debugging context
    baseline: Response | None = None
    controlled: Response | None = None

    # Multi-signal evidence (added in Wave 2). Each signal is a typed
    # piece of evidence that the ConfidenceScorer can aggregate.
    signals: list[Signal] = field(default_factory=list)

    def add_signal(self, kind: str, description: str, weight: float = 1.0) -> None:
        """Append a signal with its standard dimension tag."""
        self.signals.append(Signal(
            kind=kind,
            description=description,
            weight=weight,
            dimension=SignalKind.DIMENSION.get(kind, "response"),
        ))

    def is_meaningful(self) -> bool:
        """True if at least one indicator changed in a security-relevant way."""
        if self.signals:
            return True
        if self.status_diff != 0:
            return True
        if self.body_content_diff:
            return True
        if any(a != b for a, b in self.header_diff.items()):
            return True
        if self.timing_diff_ms > 1000.0:
            return True
        return False

    def oracle(self) -> Oracle:
        """Determine the Oracle class for this differential.

        Heuristic: if any signal from "ownership" dimension → OWNERSHIP_VIOLATION.
        If "state" → STATE_TRANSITION. If body or status diff → BODY_CONTENT.
        Else STATUS_CODE_ONLY.
        """
        for s in self.signals:
            if s.dimension == "ownership":
                return Oracle.OWNERSHIP_VIOLATION
        for s in self.signals:
            if s.dimension == "state":
                return Oracle.STATE_TRANSITION
        if self.body_content_diff or any(s.dimension == "response" and s.kind in {SignalKind.BODY_DIFF, SignalKind.REFLECTION_DIFF} for s in self.signals):
            return Oracle.BODY_CONTENT
        return Oracle.STATUS_CODE_ONLY


def compute_differential(
    baseline: Response,
    controlled: Response,
    expected_signal: str = "",
) -> DifferentialResult:
    """Compare two responses and return the differential.

    Auto-populates standard signals based on what changed:
    - status_diff if status codes differ
    - body_diff if body content differs
    - body_length_delta if body length differs significantly
    - header_diff for each header that changed
    - timing_delta if response time differs by > 1s
    """
    status_diff = controlled.status_code - baseline.status_code
    body_length_diff = len(controlled.body) - len(baseline.body)
    body_content_diff = baseline.body != controlled.body
    timing_diff_ms = controlled.elapsed_ms - baseline.elapsed_ms

    # Header diff
    base_headers = {k.lower(): v for k, v in baseline.headers.items()}
    ctrl_headers = {k.lower(): v for k, v in controlled.headers.items()}
    header_diff: dict[str, tuple[str | None, str | None]] = {}
    for k in set(base_headers) | set(ctrl_headers):
        b = base_headers.get(k)
        c = ctrl_headers.get(k)
        if b != c:
            header_diff[k] = (b, c)

    result = DifferentialResult(
        status_diff=status_diff,
        body_length_diff=body_length_diff,
        body_content_diff=body_content_diff,
        header_diff=header_diff,
        timing_diff_ms=timing_diff_ms,
        baseline=baseline,
        controlled=controlled,
        expected_signal=expected_signal,
    )

    # Auto-populate signals from observed changes
    if status_diff != 0:
        result.add_signal(
            SignalKind.STATUS_DIFF,
            f"status {baseline.status_code} → {controlled.status_code}",
            weight=0.6,
        )
    if body_content_diff:
        result.add_signal(
            SignalKind.BODY_DIFF,
            "response body content differs",
            weight=0.8,
        )
    elif body_length_diff > 50:
        result.add_signal(
            SignalKind.BODY_LENGTH_DELTA,
            f"body length changed by {body_length_diff} bytes",
            weight=0.3,
        )
    for h, (b, c) in header_diff.items():
        if h.lower() in {"set-cookie", "location", "www-authenticate"}:
            # Security-relevant headers get full weight
            result.add_signal(
                SignalKind.HEADER_DIFF,
                f"header {h} changed",
                weight=1.0,
            )
        else:
            result.add_signal(
                SignalKind.HEADER_DIFF,
                f"header {h} changed",
                weight=0.3,
            )
    if abs(timing_diff_ms) > 1000.0:
        result.add_signal(
            SignalKind.TIMING_DELTA,
            f"timing delta {timing_diff_ms:.0f}ms",
            weight=0.7,
        )

    result.meaningful = result.is_meaningful()
    return result
