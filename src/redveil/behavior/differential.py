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
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

from redveil.http.request import Request
from redveil.http.response import Response


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

    def is_meaningful(self) -> bool:
        """True if at least one indicator changed in a security-relevant way."""
        if self.status_diff != 0:
            return True
        if self.body_content_diff:
            return True
        if any(a != b for a, b in self.header_diff.values()):
            return True
        if self.timing_diff_ms > 1000.0:  # > 1s timing difference is significant
            return True
        return False


def compute_differential(
    baseline: Response,
    controlled: Response,
    expected_signal: str = "",
) -> DifferentialResult:
    """Compare two responses and return the differential."""
    result = DifferentialResult(
        status_diff=controlled.status_code - baseline.status_code,
        body_length_diff=len(controlled.body) - len(baseline.body),
        body_content_diff=baseline.body != controlled.body,
        timing_diff_ms=controlled.elapsed_ms - baseline.elapsed_ms,
        baseline=baseline,
        controlled=controlled,
        expected_signal=expected_signal,
    )

    # Header diff
    base_headers = {k.lower(): v for k, v in baseline.headers.items()}
    ctrl_headers = {k.lower(): v for k, v in controlled.headers.items()}
    for k in set(base_headers) | set(ctrl_headers):
        b = base_headers.get(k)
        c = ctrl_headers.get(k)
        if b != c:
            result.header_diff[k] = (b, c)

    result.meaningful = result.is_meaningful()
    return result
