"""Replay/Reproducibility engine.

A finding without a reproducible recipe is just a claim. The ReplayEngine
attempts to re-trigger the same observable behavior on the target using
the recipe attached to the finding. If the result is consistent across
replays, confidence is increased. If inconsistent (flaky target, time-
sensitive response, or rate-limited), confidence is decreased.

The ReplayRecipe is a structured, sanitized representation of the request
that originally produced the finding. It contains:
  - the target URL (with query parameters, without secrets in path)
  - HTTP method
  - sanitized headers (Authorization/Cookie values redacted)
  - request body (with placeholders for credentials)
  - the expected observable signal (status, body excerpt, etc.)

The ReplayResult records whether the recipe was consistent, and if not,
how it differed.
"""
from __future__ import annotations
import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from redveil.http.request import Request
from redveil.http.response import Response


@dataclass
class ReplayRecipe:
    """Structured, sanitized record of how to reproduce a finding.

    A finding without a recipe cannot be replayed. The check that produced
    the finding is responsible for filling in the recipe.
    """
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)  # sanitized
    body: str | None = None
    expected_status: int | None = None
    expected_body_excerpt: str = ""  # first 200 chars, for comparison
    expected_body_length: int | None = None
    expected_timing_ms: float | None = None
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    notes: str = ""

    def to_curl(self) -> str:
        """Render the recipe as a cURL command. Secrets in headers/body
        are redacted."""
        import shlex
        parts = [f"curl -X {self.method}"]
        for k, v in self.headers.items():
            if k.lower() in {"authorization", "cookie", "x-api-key"}:
                v = "[REDACTED]"
            parts += ["-H", shlex.quote(f"{k}: {v}")]
        if self.body:
            parts += ["--data-raw", shlex.quote(self.body)]
        parts.append(shlex.quote(self.url))
        return " ".join(parts)

    def fingerprint(self) -> str:
        """Stable hash of (method, url, sorted headers, body) for de-duplication."""
        h = hashlib.sha256()
        h.update(self.method.upper().encode())
        h.update(b"|")
        h.update(self.url.encode())
        h.update(b"|")
        for k in sorted(self.headers.keys()):
            h.update(f"{k.lower()}:{self.headers[k]}".encode())
        h.update(b"|")
        h.update((self.body or "").encode())
        return h.hexdigest()[:16]


@dataclass
class ReplayResult:
    """Result of replaying a recipe against the target."""
    recipe: ReplayRecipe
    responses: list[Response] = field(default_factory=list)  # multiple samples
    consistent: bool = True
    status_variance: int = 0  # max - min status across samples
    body_length_variance: int = 0
    body_content_match: bool = True
    timing_variance_ms: float = 0.0
    notes: str = ""

    @property
    def sample_count(self) -> int:
        return len(self.responses)

    def is_reliable(self) -> bool:
        """A finding is reliable if the recipe is consistent across replays.

        Reliable means: status code doesn't vary, body doesn't vary
        significantly, response time doesn't vary wildly.
        """
        return (
            self.consistent
            and self.status_variance == 0
            and self.body_length_variance < 50
            and self.timing_variance_ms < 1000.0
        )


class ReplayEngine:
    """Replays recipes to verify findings are reproducible.

    Each finding that has a ReplayRecipe can be replayed. The engine
    runs the recipe N times and reports whether the result is consistent.

    Usage:
        engine = ReplayEngine(http_client)
        result = await engine.replay(recipe, samples=3)
        if not result.is_reliable():
            # Flag the finding as flaky, reduce confidence
            pass
    """

    def __init__(self, http_client):
        self._http = http_client

    async def replay(
        self,
        recipe: ReplayRecipe,
        samples: int = 3,
    ) -> ReplayResult:
        """Replay the recipe N times. Returns aggregated result.

        Default 3 samples — enough to detect flakiness, fast enough to
        not bloat scans. Operator can override via config.
        """
        responses: list[Response] = []
        for _ in range(samples):
            try:
                req = Request(
                    method=recipe.method,
                    url=recipe.url,
                    headers=dict(recipe.headers),
                    body=recipe.body,
                    purpose="replay",
                )
                resp = await self._http.send(req)
                responses.append(resp)
            except Exception:
                continue
            # Small delay between samples to avoid triggering rate limits
            if samples > 1:
                time.sleep(0.1)

        if not responses:
            return ReplayResult(
                recipe=recipe,
                responses=[],
                consistent=False,
                notes="all replays failed (network error or target down)",
            )

        # Analyze consistency
        statuses = [r.status_code for r in responses]
        body_lengths = [len(r.body) for r in responses]
        timings = [r.elapsed_ms for r in responses]

        # Body content consistency: same first 200 chars?
        first_body = responses[0].body[:200]
        body_match = all(r.body[:200] == first_body for r in responses)

        return ReplayResult(
            recipe=recipe,
            responses=responses,
            consistent=(len(set(statuses)) == 1) and body_match,
            status_variance=max(statuses) - min(statuses),
            body_length_variance=max(body_lengths) - min(body_lengths),
            body_content_match=body_match,
            timing_variance_ms=max(timings) - min(timings),
            notes=(
                f"{len(responses)} samples; status={set(statuses)}; "
                f"body_len_range=[{min(body_lengths)}, {max(body_lengths)}]"
            ),
        )


# ---------------------------------------------------------------------------
# Helpers for building recipes from responses
# ---------------------------------------------------------------------------


def build_recipe_from_request(
    request: Request,
    response: Response | None = None,
    notes: str = "",
) -> ReplayRecipe:
    """Build a sanitized ReplayRecipe from a Request + observed Response.

    The headers are sanitized: secrets (Authorization, Cookie, X-API-Key)
    are redacted. The body is preserved as-is (it's typically the canary
    payload, not a secret).
    """
    sanitized_headers = {}
    for k, v in request.headers.items():
        if k.lower() in {"authorization", "cookie", "x-api-key", "x-auth-token"}:
            sanitized_headers[k] = "[REDACTED]"
        else:
            sanitized_headers[k] = v

    return ReplayRecipe(
        method=request.method,
        url=request.url,
        headers=sanitized_headers,
        body=request.body,
        expected_status=response.status_code if response else None,
        expected_body_excerpt=response.body_excerpt if response else "",
        expected_body_length=len(response.body) if response else None,
        expected_timing_ms=response.elapsed_ms if response else None,
        notes=notes,
    )
