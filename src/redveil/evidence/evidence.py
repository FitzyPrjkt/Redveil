from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field

from redveil.http.request import Request
from redveil.http.response import Response


class ObservationKind(str, Enum):
    REFLECTION = "reflection"
    TIMING_DELTA = "timing_delta"
    STATUS_DIFF = "status_diff"
    BODY_DIFF = "body_diff"
    OOB_CALLBACK = "oob_callback"
    HEADER_PRESENT = "header_present"
    HEADER_MISSING = "header_missing"
    COOKIE_FLAG = "cookie_flag"
    REDIRECT_TARGET = "redirect_target"
    ERROR_DISCLOSURE = "error_disclosure"
    FILE_EXISTENCE = "file_existence"


class Evidence(BaseModel):
    """First-class evidence object. Reproducible + sanitizable."""
    id: str = Field(default_factory=lambda: f"EV-{uuid.uuid4().hex[:8]}")
    finding_id: str | None = None  # backref once attached
    request: Request
    response: Response | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    kind: ObservationKind
    endpoint: str
    method: str
    parameter: str | None = None
    input_used: str | None = None
    status_code: int | None = None
    relevant_headers: dict[str, str] = Field(default_factory=dict)
    body_excerpt: str = ""

    timing_ms: float | None = None
    observation: str = ""  # human-readable summary
    fingerprint: str = ""

    def compute_fingerprint(self) -> str:
        """Stable fingerprint for dedup. Hashes kind+endpoint+parameter+input+relevant_headers+status."""
        payload = "|".join([
            self.kind.value,
            self.endpoint,
            self.parameter or "",
            (self.input_used or "")[:200],
            str(self.status_code or ""),
            ",".join(f"{k.lower()}={v}" for k, v in sorted(self.relevant_headers.items())),
        ])
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def model_post_init(self, __context) -> None:
        if not self.fingerprint:
            object.__setattr__(self, "fingerprint", self.compute_fingerprint())
