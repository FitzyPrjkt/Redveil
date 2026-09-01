"""Response model used internally for every inbound HTTP response.

Captures enough to reproduce, fingerprint, and re-render in evidence. Large
bodies are stored with their sha256 so evidence stays small while still being
diff-able across runs.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from pydantic import BaseModel, Field, computed_field


def _encode_body(body: str) -> bytes:
    """Encode body to bytes once. Module-level so lru_cache hits across
    Response instances that share the same body string.
    """
    return body.encode("utf-8", errors="replace")


class Response(BaseModel):
    """Internal representation of an HTTP response received by redveil.

    Captures enough to reproduce, fingerprint, and re-render in evidence.
    Large bodies are stored as excerpt + sha256 to keep evidence small.
    """

    request_id: str
    status_code: int
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    body_excerpt: str = ""  # first ~500 chars, suitable for embedding in reports
    body_truncated: bool = False
    elapsed_ms: float
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    remote_addr: str | None = None  # resolved IP — useful for SSRF/host-header evidence
    redirect_chain: list[str] = Field(default_factory=list)
    error: str | None = None  # timeout, connection error, etc.

    @computed_field  # type: ignore[prop-decorator]
    @property
    def body_sha256(self) -> str:
        return hashlib.sha256(_encode_body(self.body)).hexdigest()

    @computed_field  # type: ignore[prop-decorator]
    @property
    def body_length(self) -> int:
        return len(_encode_body(self.body))
