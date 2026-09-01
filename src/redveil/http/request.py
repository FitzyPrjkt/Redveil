"""Request model used internally for every outbound HTTP call.

Every request issued by redveil — whether by discovery, a check, a validator,
or evidence collection — is represented as a ``Request`` instance so it can
be referenced by ``Evidence`` and reproduced verbatim.
"""

from __future__ import annotations

import shlex
import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, Field


class Request(BaseModel):
    """Internal representation of an HTTP request issued by redveil.

    Every outbound request — including those issued by checks, validators, and
    evidence collectors — must be represented as a Request object so it can be
    referenced by Evidence.
    """

    request_id: str = Field(default_factory=lambda: f"req-{uuid.uuid4().hex[:12]}")
    method: str
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    params: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    body_truncated: bool = False
    cookies: dict[str, str] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    timeout_seconds: float | None = None
    auth_principal: str | None = None  # for multi-principal IDOR testing
    # Per-request auth overrides for multi-principal testing (BOLA/IDOR). When
    # set, the HttpClient applies these on top of the configured AuthProvider,
    # effectively re-authenticating as a different principal for this request.
    auth_override_headers: dict[str, str] = Field(default_factory=dict)
    auth_override_cookies: dict[str, str] = Field(default_factory=dict)
    purpose: str = "discovery"  # discovery | probe | validation | evidence

    def to_curl(self, redact_secrets: bool = True) -> str:
        """Reproducible cURL form.

        If ``redact_secrets`` is True, ``Authorization`` and ``Cookie`` header
        values are replaced with ``[REDACTED]`` so evidence exports can be
        shared without leaking credentials.
        """
        parts: list[str] = [f"curl -X {self.method}"]
        for k, v in self.headers.items():
            value = v
            if redact_secrets and k.lower() in {"authorization", "cookie"}:
                value = "[REDACTED]"
            parts += ["-H", shlex.quote(f"{k}: {value}")]
        for ck, cv in self.cookies.items():
            value = cv
            if redact_secrets:
                value = "[REDACTED]"
            parts += ["-H", shlex.quote(f"Cookie: {ck}={value}")]
        if self.body is not None:
            parts += ["--data-raw", shlex.quote(self.body)]
        if self.params:
            qs = "&".join(f"{k}={v}" for k, v in self.params.items())
            parts.append(f"{self.url}?{qs}")
        else:
            parts.append(self.url)
        return " ".join(parts)
