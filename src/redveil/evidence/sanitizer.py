from __future__ import annotations

import re
from collections.abc import Iterable

from redveil.evidence.evidence import Evidence
from redveil.http.request import Request
from redveil.http.response import Response

# Patterns that look like secrets / tokens
_SECRET_PATTERNS = [
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "[JWT_REDACTED]"),  # JWT
    (re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{20,}"), "[STRIPE_KEY_REDACTED]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[AWS_ACCESS_KEY_REDACTED]"),
    (re.compile(r"ghp_[A-Za-z0-9]{30,}"), "[GITHUB_TOKEN_REDACTED]"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "[SLACK_TOKEN_REDACTED]"),
    (re.compile(r"\b(?:\d[ -]*?){13,16}\b"), "[CC_REDACTED]"),  # credit card
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), "[EMAIL_REDACTED]"),
]

_SENSITIVE_HEADER_NAMES = {
    "authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token",
    "x-csrf-token", "x-amz-security-token", "proxy-authorization",
}

_REDACTED = "[REDACTED]"


def _redact_text(text: str) -> str:
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    out = {}
    for k, v in headers.items():
        if k.lower() in _SENSITIVE_HEADER_NAMES:
            out[k] = _REDACTED
        else:
            out[k] = _redact_text(v)
    return out


def sanitize_request(req: Request) -> Request:
    """Return a new Request with secrets redacted."""
    return req.model_copy(update={
        "headers": _redact_headers(req.headers),
        "cookies": dict.fromkeys(req.cookies, _REDACTED),  # always redact cookies
        "body": _redact_text(req.body) if req.body else req.body,
    })


def sanitize_response(resp: Response) -> Response:
    """Return a new Response with secrets redacted."""
    return resp.model_copy(update={
        "headers": _redact_headers(resp.headers),
        "body": _redact_text(resp.body),
        "body_excerpt": _redact_text(resp.body_excerpt),
    })


def sanitize_evidence(ev: Evidence) -> Evidence:
    """Return a new Evidence with request/response sanitized."""
    return ev.model_copy(update={
        "request": sanitize_request(ev.request),
        "response": sanitize_response(ev.response) if ev.response else None,
        "input_used": _redact_text(ev.input_used) if ev.input_used else ev.input_used,
        "body_excerpt": _redact_text(ev.body_excerpt),
    })


def sanitize_evidence_list(evidence: Iterable[Evidence]) -> list[Evidence]:
    return [sanitize_evidence(e) for e in evidence]
