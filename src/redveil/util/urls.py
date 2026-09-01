"""URL helpers shared across redveil.

Centralizes the logic for joining a base URL with a path so every check
and the orchestrator produce well-formed URLs (no accidental `//`).
"""
from __future__ import annotations


def join_url(base: str, path: str) -> str:
    """Join a base URL with a path, normalizing slashes.

    Equivalent to ``f"{base}/{path}"`` but without producing a double
    slash when either side already contains one. Examples::

        join_url("http://x", "/foo")        -> "http://x/foo"
        join_url("http://x/", "/foo")       -> "http://x/foo"
        join_url("http://x", "foo")         -> "http://x/foo"
        join_url("http://x/", "foo")        -> "http://x/foo"
        join_url("http://x//", "//foo")     -> "http://x/foo"

    Absolute URLs in ``path`` are returned unchanged — this is a join,
    not a strict override.
    """
    if not base:
        return path or ""
    if not path:
        return base.rstrip("/") or base

    # Absolute path: pass through. Callers that want override semantics
    # should check explicitly.
    if "://" in path:
        return path

    left = base.rstrip("/")
    right = path.lstrip("/")
    if not right:
        return left or base
    return f"{left}/{right}"
