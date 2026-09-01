"""Async HTTP client, request/response abstractions, and transport configuration.

Public surface:

* :class:`~redveil.http.request.Request` — every outbound request.
* :class:`~redveil.http.response.Response` — every inbound response.
* Auth providers (:class:`AuthProvider` and concrete subclasses) and the
  :func:`build_auth_provider` factory.

The ``HttpClient`` itself is implemented in a later worker.
"""

from redveil.http.request import Request
from redveil.http.response import Response
from redveil.http.session import (
    AnonymousAuth,
    AuthProvider,
    BasicAuth,
    BearerAuth,
    CookieAuth,
    CustomHeaderAuth,
    build_auth_provider,
)

__all__ = [
    "AnonymousAuth",
    "AuthProvider",
    "BasicAuth",
    "BearerAuth",
    "CookieAuth",
    "CustomHeaderAuth",
    "Request",
    "Response",
    "build_auth_provider",
]
