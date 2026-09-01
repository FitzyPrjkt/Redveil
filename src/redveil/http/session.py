"""Auth providers and factory.

Each provider is a stateless strategy that mutates a per-request header and
cookie dict in place. The :func:`build_auth_provider` factory maps an
``AuthConfig`` to the appropriate subclass.

Implementations are required to be stateless and thread-safe: the HttpClient
will call ``apply(headers, cookies)`` once per request.
"""

from __future__ import annotations

import base64
from abc import ABC, abstractmethod

from redveil.config import AuthConfig, AuthMethod


class AuthProvider(ABC):
    """Strategy that applies auth material to outbound requests.

    Implementations must be stateless and thread-safe. The HttpClient will
    call .apply(headers, cookies) once per request to mutate the request
    in place. Sensitive values must not be logged.
    """

    @abstractmethod
    def apply(self, headers: dict[str, str], cookies: dict[str, str]) -> None:
        """Mutate headers/cookies in place."""

    @property
    @abstractmethod
    def identity(self) -> str:
        """Short label for logs and evidence (e.g. 'anonymous', 'principal-A')."""


class AnonymousAuth(AuthProvider):
    """No-op provider used when no authentication is configured."""

    def apply(self, headers: dict[str, str], cookies: dict[str, str]) -> None:
        return None

    @property
    def identity(self) -> str:
        return "anonymous"


class CookieAuth(AuthProvider):
    """Merges a static cookie dict into the outbound request."""

    def __init__(self, cookies: list[dict[str, str]], principal: str = "cookie-principal"):
        self._cookies = {
            c["name"]: c["value"] for c in cookies if "name" in c and "value" in c
        }
        self._principal = principal

    def apply(self, headers: dict[str, str], cookies: dict[str, str]) -> None:
        cookies.update(self._cookies)

    @property
    def identity(self) -> str:
        return self._principal


class BearerAuth(AuthProvider):
    """Adds an ``Authorization: Bearer <token>`` header."""

    def __init__(self, token: str, principal: str = "bearer-principal"):
        self._token = token
        self._principal = principal

    def apply(self, headers: dict[str, str], cookies: dict[str, str]) -> None:
        headers["Authorization"] = f"Bearer {self._token}"

    @property
    def identity(self) -> str:
        return self._principal


class BasicAuth(AuthProvider):
    """Adds an ``Authorization: Basic base64(user:pass)`` header."""

    def __init__(self, username: str, password: str, principal: str | None = None):
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        self._header = f"Basic {token}"
        self._principal = principal or f"basic:{username}"

    def apply(self, headers: dict[str, str], cookies: dict[str, str]) -> None:
        headers["Authorization"] = self._header

    @property
    def identity(self) -> str:
        return self._principal


class CustomHeaderAuth(AuthProvider):
    """Adds a free-form header (e.g. ``X-API-Key``)."""

    def __init__(self, name: str, value: str, principal: str | None = None):
        self._name = name
        self._value = value
        self._principal = principal or f"custom:{name}"

    def apply(self, headers: dict[str, str], cookies: dict[str, str]) -> None:
        headers[self._name] = self._value

    @property
    def identity(self) -> str:
        return self._principal


def build_auth_provider(
    config: AuthConfig, principal: str | None = None
) -> AuthProvider:
    """Factory that maps ``AuthConfig`` to an ``AuthProvider``.

    ``principal``: optional override identity for multi-principal testing.
    """
    name = principal
    match config.method:
        case AuthMethod.NONE:
            return AnonymousAuth()
        case AuthMethod.COOKIE:
            if not name:
                name = "cookie-principal"
            return CookieAuth(config.cookies, principal=name)
        case AuthMethod.BEARER:
            assert config.token is not None
            if not name:
                name = "bearer-principal"
            return BearerAuth(config.token, principal=name)
        case AuthMethod.BASIC:
            assert config.username is not None and config.password is not None
            if not name:
                name = f"basic:{config.username}"
            return BasicAuth(config.username, config.password, principal=name)
        case AuthMethod.CUSTOM_HEADER:
            assert config.header_name is not None and config.header_value is not None
            if not name:
                name = f"custom:{config.header_name}"
            return CustomHeaderAuth(
                config.header_name, config.header_value, principal=name
            )
