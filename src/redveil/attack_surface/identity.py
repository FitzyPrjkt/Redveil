"""Identity / Principal — an authenticated actor in the Application Model.

Identities are used by multi-principal checks (BOLA, BFLA, session-fixation,
mass-assignment). Each Identity carries its own authentication state
(cookies, tokens) and role(s).
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum


class AuthMethod(str, Enum):
    NONE = "none"
    COOKIE = "cookie"
    BEARER = "bearer"
    BASIC = "basic"
    CUSTOM_HEADER = "custom_header"


@dataclass
class Identity:
    """An authenticated actor in the system under test.

    The Identity carries:
    - a unique name (for logging and reports)
    - a role (for BOLA/BFLA comparison)
    - authentication material (cookies, tokens) for the HTTP client to use
    """
    name: str
    role: str = "user"  # "user", "admin", "tenant-a", "anonymous", etc.
    auth_method: AuthMethod = AuthMethod.NONE
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    bearer_token: str | None = None
    basic_user: str | None = None
    basic_pass: str | None = None

    def is_authenticated(self) -> bool:
        return self.auth_method != AuthMethod.NONE

    def to_override(self) -> tuple[dict[str, str], dict[str, str]]:
        """Render to (headers, cookies) for per-request override.

        The HTTP client merges these on top of the base auth when the request
        specifies this Identity.
        """
        cookies = dict(self.cookies)
        headers = dict(self.headers)
        if self.auth_method == AuthMethod.BEARER and self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        elif self.auth_method == AuthMethod.BASIC and self.basic_user:
            import base64
            token = base64.b64encode(
                f"{self.basic_user}:{self.basic_pass or ''}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {token}"
        return headers, cookies

    def __hash__(self) -> int:
        return hash(self.name)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Identity):
            return NotImplemented
        return self.name == other.name
