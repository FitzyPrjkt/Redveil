"""Parameter — a single parameter on an Endpoint.

Parameters can be in the path, query string, request body, or header. They
carry observed sample values (used for canary selection) and inferred
type (string, integer, email, uuid, etc.).
"""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum


class ParamLocation(str, Enum):
    PATH = "path"
    QUERY = "query"
    BODY = "body"
    HEADER = "header"
    COOKIE = "cookie"


class ParamType(str, Enum):
    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    EMAIL = "email"
    UUID = "uuid"
    URL = "url"
    ENUM = "enum"  # finite set of values
    TOKEN = "token"  # looks like a session token or API key
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Parameter:
    """A single parameter on an endpoint."""
    name: str
    location: ParamLocation
    type: ParamType = ParamType.UNKNOWN
    sample_values: tuple[str, ...] = ()
    required: bool = False

    @property
    def is_security_relevant(self) -> bool:
        """Heuristic: parameters named like auth/redirect/id/etc. are security-relevant."""
        name = self.name.lower()
        security_names = {
            "id", "user_id", "userid", "uid", "account", "account_id",
            "url", "redirect", "next", "return", "callback", "goto", "continue",
            "token", "session", "auth", "apikey", "api_key", "access_token",
            "file", "path", "page", "template", "include", "src", "source",
            "q", "search", "query", "input", "host", "ip", "target", "addr",
            "role", "admin", "is_admin", "permission", "scope",
        }
        return any(tok in name for tok in security_names) or self.type in {ParamType.TOKEN, ParamType.UUID}

    def __hash__(self) -> int:
        return hash((self.name, self.location.value))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Parameter):
            return NotImplemented
        return self.name == other.name and self.location == other.location
