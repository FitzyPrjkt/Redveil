"""Endpoint — a discoverable HTTP-accessible surface.

An Endpoint represents a unique URL + method combination. Parameters
(path, query, body, header) are attached. Auth requirements are tracked
implicitly via observed auth state during testing.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redveil.attack_surface.parameter import Parameter


@dataclass(frozen=True)
class Endpoint:
    """A unique HTTP endpoint identified by method + path.

    Example:
        Endpoint(method="GET", path="/api/users/{id}", auth_required="user")
    """
    method: str
    path: str
    auth_required: str | None = None  # None = anonymous, "user", "admin", etc.
    source: str = "crawl"  # where this was discovered: "crawl", "robots", "link", "form"
    parameters: tuple["Parameter", ...] = field(default_factory=tuple)

    @property
    def signature(self) -> str:
        """A stable signature for this endpoint (method + path)."""
        return f"{self.method.upper()} {self.path}"

    @property
    def has_parameters(self) -> bool:
        return len(self.parameters) > 0

    def with_params(self, params: list["Parameter"]) -> "Endpoint":
        """Return a new Endpoint with the given parameters."""
        return Endpoint(
            method=self.method,
            path=self.path,
            auth_required=self.auth_required,
            source=self.source,
            parameters=tuple(params),
        )

    def __hash__(self) -> int:
        return hash((self.method.upper(), self.path))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Endpoint):
            return NotImplemented
        return self.method.upper() == other.method.upper() and self.path == other.path
