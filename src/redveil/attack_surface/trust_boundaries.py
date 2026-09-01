"""Trust boundary — a place where authorization is supposed to be enforced.

Examples:
- Anonymous → Authenticated (login required)
- User → Admin (privilege escalation boundary)
- Tenant A → Tenant B (multi-tenant isolation)
- Public → Internal API (network-level boundary)

Each trust boundary is associated with the set of Identities allowed to
cross it. A BOLA / BFLA / tenant-isolation check tests whether the
boundary holds in practice.
"""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass(frozen=True)
class TrustBoundary:
    """A boundary between two authorization zones.

    `allowed` lists the role names that may cross. Anything not in `allowed`
    is denied by policy. A successful test of the boundary means the
    boundary holds; a finding means it doesn't.
    """
    name: str
    from_zone: str
    to_zone: str
    allowed: frozenset[str] = field(default_factory=frozenset)

    def is_allowed(self, role: str) -> bool:
        return role in self.allowed

    def __hash__(self) -> int:
        return hash((self.from_zone, self.to_zone))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TrustBoundary):
            return NotImplemented
        return (self.from_zone, self.to_zone) == (other.from_zone, other.to_zone)


# Common trust boundaries the engine can use out of the box
ANONYMOUS_TO_USER = TrustBoundary(
    name="anonymous_to_user",
    from_zone="anonymous",
    to_zone="user",
    allowed=frozenset({"anonymous"}),  # anyone can attempt to authenticate
)

USER_TO_ADMIN = TrustBoundary(
    name="user_to_admin",
    from_zone="user",
    to_zone="admin",
    allowed=frozenset({"admin"}),  # only admins
)

TENANT_A_TO_TENANT_B = TrustBoundary(
    name="tenant_isolation",
    from_zone="tenant-a",
    to_zone="tenant-b",
    allowed=frozenset(),  # no cross-tenant by default
)
