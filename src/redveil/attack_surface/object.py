"""Object — a domain entity with an owner (used by BOLA, BFLA, mass-assignment).

An Object is something a user can own: an order, a document, a profile,
a comment. The owner_id links the object back to an Identity. BOLA checks
verify that the requesting identity is the owner of the object being accessed.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Object:
    """A domain entity the system manages.

    Example:
        Object(type="order", id="123", owner_id="alice", attributes={"total": 99.0})
    """
    type: str                       # "order", "user", "comment", etc.
    id: str                         # unique within type
    owner_id: str | None = None     # which Identity owns this object
    attributes: dict[str, Any] = field(default_factory=dict)
    source: str = "observation"     # how we learned about it: "api_response", "static", etc.

    def is_owned_by(self, identity_name: str) -> bool:
        return self.owner_id == identity_name

    def __hash__(self) -> int:
        return hash((self.type, self.id))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Object):
            return NotImplemented
        return self.type == other.type and self.id == other.id
