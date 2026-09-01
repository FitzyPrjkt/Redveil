"""ApplicationModel — the complete model of the target as observed.

Collected by the AttackSurfaceMapper and consumed by check plugins and the
Behavior Engine. Holds endpoints, parameters, identities, objects, and
trust boundaries discovered during the scan.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Iterable

from redveil.attack_surface.endpoint import Endpoint
from redveil.attack_surface.identity import Identity
from redveil.attack_surface.object import Object
from redveil.attack_surface.trust_boundaries import TrustBoundary


@dataclass
class ApplicationModel:
    """The application-under-test model, as observed.

    Populated by the AttackSurfaceMapper. Checks read from it instead of
    building their own ad-hoc views of the target.
    """
    target_name: str = ""
    base_url: str = ""

    endpoints: dict[tuple[str, str], Endpoint] = field(default_factory=dict)
    identities: dict[str, Identity] = field(default_factory=dict)
    objects: dict[tuple[str, str], Object] = field(default_factory=dict)
    trust_boundaries: dict[str, TrustBoundary] = field(default_factory=dict)

    def add_endpoint(self, endpoint: Endpoint) -> None:
        self.endpoints[(endpoint.method.upper(), endpoint.path)] = endpoint

    def add_identity(self, identity: Identity) -> None:
        self.identities[identity.name] = identity

    def add_object(self, obj: Object) -> None:
        self.objects[(obj.type, obj.id)] = obj

    def add_trust_boundary(self, boundary: TrustBoundary) -> None:
        self.trust_boundaries[boundary.name] = boundary

    def get_endpoint(self, method: str, path: str) -> Endpoint | None:
        return self.endpoints.get((method.upper(), path))

    def iter_endpoints(self) -> Iterable[Endpoint]:
        return self.endpoints.values()

    def iter_identities(self) -> Iterable[Identity]:
        return self.identities.values()

    def iter_objects(self) -> Iterable[Object]:
        return self.objects.values()

    def find_objects_owned_by(self, identity_name: str) -> list[Object]:
        return [o for o in self.objects.values() if o.owner_id == identity_name]

    def find_objects_not_owned_by(self, identity_name: str) -> list[Object]:
        return [o for o in self.objects.values() if o.owner_id and o.owner_id != identity_name]

    def summary(self) -> dict[str, int]:
        return {
            "endpoints": len(self.endpoints),
            "identities": len(self.identities),
            "objects": len(self.objects),
            "trust_boundaries": len(self.trust_boundaries),
        }
