"""Attack surface model — the structured representation of the target.

Modules:
- endpoint: a discoverable HTTP endpoint
- parameter: a single parameter on an endpoint
- identity: an authenticated principal
- object: a domain entity with an owner
- trust_boundaries: authorization zones
- model: the complete ApplicationModel
- mapper: builds the model from observed traffic
"""
from redveil.attack_surface.endpoint import Endpoint
from redveil.attack_surface.parameter import Parameter, ParamLocation, ParamType
from redveil.attack_surface.identity import Identity, AuthMethod
from redveil.attack_surface.object import Object
from redveil.attack_surface.trust_boundaries import TrustBoundary, ANONYMOUS_TO_USER, USER_TO_ADMIN, TENANT_A_TO_TENANT_B
from redveil.attack_surface.model import ApplicationModel
from redveil.attack_surface.mapper import AttackSurfaceMapper

__all__ = [
    "Endpoint",
    "Parameter", "ParamLocation", "ParamType",
    "Identity", "AuthMethod",
    "Object",
    "TrustBoundary", "ANONYMOUS_TO_USER", "USER_TO_ADMIN", "TENANT_A_TO_TENANT_B",
    "ApplicationModel",
    "AttackSurfaceMapper",
]
