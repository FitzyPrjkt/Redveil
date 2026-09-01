"""Oracle — defines what counts as evidence for a finding.

Different checks use different evidence. A status-code-only diff is a
weak oracle (could be a redirect, rate-limit, or unrelated change). A
state transition is a strong oracle (session was actually invalidated).
An ownership violation is a very strong oracle (we have direct proof
the boundary is broken).

Each check declares which Oracle class it uses. The Oracle informs
the ConfidenceScorer how to weight the signals it collected.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import IntEnum


class Oracle(IntEnum):
    """Strength of the evidence oracle.

    Higher value = stronger evidence. The ConfidenceScorer uses this as
    a base multiplier when scoring signals.
    """
    STATUS_CODE_ONLY = 1     # only HTTP status differs
    BODY_CONTENT = 2         # response body differs in content
    HEADER_VALUE = 2         # response header differs
    STATE_TRANSITION = 4     # observed authentication/state change
    OWNERSHIP_VIOLATION = 5  # direct proof: principal X accessed Y's resource


@dataclass
class Signal:
    """A single piece of evidence produced by differential analysis.

    Signals accumulate. The more independent signals support a hypothesis,
    the higher the confidence. Independent means the signals come from
    different dimensions (status vs body vs header vs state) — multiple
    signals from the same dimension count as one.
    """
    kind: str
    description: str
    weight: float = 1.0  # 0.0 to 1.0; how strong is this particular signal?
    dimension: str = "response"  # response | state | behavior | ownership

    def __hash__(self) -> int:
        return hash((self.kind, self.dimension))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Signal):
            return NotImplemented
        return self.kind == other.kind and self.dimension == other.dimension


# Standard signal types so different checks emit the same names
class SignalKind:
    """Catalog of standard signal kinds."""
    STATUS_DIFF = "status_diff"               # 200 vs 403
    BODY_DIFF = "body_diff"                     # different content
    BODY_LENGTH_DELTA = "body_length_delta"     # length change
    HEADER_DIFF = "header_diff"                 # different header value
    TIMING_DELTA = "timing_delta"               # significant timing change
    STATE_TRANSITION = "state_transition"       # e.g. AUTHED → INVALIDATED
    OWNERSHIP_VIOLATION = "ownership_violation" # B accessed A's object
    CANARY_REFLECTED = "canary_reflected"       # benign canary in response
    COOKIE_STILL_VALID = "cookie_still_valid"   # session not invalidated
    ADMIN_ENDPOINT_ACCESSIBLE = "admin_endpoint_accessible"
    REFLECTION_DIFF = "reflection_diff"         # different parameter reflection
    COOKIE_FLAG_MISSING = "cookie_flag_missing"
    WEAK_TOKEN_ENTROPY = "weak_token_entropy"
    TOKEN_IN_BODY = "token_in_body"
    SERVER_VERSION_DISCLOSED = "server_version_disclosed"
    CORS_ORIGIN_REFLECTED = "cors_origin_reflected"
    CORS_WILDCARD_WITH_CREDS = "cors_wildcard_with_creds"
    METHOD_ALLOWED = "method_allowed"
    EXPOSED_DEBUG_ENDPOINT = "exposed_debug_endpoint"
    SENSITIVE_FIELD_EXPOSED = "sensitive_field_exposed"
    OPEN_REDIRECT_PARAM = "open_redirect_param"
    GRAPHQL_INTROSPECTION = "graphql_introspection"
    SUBDOMAIN_DISCOVERED = "subdomain_discovered"

    # Dimension tags so the ConfidenceScorer can de-duplicate within dimension
    DIMENSION = {
        STATUS_DIFF: "response",
        BODY_DIFF: "response",
        BODY_LENGTH_DELTA: "response",
        HEADER_DIFF: "response",
        TIMING_DELTA: "response",
        CANARY_REFLECTED: "response",
        CORS_ORIGIN_REFLECTED: "response",
        CORS_WILDCARD_WITH_CREDS: "response",
        METHOD_ALLOWED: "response",
        EXPOSED_DEBUG_ENDPOINT: "response",
        SENSITIVE_FIELD_EXPOSED: "response",
        OPEN_REDIRECT_PARAM: "response",
        GRAPHQL_INTROSPECTION: "response",
        SUBDOMAIN_DISCOVERED: "response",
        SERVER_VERSION_DISCLOSED: "response",
        COOKIE_FLAG_MISSING: "response",
        REFLECTION_DIFF: "response",
        STATE_TRANSITION: "state",
        COOKIE_STILL_VALID: "state",
        OWNERSHIP_VIOLATION: "ownership",
        WEAK_TOKEN_ENTROPY: "behavior",
        TOKEN_IN_BODY: "behavior",
        ADMIN_ENDPOINT_ACCESSIBLE: "behavior",
    }
