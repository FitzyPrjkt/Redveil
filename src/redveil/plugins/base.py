"""Plugin base class — the contract every check implements.

A check is a self-contained vulnerability detection unit. The framework is
plugin-agnostic: it knows nothing about specific checks, only that any
:class:`Check` subclass exposes a discover -> validate -> evidence -> assess
lifecycle and a :class:`CheckMeta` describing its safety profile.

Plugins cannot bypass the scope controller or instantiate their own HTTP
client. They receive wired-up dependencies via :class:`CheckDependencies`,
which makes them testable and prevents scope bypass by construction.
"""

from __future__ import annotations

from abc import ABC
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from redveil.evidence.evidence import Evidence

if TYPE_CHECKING:
    from redveil.config import RedVeilConfig, SafetyProfile
    from redveil.core.lifecycle import ScanContext
    from redveil.core.scope import ScopeController
    from redveil.http.client import HttpClient


class CheckCategory(str, Enum):
    """Logical grouping of checks. Maps to OWASP and PentestGuide categories."""
    HEADERS = "headers"
    TLS = "tls"
    DISCLOSURE = "disclosure"
    CORS = "cors"
    METHODS = "methods"
    REDIRECT = "redirect"
    DISCOVERY = "discovery"
    XSS = "xss"
    SQLI = "sqli"
    COMMAND_INJECTION = "command_injection"
    SSRF = "ssrf"
    PATH_TRAVERSAL = "path_traversal"
    FILE_INCLUSION = "file_inclusion"
    XXE = "xxe"
    SSTI = "ssti"
    DESERIALIZATION = "deserialization"
    FILE_UPLOAD = "file_upload"
    AUTH = "auth"
    IDOR = "idor"
    BFLA = "bfla"
    BUSINESS_LOGIC = "business_logic"
    SESSION = "session"
    CSRF = "csrf"
    CLICKJACKING = "clickjacking"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    POSTMESSAGE = "postmessage"
    DOM_CLOBBERING = "dom_clobbering"
    WEBSOCKET = "websocket"
    BROWSER_STORAGE = "browser_storage"
    GRAPHQL = "graphql"
    WEBHOOK = "webhook"
    RATE_LIMIT = "rate_limit"
    REQUEST_SMUGGLING = "request_smuggling"
    HOST_HEADER = "host_header"
    HPP = "hpp"
    INFRASTRUCTURE = "infrastructure"
    CLIENT_SIDE_URL = "client_side_url"
    GRAPHQL_INTROSPECTION = "graphql_introspection"
    API_VERSIONING = "api_versioning"
    MASS_ASSIGNMENT = "mass_assignment"
    EXCESSIVE_DATA_EXPOSURE = "excessive_data_exposure"
    ZIP_SLIP = "zip_slip"
    ARCHIVE_EXTRACTION = "archive_extraction"
    IMAGE_PROCESSING = "image_processing"
    MIME_CONFUSION = "mime_confusion"
    LFI = "lfi"
    FILE_OVERWRITE = "file_overwrite"
    DANGEROUS_FILE_TYPES = "dangerous_file_types"
    SESSION_FIXATION = "session_fixation"
    SESSION_HIJACKING = "session_hijacking"
    WEAK_TOKENS = "weak_tokens"
    SESSION_NOT_INVALIDATED = "session_not_invalidated"
    COOKIE_MISCONFIG = "cookie_misconfig"
    SAMESITE = "samesite"
    TOKEN_LEAKAGE = "token_leakage"
    EXPOSED_PANELS = "exposed_panels"
    DEBUG_INTERFACES = "debug_interfaces"
    CLOUD_METADATA = "cloud_metadata"


@dataclass
class CheckMeta:
    """Static metadata about a check plugin."""
    id: str
    name: str
    category: CheckCategory
    safety_profile: SafetyProfile
    version: str = "0.1.0"
    description: str = ""
    references: list[str] | None = None  # CWE IDs, OWASP links, etc.
    # Risk level of the actions this check performs. Used by ActionGate
    # to decide whether user confirmation is required. Defaults to NONE
    # for passive checks. Active checks should declare explicitly.
    max_risk: str = "none"   # "none" | "low" | "medium" | "high" | "blocked"


@dataclass
class CheckDependencies:
    """Wired-up dependencies passed to every check.

    A check must never instantiate its own HttpClient, ScopeController, or
    registry. It receives them here. This makes checks testable and prevents
    scope bypass.
    """
    http: HttpClient
    scope: ScopeController
    config: RedVeilConfig
    context: ScanContext
    # Optional Behavior Engine model + behavior. The orchestrator builds
    # these once per scan (via AttackSurfaceMapper) and passes them here.
    # Checks that don't use the new infrastructure can leave these as None.
    application_model: Any = None  # redveil.attack_surface.ApplicationModel
    behavior_model: Any = None     # redveil.behavior.BehaviorModel


class ValidationOutcome(str, Enum):
    """Outcome of validating a candidate finding."""
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    INCONCLUSIVE = "inconclusive"
    FALSE_POSITIVE = "false_positive"


class ValidationResult(BaseModel):
    """Return type of Check.validate().

    The orchestrator uses the outcome to decide whether to keep the candidate:
        CONFIRMED / LIKELY      -> collect evidence, then assess
        INCONCLUSIVE            -> keep with low confidence
        FALSE_POSITIVE          -> drop the candidate
    """
    outcome: ValidationOutcome
    confidence: str = "medium"  # high/medium/low
    evidence: list[Evidence] = Field(default_factory=list)
    observation: str = ""


class Check(ABC):
    """Base class for all vulnerability checks.

    Lifecycle:
        1. discover(ctx)         -> returns list of candidate indicators
        2. validate(ctx, c)      -> returns ValidationResult (CONFIRMED/LIKELY/FALSE_POSITIVE/INCONCLUSIVE)
        3. collect_evidence(c)   -> returns list[Evidence]
        4. assess(result)        -> returns Finding with severity + confidence

    A plugin may override any subset; the default is a discover-only check.
    """

    meta: CheckMeta

    def __init__(self) -> None:
        self._deps: CheckDependencies | None = None

    def bind(self, deps: CheckDependencies) -> None:
        """Bind dependencies. The framework injects the orchestrator-owned
        HttpClient and ScopeController. Plugins cannot supply their own.
        """
        if not isinstance(deps, CheckDependencies):
            raise TypeError(
                f"Check {self.meta.id}.bind() requires a CheckDependencies instance"
            )
        if deps.http is None or deps.scope is None:
            raise ValueError(
                f"Check {self.meta.id}.bind() got None for http/scope"
            )
        # Sanity: the HttpClient must be the same instance the orchestrator holds.
        # This is a soft check (object identity). Phase 2 will tighten via a registry
        # of authorized clients.
        if not hasattr(deps.http, "_scope") or deps.http._scope is not deps.scope:
            raise ValueError(
                f"Check {self.meta.id}: HttpClient is not bound to the supplied "
                "ScopeController. Plugin-supplied clients are not permitted."
            )
        self._deps = deps

    @property
    def deps(self) -> CheckDependencies:
        if self._deps is None:
            raise RuntimeError(f"Check {self.meta.id} used before .bind()")
        return self._deps

    @property
    def id(self) -> str:
        return self.meta.id

    @property
    def name(self) -> str:
        return self.meta.name

    @property
    def category(self) -> CheckCategory:
        return self.meta.category

    @property
    def safety_profile(self) -> SafetyProfile:
        return self.meta.safety_profile

    async def discover(self, ctx: ScanContext) -> list[Any]:
        """Return a list of candidate findings (raw indicators).

        Default: no candidates.
        """
        return []

    async def validate(self, ctx: ScanContext, candidate: Any) -> ValidationResult | None:
        """Validate a single candidate. Returns a ValidationResult or None.

        Returns:
            ValidationResult describing the outcome. The orchestrator uses
            the outcome to decide whether to proceed with evidence collection
            and assessment. Returns None to indicate "no validation needed"
            (e.g. a passive check already proven itself in discover()).
        """
        raise NotImplementedError(
            f"Check {self.meta.id} does not implement validate()"
        )

    async def collect_evidence(self, candidate: Any) -> list[Evidence]:
        """Collect evidence supporting the finding.

        Returns a list of Evidence objects (possibly empty). Called after a
        successful validate() — the orchestrator uses these to populate the
        final Finding's evidence_ids and reproduction steps.
        """
        return []

    async def assess(self, candidate: Any) -> Any:
        """Produce a Finding from a validated candidate.

        Returns a Finding object describing the vulnerability. The
        orchestrator appends it to the scan context after deduplication.
        """
        return None
