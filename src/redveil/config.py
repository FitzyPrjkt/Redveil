"""Pydantic configuration models for redveil.

The root config is ``RedVeilConfig`` — a ``pydantic-settings`` model that can be
loaded from a YAML or JSON file, or constructed from keyword arguments.

Every configuration object is immutable at runtime. Sub-models enforce strict
validation: a misconfigured authorization flag, an incomplete auth block, or
an upper-case host name should fail fast at load time, not at scan time.

Usage::

    cfg = RedVeilConfig.from_yaml("scope.yaml")
    # or
    cfg = RedVeilConfig(**yaml.safe_load(open("scope.yaml")))
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, HttpUrl, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class SafetyProfile(str, Enum):
    """How invasive a check is allowed to be.

    - PASSIVE: only observes; no mutation, no payload injection.
    - LOW_IMPACT: safe probes (CORS preflight, method check, header injection
      of benign values, harmless reflection tests).
    - ACTIVE: requires explicit authorization. Includes authenticated
      multi-principal tests, time-based blind probes, OOB callbacks,
      destructive-shaped validators (still bounded and non-payload-executing).
    """

    PASSIVE = "passive"
    LOW_IMPACT = "low_impact"
    ACTIVE = "active"


class AuthMethod(str, Enum):
    """Authentication strategy applied to every outbound request."""

    NONE = "none"
    COOKIE = "cookie"
    BEARER = "bearer"
    BASIC = "basic"
    CUSTOM_HEADER = "custom_header"


class TargetConfig(BaseModel):
    """What to scan."""

    base_url: HttpUrl
    name: str | None = None
    description: str | None = None


class ScopeConfig(BaseModel):
    """Strict scope enforcement: where the framework is allowed to send requests.

    Every outbound request passes through the ScopeController which validates
    against these rules. If a redirect chain hops outside, it is rejected.
    """

    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_paths: list[str] = Field(default_factory=list)  # glob patterns
    excluded_paths: list[str] = Field(default_factory=list)  # glob patterns, deny-list
    follow_redirects: bool = True
    max_redirects: int = 5

    @field_validator("allowed_hosts")
    @classmethod
    def _lower_hosts(cls, v: list[str]) -> list[str]:
        return [h.lower() for h in v if h]


class LimitsConfig(BaseModel):
    """Network and resource budgets applied by the HttpClient."""

    requests_per_second: float = 2.0
    max_requests: int = 500
    timeout_seconds: float = 10.0
    max_response_size_bytes: int = 5_000_000  # 5 MB
    max_concurrent_requests: int = 5
    connection_pool_size: int = 10


class AuthorizationConfig(BaseModel):
    """Explicit gates for invasive behavior.

    ``active_testing`` and ``acknowledged_safety_terms`` are intentionally
    separate: the former declares intent, the latter records the operator has
    read and accepted the safety model. The cross-field validator prevents
    enabling testing without acknowledgement.
    """

    active_testing: bool = False
    out_of_band_callback_domain: str | None = None  # e.g. "oast.example"
    acknowledged_safety_terms: bool = False

    @model_validator(mode="after")
    def _active_requires_acknowledgement(self) -> AuthorizationConfig:
        if self.active_testing and not self.acknowledged_safety_terms:
            raise ValueError(
                "authorization.active_testing=true requires "
                "authorization.acknowledged_safety_terms=true"
            )
        return self


class PrincipalConfig(BaseModel):
    """A named authentication principal for multi-principal testing (BOLA/IDOR).

    Each PrincipalConfig describes one of the test accounts the operator has
    provisioned. A check (e.g. ``bola-idor``) that needs to compare access
    outcomes across accounts reads the ``principals`` list and re-issues the
    same request as each principal in turn. The principal's identity is
    captured in the resulting Evidence so reports show which account accessed
    which resource.

    This is *not* a separate auth method — it's a parallel set of auth
    material that can be applied to a single request via the per-request
    ``auth_override_headers`` / ``auth_override_cookies`` fields on
    :class:`redveil.http.request.Request`.
    """

    name: str
    # For COOKIE
    cookies: list[dict[str, str]] = Field(default_factory=list)
    # For BEARER (alternative to cookies)
    bearer_token: str | None = None
    # For BASIC (alternative to cookies)
    basic_username: str | None = None
    basic_password: str | None = None
    # Extra free-form headers always applied alongside this principal's auth
    extra_headers: dict[str, str] = Field(default_factory=dict)

    def to_override(self) -> tuple[dict[str, str], dict[str, str]]:
        """Render this principal as ``(headers, cookies)`` overrides for a
        single Request.

        Returns a 2-tuple that can be applied on top of the configured
        ``AuthProvider`` to make the request look like it came from this
        principal. The returned values are sensitive — Evidence sanitization
        is responsible for redacting them in reports.
        """
        import base64

        headers: dict[str, str] = dict(self.extra_headers)
        cookies: dict[str, str] = {
            c["name"]: c["value"]
            for c in self.cookies
            if "name" in c and "value" in c
        }
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        if self.basic_username and self.basic_password:
            token = base64.b64encode(
                f"{self.basic_username}:{self.basic_password}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {token}"
        return headers, cookies


class AuthConfig(BaseModel):
    """Authentication material applied by the configured AuthProvider."""

    method: AuthMethod = AuthMethod.NONE
    # For COOKIE: list of {name, value} dicts OR path to cookie jar
    cookies: list[dict[str, str]] = Field(default_factory=list)
    cookie_jar_path: str | None = None
    # For BEARER
    token: str | None = None
    # For BASIC
    username: str | None = None
    password: str | None = None
    # For CUSTOM_HEADER
    header_name: str | None = None
    header_value: str | None = None
    # Extra free-form headers applied to all requests
    extra_headers: dict[str, str] = Field(default_factory=dict)
    # Multi-principal auth for BOLA/IDOR testing. Empty list = single-principal
    # mode (the framework still uses ``method`` + ``cookies``/``token``).
    principals: list[PrincipalConfig] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_method_fields(self) -> AuthConfig:
        if self.method is AuthMethod.BEARER and not self.token:
            raise ValueError("BEARER auth requires 'token'")
        if self.method is AuthMethod.BASIC and (not self.username or not self.password):
            raise ValueError("BASIC auth requires 'username' and 'password'")
        if self.method is AuthMethod.CUSTOM_HEADER and (
            not self.header_name or not self.header_value
        ):
            raise ValueError(
                "CUSTOM_HEADER auth requires 'header_name' and 'header_value'"
            )
        # Validate each principal has *some* auth material — an empty
        # principal would produce a no-op request indistinguishable from
        # anonymous access.
        for i, p in enumerate(self.principals):
            if not (p.cookies or p.bearer_token or (p.basic_username and p.basic_password)):
                raise ValueError(
                    f"auth.principals[{i}] ({p.name!r}) has no auth material "
                    "(need cookies, bearer_token, or basic_username/password)"
                )
        return self


class ReportingConfig(BaseModel):
    """Reporting configuration."""

    output_dir: Path = Path("reports")
    formats: list[Literal["markdown", "json", "html"]] = Field(
        default_factory=lambda: ["markdown", "json"]
    )
    redact_secrets: bool = True


class RedVeilConfig(BaseSettings):
    """Root config. Can be loaded from YAML/JSON via pydantic-settings.

    Usage::

        cfg = RedVeilConfig.from_yaml("scope.yaml")
        # or
        cfg = RedVeilConfig(**yaml.safe_load(open("scope.yaml")))
    """

    model_config = SettingsConfigDict(
        env_prefix="REDVEIL_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    target: TargetConfig
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    authorization: AuthorizationConfig = Field(default_factory=AuthorizationConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    profile: SafetyProfile = SafetyProfile.PASSIVE

    @classmethod
    def from_yaml(cls, path: str | Path) -> RedVeilConfig:
        """Load configuration from a YAML file.

        Imported lazily so the module is usable in environments without
        ``pyyaml`` installed (the dependency is required by the package
        anyway, but this keeps the import site explicit).
        """
        import yaml

        with open(path) as f:
            data = yaml.safe_load(f)
        if data is None:
            raise ValueError(f"Empty config file: {path}")
        return cls(**data)
