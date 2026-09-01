"""Environment awareness — distinguish dev/staging/prod/CDN/WAF/proxy.

Different environments produce different false-positive profiles:
- dev:  findings are usually real (no WAF, no caching, no rate limit)
- staging: similar to prod but may have leftover debug code
- production: needs more verification (WAF, CDN, rate limit, cache)
- CDN-fronted: server behavior may be masked by edge cache
- WAF-fronted: WAF may block probe requests or modify responses
- behind-proxy: X-Forwarded-* headers may affect server behavior
- behind-load-balancer: same backend may serve different requests

Each environment adjusts the confidence scoring. The adjustment is
applied via environmental_penalty in ConfidenceScorer.

Penalties (applied via environmental_penalty):
- dev: 0.0
- staging: 0.2
- production: 0.5
- cdn: 0.3
- waf: 0.6
- proxy: 0.2
- load_balancer: 0.3
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum


class Environment(str, Enum):
    """The kind of environment being scanned."""
    DEV = "dev"
    STAGING = "staging"
    PRODUCTION = "production"
    CDN = "cdn"                # behind a CDN (Cloudflare, Akamai, etc.)
    WAF = "waf"                # behind a WAF (ModSecurity, etc.)
    PROXY = "proxy"            # behind a reverse proxy (nginx, etc.)
    LOAD_BALANCER = "load_balancer"

    @classmethod
    def from_string(cls, value: str) -> "Environment":
        try:
            return cls(value.lower())
        except ValueError:
            aliases = {
                "prod": cls.PRODUCTION,
                "live": cls.PRODUCTION,
                "test": cls.STAGING,
                "qa": cls.STAGING,
                "localhost": cls.DEV,
            }
            return aliases.get(value.lower(), cls.PRODUCTION)


@dataclass
class EnvironmentProfile:
    """The deployment environment of the target.

    Multiple environments can be active (e.g., "production behind CDN with WAF").
    The total environmental_penalty is the sum of all active penalties.
    """
    environments: tuple[Environment, ...] = (Environment.PRODUCTION,)

    @classmethod
    def from_config(cls, env_str: str) -> "EnvironmentProfile":
        """Parse a comma-separated environment string from config.

        Example: "production,waf" → EnvironmentProfile with both active.
        """
        if not env_str:
            return cls()
        envs = tuple(Environment.from_string(s.strip()) for s in env_str.split(",") if s.strip())
        return cls(environments=envs or (Environment.PRODUCTION,))

    @property
    def environmental_penalty(self) -> float:
        """Sum of penalties from all active environments."""
        return sum(_PENALTIES.get(env, 0.0) for env in self.environments)

    @property
    def is_noisy(self) -> bool:
        """True if the environment is likely to introduce noise."""
        return any(env in _NOISY_ENVS for env in self.environments)

    def __str__(self) -> str:
        return ",".join(env.value for env in self.environments)


_PENALTIES: dict[Environment, float] = {
    Environment.DEV: 0.0,
    Environment.STAGING: 0.2,
    Environment.PRODUCTION: 0.5,
    Environment.CDN: 0.3,
    Environment.WAF: 0.6,
    Environment.PROXY: 0.2,
    Environment.LOAD_BALANCER: 0.3,
}

_NOISY_ENVS = {Environment.PRODUCTION, Environment.WAF, Environment.CDN}


# ---------------------------------------------------------------------------
# Uncertainty propagation
# ---------------------------------------------------------------------------


@dataclass
class Uncertainty:
    """A measure of how certain we are about an observation.

    Uncertainty is a value in [0.0, 1.0] where 0.0 = fully certain,
    1.0 = completely uncertain. It propagates through the pipeline:
    if any step has uncertainty > threshold, downstream confidence is
    downgraded.

    Sources of uncertainty:
    - Endpoint is flaky (Wave 4)
    - Response is ambiguous (e.g., WAF returns 403 for benign + malicious)
    - Network is unreliable (high latency, timeouts)
    - Target returned a cached response (stale data)
    """
    sources: dict[str, float] = field(default_factory=dict)

    @property
    def total(self) -> float:
        """Total uncertainty: returns max of all sources."""
        if not self.sources:
            return 0.0
        return max(self.sources.values())

    def add(self, source: str, value: float) -> None:
        self.sources[source] = min(1.0, max(0.0, value))

    def is_acceptable(self, threshold: float = 0.5) -> bool:
        """True if uncertainty is below the threshold (worth proceeding)."""
        return self.total <= threshold

    def to_penalty(self) -> float:
        """Convert uncertainty to a confidence penalty.

        relationship: uncertainty 0.0 → penalty 0.0, uncertainty 1.0
        → penalty 2.0 (significant downgrade).
        """
        return self.total * 2.0

    def __bool__(self) -> bool:
        return self.total > 0.0
