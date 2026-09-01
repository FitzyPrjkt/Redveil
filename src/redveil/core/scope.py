"""Strict scope controller — the primary safety rail of redveil.

Every outbound HTTP request MUST pass through ScopeController.check() before
being sent. The controller enforces:

* Host allowlist (case-insensitive, exact match).
* Path allowlist (glob patterns) and path exclude list (deny-list).
* Destructive-path heuristics: mutating methods to destructive-looking paths
  are rejected unless the path is explicitly allowed.
* Redirect-chain validation: every hop in a 3xx chain must remain in scope.

Plugins cannot bypass this controller — they receive an HttpClient instance
that calls ScopeController internally. If a plugin attempts an out-of-scope
request, ScopeViolation is raised before any byte is put on the wire.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from urllib.parse import urlparse

from redveil.config import ScopeConfig


@dataclass(frozen=True)
class ScopeDecision:
    """Outcome of a scope check.

    `allowed` is the boolean verdict; `reason` is a human-readable explanation
    intended for logs and operator-facing reports. Never expose `reason` to
    end-user targets.
    """

    allowed: bool
    reason: str = ""


class ScopeViolation(Exception):
    """Raised when an outbound request would leave the authorized scope.

    The HTTP transport raises this for any blocked request. Plugins that
    receive a ScopeViolation should treat it as a hard failure — never retry
    or attempt to work around it.
    """


class ScopeController:
    """Centralized enforcement of the testing scope.

    The HTTP transport layer calls ScopeController.check() on every request
    before sending. Plugins receive an HttpClient and call .send(); the
    client performs the gatekeeping. There is no other path to the network.

    Configuration:
        ScopeConfig.allowed_hosts — set of hostnames the framework may contact.
        ScopeConfig.allowed_paths — list of glob patterns for in-scope paths.
        ScopeConfig.excluded_paths — list of glob patterns always blocked
            (evaluated AFTER allowed_paths).
    """

    # Destructive path patterns. Requests to these with mutating methods are
    # rejected unless the path is explicitly whitelisted in
    # ScopeConfig.allowed_paths (a match there is required, but not sufficient
    # — the mutating method check still applies). These are deliberately
    # conservative defaults; operators must explicitly add dangerous patterns
    # they need to test.
    DEFAULT_DESTRUCTIVE_PATTERNS = (
        "/delete/*",
        "/remove/*",
        "/drop/*",
        "/purge/*",
        "/admin/production/*",
        "/wipe/*",
        "/destroy/*",
        "/reset/*",
    )

    # HTTP methods considered mutating for the destructive-pattern check.
    # GET, HEAD, OPTIONS are never mutating. CONNECT and TRACE are also
    # safe; the rest of the standard methods are treated as mutating.
    MUTATING_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})

    def __init__(self, config: ScopeConfig):
        self._config = config
        self._allowed_hosts: set[str] = {h.lower() for h in config.allowed_hosts}
        self._allowed_paths: list[str] = list(config.allowed_paths)
        self._excluded_paths: list[str] = list(config.excluded_paths)
        self._destructive_patterns: list[str] = list(self.DEFAULT_DESTRUCTIVE_PATTERNS)

    @property
    def allowed_hosts(self) -> frozenset[str]:
        """Read-only view of the lowercased allowed-host set."""
        return frozenset(self._allowed_hosts)

    @property
    def max_redirects(self) -> int:
        """Maximum redirect hops permitted in a single chain."""
        return self._config.max_redirects

    def check(self, url: str, method: str = "GET") -> ScopeDecision:
        """Validate a single URL against the scope. Returns decision.

        Order of checks (fail-fast):
            1. allowed_hosts is non-empty (else reject everything).
            2. URL hostname is in allowed_hosts.
            3. URL path matches an allowed_paths glob (if any are configured).
            4. URL path is not in excluded_paths.
            5. If method is mutating and path matches a destructive pattern,
               reject.
        """
        parsed = urlparse(url)

        # urlparse needs a scheme to extract hostname correctly. If the URL
        # doesn't have one, hostname is None — which we treat as out-of-scope.
        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"
        method_upper = method.upper()

        if not self._allowed_hosts:
            return ScopeDecision(
                False,
                "scope.allowed_hosts is empty; refusing all requests",
            )

        if not host:
            return ScopeDecision(
                False,
                f"could not extract hostname from URL '{url}'",
            )

        if host not in self._allowed_hosts:
            return ScopeDecision(
                False,
                f"host '{host}' is not in scope.allowed_hosts",
            )

        if not self._path_allowed(path):
            return ScopeDecision(
                False,
                f"path '{path}' matches no allowed_paths entry",
            )

        if self._path_excluded(path):
            return ScopeDecision(
                False,
                f"path '{path}' matches scope.excluded_paths",
            )

        if (
            method_upper in self.MUTATING_METHODS
            and self._path_destructive(path)
        ):
            return ScopeDecision(
                False,
                f"mutating {method_upper} to destructive path '{path}' is not allowed",
            )

        return ScopeDecision(True, "in-scope")

    def check_redirect_chain(
        self, original_url: str, chain: list[str]
    ) -> ScopeDecision:
        """Validate that every hop in a redirect chain stays in scope.

        The original URL is checked first; then each hop in `chain` is checked
        in order. The first hop that escapes scope causes rejection with a
        message naming the offending URL.
        """
        decision = self.check(original_url)
        if not decision.allowed:
            return decision
        for hop in chain:
            d = self.check(hop)
            if not d.allowed:
                return ScopeDecision(
                    False,
                    f"redirect chain escapes scope at '{hop}': {d.reason}",
                )
        return ScopeDecision(True, "all hops in scope")

    def _path_allowed(self, path: str) -> bool:
        """An empty allowed_paths list means 'allow all' (host already gated)."""
        if not self._allowed_paths:
            return True
        return any(fnmatch.fnmatch(path, p) for p in self._allowed_paths)

    def _path_excluded(self, path: str) -> bool:
        """An empty excluded_paths list means 'deny nothing extra'."""
        return any(fnmatch.fnmatch(path, p) for p in self._excluded_paths)

    def _path_destructive(self, path: str) -> bool:
        return any(
            fnmatch.fnmatch(path, p) for p in self._destructive_patterns
        )

    def __repr__(self) -> str:
        return (
            f"ScopeController(allowed_hosts={sorted(self._allowed_hosts)}, "
            f"allowed_paths={self._allowed_paths}, "
            f"excluded_paths={self._excluded_paths})"
        )
