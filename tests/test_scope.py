"""Tests for the ScopeController — the primary safety rail.

These tests cover the host allowlist, path allowlist, exclude list,
destructive-path heuristics, and redirect-chain validation. They are pure
unit tests with no network I/O; they construct ScopeConfig objects directly.
"""

from __future__ import annotations

import pytest

from redveil.config import ScopeConfig
from redveil.core.scope import ScopeController, ScopeDecision, ScopeViolation


def _make_scope(
    *,
    hosts: list[str] | None = None,
    allowed_paths: list[str] | None = None,
    excluded_paths: list[str] | None = None,
) -> ScopeController:
    """Build a ScopeController with sensible defaults.

    Tests override only the fields they care about; everything else uses the
    minimal permissive defaults.
    """
    config = ScopeConfig(
        allowed_hosts=hosts if hosts is not None else ["example.com"],
        allowed_paths=allowed_paths if allowed_paths is not None else [],
        excluded_paths=excluded_paths if excluded_paths is not None else [],
    )
    return ScopeController(config)


# ---------------------------------------------------------------------------
# Host allowlist
# ---------------------------------------------------------------------------


def test_empty_allowed_hosts_rejects_everything() -> None:
    """An empty host list is fail-closed: all requests are denied."""
    scope = _make_scope(hosts=[])
    decision = scope.check("https://example.com/api")
    assert decision.allowed is False
    assert "allowed_hosts is empty" in decision.reason


@pytest.mark.parametrize(
    ("hosts", "url", "allowed", "reason_fragment"),
    [
        (["example.com"], "https://example.com/api", True, "in-scope"),
        (["example.com"], "https://EXAMPLE.com/api", True, "in-scope"),
        (["example.com"], "https://other.com/api", False, "not in scope.allowed_hosts"),
        (["example.com"], "https://sub.evil.com/api", False, "not in scope.allowed_hosts"),
        (["api.example.com"], "https://example.com/api", False, "not in scope.allowed_hosts"),
    ],
)
def test_host_allowlist(
    hosts: list[str], url: str, allowed: bool, reason_fragment: str
) -> None:
    """Host matching is exact, case-insensitive; subdomains do NOT implicitly match."""
    scope = _make_scope(hosts=hosts)
    decision = scope.check(url)
    assert decision.allowed is allowed
    assert reason_fragment in decision.reason or reason_fragment == "in-scope"


def test_url_without_scheme_rejected() -> None:
    """A URL with no scheme yields no hostname and is rejected."""
    scope = _make_scope(hosts=["example.com"])
    decision = scope.check("example.com/api")
    assert decision.allowed is False
    assert "hostname" in decision.reason


# ---------------------------------------------------------------------------
# Path allowlist (glob)
# ---------------------------------------------------------------------------


def test_allowed_paths_glob_matches() -> None:
    """A glob in allowed_paths matches all paths under the prefix."""
    scope = _make_scope(
        hosts=["example.com"],
        allowed_paths=["/api/*", "/health"],
    )
    assert scope.check("https://example.com/api/users").allowed is True
    assert scope.check("https://example.com/api/v1/orders/123").allowed is True
    assert scope.check("https://example.com/health").allowed is True


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/admin",
        "https://example.com/",
        "https://example.com/api",
        "https://example.com/static/app.js",
    ],
)
def test_allowed_paths_no_match_rejected(url: str) -> None:
    """If allowed_paths is configured, paths outside it are rejected."""
    scope = _make_scope(
        hosts=["example.com"],
        allowed_paths=["/api/*", "/health"],
    )
    decision = scope.check(url)
    assert decision.allowed is False
    assert "allowed_paths" in decision.reason


def test_empty_allowed_paths_means_allow_all() -> None:
    """With no allowed_paths configured, every path is permitted (host still gated)."""
    scope = _make_scope(hosts=["example.com"], allowed_paths=[])
    assert scope.check("https://example.com/anything").allowed is True
    assert scope.check("https://example.com/admin/secrets").allowed is True


# ---------------------------------------------------------------------------
# Path exclude list (deny-list)
# ---------------------------------------------------------------------------


def test_excluded_paths_blocks_even_when_allowed() -> None:
    """Excluded paths beat allowed paths — denial is sticky."""
    scope = _make_scope(
        hosts=["example.com"],
        allowed_paths=["/*"],  # allow everything
        excluded_paths=["/admin/*", "/logout"],
    )
    assert scope.check("https://example.com/api/users").allowed is True
    assert scope.check("https://example.com/admin/users").allowed is False
    assert scope.check("https://example.com/logout").allowed is False
    assert "excluded_paths" in scope.check("https://example.com/logout").reason


def test_excluded_paths_empty_blocks_nothing_extra() -> None:
    """An empty exclude list does not block anything beyond allowed_paths."""
    scope = _make_scope(
        hosts=["example.com"],
        allowed_paths=["/*"],
        excluded_paths=[],
    )
    assert scope.check("https://example.com/anything").allowed is True


# ---------------------------------------------------------------------------
# Destructive-path heuristics
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method",
    ["POST", "PUT", "DELETE", "PATCH"],
)
def test_destructive_path_blocks_mutating_methods(method: str) -> None:
    """Mutating methods to destructive-looking paths are rejected by default."""
    scope = _make_scope(
        hosts=["example.com"],
        allowed_paths=["/*"],  # wide allow so the destructive check is the gate
    )
    decision = scope.check("https://example.com/delete/user/42", method=method)
    assert decision.allowed is False
    assert "destructive path" in decision.reason


@pytest.mark.parametrize(
    "method",
    ["GET", "HEAD", "OPTIONS"],
)
def test_destructive_path_allows_readonly_methods(method: str) -> None:
    """Read-only methods to destructive-looking paths are allowed."""
    scope = _make_scope(
        hosts=["example.com"],
        allowed_paths=["/*"],
    )
    decision = scope.check("https://example.com/delete/user/42", method=method)
    assert decision.allowed is True


@pytest.mark.parametrize(
    "path",
    [
        "/delete/foo",
        "/remove/bar",
        "/drop/baz",
        "/purge/qux",
        "/admin/production/db",
        "/wipe/storage",
        "/destroy/account",
        "/reset/password",
    ],
)
def test_destructive_patterns_cover_known_dangerous_paths(path: str) -> None:
    """The default destructive patterns cover common dangerous operations."""
    scope = _make_scope(hosts=["example.com"], allowed_paths=["/*"])
    decision = scope.check(f"https://example.com{path}", method="POST")
    assert decision.allowed is False


def test_non_destructive_path_allows_post() -> None:
    """POST to a normal path is permitted (the destructive list is conservative)."""
    scope = _make_scope(hosts=["example.com"], allowed_paths=["/*"])
    decision = scope.check("https://example.com/api/users", method="POST")
    assert decision.allowed is True


def test_method_case_insensitive() -> None:
    """Method matching is case-insensitive (HTTP methods are uppercase by convention)."""
    scope = _make_scope(hosts=["example.com"], allowed_paths=["/*"])
    assert scope.check("https://example.com/delete/x", method="post").allowed is False
    assert scope.check("https://example.com/delete/x", method="PoSt").allowed is False


# ---------------------------------------------------------------------------
# Redirect-chain validation
# ---------------------------------------------------------------------------


def test_redirect_chain_all_in_scope() -> None:
    """A redirect chain whose every hop is in scope is permitted."""
    scope = _make_scope(hosts=["example.com"])
    chain = [
        "https://example.com/login",
        "https://example.com/oauth/callback",
        "https://example.com/dashboard",
    ]
    decision = scope.check_redirect_chain(chain[0], chain[1:])
    assert decision.allowed is True


def test_redirect_chain_middle_hop_escapes_scope() -> None:
    """If any hop escapes scope, the chain is rejected with the offender named."""
    scope = _make_scope(hosts=["example.com"])
    chain = [
        "https://example.com/login",
        "https://attacker.example.org/capture",  # escape
        "https://example.com/done",
    ]
    decision = scope.check_redirect_chain(chain[0], chain[1:])
    assert decision.allowed is False
    assert "attacker.example.org" in decision.reason
    assert "redirect chain" in decision.reason


def test_redirect_chain_last_hop_escapes_scope() -> None:
    """A late-hop escape is still caught."""
    scope = _make_scope(hosts=["example.com"])
    chain = [
        "https://example.com/a",
        "https://example.com/b",
        "https://example.com/c",
        "https://evil.com/exfil",
    ]
    decision = scope.check_redirect_chain(chain[0], chain[1:])
    assert decision.allowed is False
    assert "evil.com" in decision.reason


def test_redirect_chain_original_out_of_scope() -> None:
    """If the original URL is already out of scope, the chain is rejected up front."""
    scope = _make_scope(hosts=["example.com"])
    decision = scope.check_redirect_chain(
        "https://attacker.com/x",
        ["https://example.com/y"],
    )
    assert decision.allowed is False


def test_redirect_chain_empty_hops_is_validated_against_original_only() -> None:
    """With no hops, the chain reduces to a single check of the original URL."""
    scope = _make_scope(hosts=["example.com"])
    assert scope.check_redirect_chain("https://example.com/x", []).allowed is True
    assert scope.check_redirect_chain("https://evil.com/x", []).allowed is False


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------


def test_scope_decision_is_frozen() -> None:
    """ScopeDecision is a frozen dataclass — decisions are immutable."""
    decision = ScopeDecision(allowed=True, reason="ok")
    with pytest.raises(Exception):  # FrozenInstanceError, but don't pin it
        decision.allowed = False  # type: ignore[misc]


def test_scope_violation_is_exception() -> None:
    """ScopeViolation is a regular Exception subclass with useful messages."""
    exc = ScopeViolation("blocked")
    assert isinstance(exc, Exception)
    assert "blocked" in str(exc)


def test_repr_includes_config() -> None:
    """Repr is informative for debugging."""
    scope = _make_scope(hosts=["example.com"])
    rendered = repr(scope)
    assert "example.com" in rendered


def test_max_redirects_exposed_from_config() -> None:
    """max_redirects comes from ScopeConfig and is accessible via the controller."""
    cfg = ScopeConfig(allowed_hosts=["example.com"], max_redirects=3)
    scope = ScopeController(cfg)
    assert scope.max_redirects == 3

    cfg_default = ScopeConfig(allowed_hosts=["example.com"])
    assert ScopeController(cfg_default).max_redirects == 5  # default
