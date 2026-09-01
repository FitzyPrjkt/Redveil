"""Tests for configuration models."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from redveil.config import (
    AuthConfig,
    AuthMethod,
    AuthorizationConfig,
    LimitsConfig,
    RedVeilConfig,
    ReportingConfig,
    SafetyProfile,
    ScopeConfig,
    TargetConfig,
)

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# SafetyProfile enum
# ---------------------------------------------------------------------------


def test_safety_profile_values() -> None:
    assert SafetyProfile.PASSIVE.value == "passive"
    assert SafetyProfile.LOW_IMPACT.value == "low_impact"
    assert SafetyProfile.ACTIVE.value == "active"


def test_safety_profile_from_string() -> None:
    assert SafetyProfile("active") is SafetyProfile.ACTIVE


# ---------------------------------------------------------------------------
# ScopeConfig
# ---------------------------------------------------------------------------


def test_scope_lowercases_hosts() -> None:
    scope = ScopeConfig(allowed_hosts=["Example.COM", "API.Example.COM", ""])
    assert scope.allowed_hosts == ["example.com", "api.example.com"]


def test_scope_drops_empty_hosts() -> None:
    scope = ScopeConfig(allowed_hosts=["", "a.test", "   "])
    # whitespace-only strings are kept by the validator but empty strings dropped
    assert "a.test" in scope.allowed_hosts
    assert "" not in scope.allowed_hosts


def test_scope_defaults() -> None:
    scope = ScopeConfig()
    assert scope.allowed_hosts == []
    assert scope.allowed_paths == []
    assert scope.excluded_paths == []
    assert scope.follow_redirects is True
    assert scope.max_redirects == 5


# ---------------------------------------------------------------------------
# AuthorizationConfig
# ---------------------------------------------------------------------------


def test_authorization_active_requires_acknowledgement() -> None:
    with pytest.raises(ValidationError) as exc:
        AuthorizationConfig(active_testing=True, acknowledged_safety_terms=False)
    assert "acknowledged_safety_terms" in str(exc.value)


def test_authorization_passive_accepted() -> None:
    cfg = AuthorizationConfig(active_testing=False, acknowledged_safety_terms=False)
    assert cfg.active_testing is False


def test_authorization_acknowledged_with_active() -> None:
    cfg = AuthorizationConfig(active_testing=True, acknowledged_safety_terms=True)
    assert cfg.active_testing is True
    assert cfg.acknowledged_safety_terms is True


# ---------------------------------------------------------------------------
# AuthConfig validators
# ---------------------------------------------------------------------------


def test_auth_bearer_requires_token() -> None:
    with pytest.raises(ValidationError) as exc:
        AuthConfig(method=AuthMethod.BEARER, token=None)
    assert "token" in str(exc.value)


def test_auth_bearer_with_token_ok() -> None:
    cfg = AuthConfig(method=AuthMethod.BEARER, token="abc")
    assert cfg.token == "abc"


def test_auth_basic_requires_credentials() -> None:
    with pytest.raises(ValidationError) as exc:
        AuthConfig(method=AuthMethod.BASIC, username=None, password=None)
    assert "username" in str(exc.value) and "password" in str(exc.value)


def test_auth_basic_partial_credentials_rejected() -> None:
    with pytest.raises(ValidationError):
        AuthConfig(method=AuthMethod.BASIC, username="alice", password=None)
    with pytest.raises(ValidationError):
        AuthConfig(method=AuthMethod.BASIC, username=None, password="s3cret")


def test_auth_custom_header_requires_name_and_value() -> None:
    with pytest.raises(ValidationError) as exc:
        AuthConfig(method=AuthMethod.CUSTOM_HEADER, header_name=None, header_value=None)
    assert "header_name" in str(exc.value)
    assert "header_value" in str(exc.value)


def test_auth_anonymous_ok() -> None:
    cfg = AuthConfig()
    assert cfg.method is AuthMethod.NONE


# ---------------------------------------------------------------------------
# Other defaults
# ---------------------------------------------------------------------------


def test_target_config_basic() -> None:
    target = TargetConfig(base_url="https://example.com")  # type: ignore[arg-type]
    assert target.name is None


def test_limits_defaults() -> None:
    limits = LimitsConfig()
    assert limits.requests_per_second == 2.0
    assert limits.max_requests == 500
    assert limits.timeout_seconds == 10.0
    assert limits.max_response_size_bytes == 5_000_000


def test_reporting_defaults() -> None:
    rep = ReportingConfig()
    assert rep.output_dir == Path("reports")
    assert "markdown" in rep.formats
    assert rep.redact_secrets is True


# ---------------------------------------------------------------------------
# RedVeilConfig YAML loading
# ---------------------------------------------------------------------------


def test_redveilconfig_from_yaml(tmp_path: Path) -> None:
    # Use the shipped fixture directly
    fixture = FIXTURES / "scope.yaml"
    cfg = RedVeilConfig.from_yaml(fixture)
    assert str(cfg.target.base_url).rstrip("/") == "https://example.com"
    assert cfg.target.name == "Example Staging"
    assert "example.com" in cfg.scope.allowed_hosts
    assert cfg.limits.requests_per_second == 2
    assert cfg.authorization.active_testing is False
    assert cfg.profile is SafetyProfile.PASSIVE


def test_redveilconfig_from_yaml_missing_target(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("scope:\n  allowed_hosts: [x]\n")
    with pytest.raises(ValidationError):
        RedVeilConfig.from_yaml(bad)


def test_redveilconfig_from_yaml_empty_file(tmp_path: Path) -> None:
    empty = tmp_path / "empty.yaml"
    empty.write_text("")
    with pytest.raises(ValueError):
        RedVeilConfig.from_yaml(empty)


def test_redveilconfig_env_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDVEIL_PROFILE", "active")
    monkeypatch.setenv(
        "REDVEIL_AUTHORIZATION__ACTIVE_TESTING", "true"
    )
    monkeypatch.setenv(
        "REDVEIL_AUTHORIZATION__ACKNOWLEDGED_SAFETY_TERMS", "true"
    )
    cfg = RedVeilConfig(
        target=TargetConfig(base_url="https://example.com")  # type: ignore[arg-type]
    )
    assert cfg.profile is SafetyProfile.ACTIVE
    assert cfg.authorization.active_testing is True
    assert cfg.authorization.acknowledged_safety_terms is True
