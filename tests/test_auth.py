"""Tests for AuthProvider implementations and the factory."""

from __future__ import annotations

import base64

import pytest

from redveil.config import AuthConfig, AuthMethod
from redveil.http.session import (
    AnonymousAuth,
    BasicAuth,
    BearerAuth,
    CookieAuth,
    CustomHeaderAuth,
    build_auth_provider,
)

# ---------------------------------------------------------------------------
# AnonymousAuth
# ---------------------------------------------------------------------------


def test_anonymous_leaves_headers_and_cookies_untouched() -> None:
    headers = {"X-Trace": "abc"}
    cookies = {"session": "xyz"}
    anon = AnonymousAuth()
    anon.apply(headers, cookies)
    assert headers == {"X-Trace": "abc"}
    assert cookies == {"session": "xyz"}
    assert anon.identity == "anonymous"


# ---------------------------------------------------------------------------
# CookieAuth
# ---------------------------------------------------------------------------


def test_cookie_auth_merges_cookies() -> None:
    cookies_in = [
        {"name": "session", "value": "abc"},
        {"name": "tracking", "value": "xyz"},
    ]
    auth = CookieAuth(cookies_in)
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}
    auth.apply(headers, cookies)
    assert cookies == {"session": "abc", "tracking": "xyz"}
    assert headers == {}


def test_cookie_auth_ignores_malformed_entries() -> None:
    cookies_in = [
        {"name": "ok", "value": "1"},
        {"name": "no_value"},  # type: ignore[list-item]
        {"value": "no_name"},  # type: ignore[list-item]
        {},
    ]
    auth = CookieAuth(cookies_in)
    cookies: dict[str, str] = {}
    auth.apply({}, cookies)
    assert cookies == {"ok": "1"}


def test_cookie_auth_default_identity() -> None:
    auth = CookieAuth([])
    assert auth.identity == "cookie-principal"


def test_cookie_auth_custom_identity() -> None:
    auth = CookieAuth([], principal="admin")
    assert auth.identity == "admin"


# ---------------------------------------------------------------------------
# BearerAuth
# ---------------------------------------------------------------------------


def test_bearer_auth_sets_authorization_header() -> None:
    auth = BearerAuth("deadbeef")
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}
    auth.apply(headers, cookies)
    assert headers["Authorization"] == "Bearer deadbeef"
    assert cookies == {}


def test_bearer_auth_identity() -> None:
    assert BearerAuth("t").identity == "bearer-principal"
    assert BearerAuth("t", principal="svc-account").identity == "svc-account"


# ---------------------------------------------------------------------------
# BasicAuth
# ---------------------------------------------------------------------------


def test_basic_auth_produces_correct_base64() -> None:
    auth = BasicAuth("alice", "s3cret")
    expected = "Basic " + base64.b64encode(b"alice:s3cret").decode()
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}
    auth.apply(headers, cookies)
    assert headers["Authorization"] == expected


def test_basic_auth_identity_default() -> None:
    auth = BasicAuth("alice", "s3cret")
    assert auth.identity == "basic:alice"


def test_basic_auth_identity_override() -> None:
    auth = BasicAuth("alice", "s3cret", principal="principal-A")
    assert auth.identity == "principal-A"


# ---------------------------------------------------------------------------
# CustomHeaderAuth
# ---------------------------------------------------------------------------


def test_custom_header_auth_sets_arbitrary_header() -> None:
    auth = CustomHeaderAuth("X-API-Key", "deadbeef")
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}
    auth.apply(headers, cookies)
    assert headers["X-API-Key"] == "deadbeef"
    assert cookies == {}


def test_custom_header_auth_identity() -> None:
    auth = CustomHeaderAuth("X-API-Key", "v")
    assert auth.identity == "custom:X-API-Key"
    auth2 = CustomHeaderAuth("X-API-Key", "v", principal="ci")
    assert auth2.identity == "ci"


# ---------------------------------------------------------------------------
# build_auth_provider factory
# ---------------------------------------------------------------------------


def test_factory_returns_anonymous_for_none() -> None:
    cfg = AuthConfig(method=AuthMethod.NONE)
    provider = build_auth_provider(cfg)
    assert isinstance(provider, AnonymousAuth)


def test_factory_returns_cookie_auth() -> None:
    cfg = AuthConfig(
        method=AuthMethod.COOKIE, cookies=[{"name": "a", "value": "b"}]
    )
    provider = build_auth_provider(cfg)
    assert isinstance(provider, CookieAuth)
    assert provider.identity == "cookie-principal"


def test_factory_returns_bearer_auth() -> None:
    cfg = AuthConfig(method=AuthMethod.BEARER, token="t")
    provider = build_auth_provider(cfg)
    assert isinstance(provider, BearerAuth)
    assert provider.identity == "bearer-principal"


def test_factory_returns_basic_auth() -> None:
    cfg = AuthConfig(method=AuthMethod.BASIC, username="u", password="p")
    provider = build_auth_provider(cfg)
    assert isinstance(provider, BasicAuth)
    assert provider.identity == "basic:u"


def test_factory_returns_custom_header_auth() -> None:
    cfg = AuthConfig(
        method=AuthMethod.CUSTOM_HEADER, header_name="X-K", header_value="v"
    )
    provider = build_auth_provider(cfg)
    assert isinstance(provider, CustomHeaderAuth)
    assert provider.identity == "custom:X-K"


def test_factory_principal_override() -> None:
    cfg = AuthConfig(method=AuthMethod.BEARER, token="t")
    provider = build_auth_provider(cfg, principal="principal-A")
    assert provider.identity == "principal-A"


def test_factory_asserts_required_fields() -> None:
    # If AuthConfig validation is bypassed, the factory asserts required fields.
    cfg = AuthConfig.model_construct(
        method=AuthMethod.BEARER, token=None
    )
    with pytest.raises(AssertionError):
        build_auth_provider(cfg)
