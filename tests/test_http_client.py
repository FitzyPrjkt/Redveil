"""Tests for HttpClient — the transport layer.

We mock httpx with respx so these are pure unit tests (no real network).
The scope and rate-limit tests live in their own modules; here we focus on:

* Scope enforcement at the .send() boundary.
* LimitsConfig enforcement (max_requests, response-size cap, timeout).
* Redirect-chain revalidation.
* Request/Response field plumbing (request_id, body truncation, etc.).
"""

from __future__ import annotations

import pytest
import respx
from httpx import Response as HttpxResponse

from redveil.config import LimitsConfig, ScopeConfig
from redveil.core.scope import ScopeController, ScopeViolation
from redveil.http.client import HttpClient
from redveil.http.request import Request

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _scope(
    *,
    hosts: list[str] | None = None,
    allowed_paths: list[str] | None = None,
    excluded_paths: list[str] | None = None,
) -> ScopeController:
    return ScopeController(
        ScopeConfig(
            allowed_hosts=hosts if hosts is not None else ["example.com"],
            allowed_paths=allowed_paths if allowed_paths is not None else [],
            excluded_paths=excluded_paths if excluded_paths is not None else [],
        )
    )


def _limits(**overrides: int | float) -> LimitsConfig:
    """Build a LimitsConfig with test-friendly defaults."""
    defaults: dict[str, int | float] = {
        "requests_per_second": 1000.0,
        "max_concurrent_requests": 10,
        "max_requests": 100,
        "timeout_seconds": 5.0,
        "max_response_size_bytes": 1024 * 1024,
        "connection_pool_size": 10,
    }
    defaults.update(overrides)
    return LimitsConfig(**defaults)  # type: ignore[arg-type]


def _request(
    url: str,
    *,
    method: str = "GET",
    request_id: str = "req-test",
) -> Request:
    return Request(
        request_id=request_id,
        method=method,
        url=url,
        headers={},
        body=None,
        cookies={},
    )


# ---------------------------------------------------------------------------
# Scope enforcement
# ---------------------------------------------------------------------------


async def test_send_raises_scope_violation_for_out_of_scope_host() -> None:
    """A request to a host not in the allowlist is blocked before sending."""
    client_scope = _scope(hosts=["example.com"])
    client = HttpClient(client_scope, _limits())
    async with client:
        with pytest.raises(ScopeViolation) as exc_info:
            await client.send(_request("https://attacker.com/api"))
    assert "attacker.com" in str(exc_info.value)
    # No request was actually counted.
    assert client.request_count == 0


async def test_send_allows_in_scope_host() -> None:
    """An in-scope host is permitted through to the transport."""
    with respx.mock(assert_all_called=True) as mock:
        mock.get("https://example.com/api").mock(
            return_value=HttpxResponse(200, json={"ok": True})
        )
        async with HttpClient(_scope(), _limits()) as client:
            response = await client.send(_request("https://example.com/api"))
    assert response.status_code == 200
    assert response.error is None
    assert client.request_count == 1


# ---------------------------------------------------------------------------
# LimitsConfig enforcement
# ---------------------------------------------------------------------------


async def test_send_rejects_after_max_requests() -> None:
    """Once max_requests is reached, further .send() calls raise RuntimeError."""
    with respx.mock() as mock:
        mock.get("https://example.com/api").mock(
            return_value=HttpxResponse(200, text="ok")
        )
        async with HttpClient(_scope(), _limits(max_requests=2)) as client:
            await client.send(_request("https://example.com/api"))
            await client.send(_request("https://example.com/api"))
            assert client.request_count == 2
            with pytest.raises(RuntimeError) as exc_info:
                await client.send(_request("https://example.com/api"))
    assert "max_requests" in str(exc_info.value)


async def test_request_count_increments_per_send() -> None:
    """The request_count property tracks total successful sends."""
    with respx.mock() as mock:
        mock.get("https://example.com/a").mock(
            return_value=HttpxResponse(200, text="a")
        )
        mock.get("https://example.com/b").mock(
            return_value=HttpxResponse(200, text="b")
        )
        async with HttpClient(_scope(), _limits()) as client:
            await client.send(_request("https://example.com/a"))
            await client.send(_request("https://example.com/b"))
            assert client.request_count == 2


# ---------------------------------------------------------------------------
# Transport error handling
# ---------------------------------------------------------------------------


async def test_send_times_out_cleanly() -> None:
    """An httpx.TimeoutException is captured in Response.error, not raised."""
    # NOTE: Use httpx.TimeoutException, NOT bare TimeoutError. HttpClient._do_send
    # narrows its except clause to httpx.HTTPError, and httpx.TimeoutException
    # is the only TimeoutError subclass that also derives from httpx.HTTPError.
    # A bare TimeoutError would propagate unhandled and break this test.
    import httpx

    with respx.mock() as mock:
        # respx supports mocking timeouts via side_effect or a timeout response.
        mock.get("https://example.com/slow").mock(
            side_effect=httpx.TimeoutException("simulated timeout")
        )
        async with HttpClient(_scope(), _limits()) as client:
            # HttpClient catches httpx.TimeoutException via its httpx.HTTPError
            # except clause and records the failure on Response.error.
            response = await client.send(_request("https://example.com/slow"))
    assert response.error is not None
    assert response.status_code == 0


async def test_send_handles_connect_error() -> None:
    """An httpx.ConnectError is captured, not propagated."""
    import httpx

    with respx.mock() as mock:
        mock.get("https://example.com/down").mock(
            side_effect=httpx.ConnectError("connection refused")
        )
        async with HttpClient(_scope(), _limits()) as client:
            response = await client.send(_request("https://example.com/down"))
    assert response.error is not None
    assert "connect_error" in response.error


# ---------------------------------------------------------------------------
# Response size cap
# ---------------------------------------------------------------------------


async def test_response_truncated_when_oversized() -> None:
    """Responses larger than max_response_size_bytes are truncated, not crashed."""
    big_payload = "A" * (2 * 1024 * 1024)  # 2 MiB
    with respx.mock() as mock:
        mock.get("https://example.com/big").mock(
            return_value=HttpxResponse(200, text=big_payload)
        )
        async with HttpClient(
            _scope(), _limits(max_response_size_bytes=1024)
        ) as client:
            response = await client.send(_request("https://example.com/big"))
    assert response.body_truncated is True
    assert len(response.body) == 1024
    assert response.body == "A" * 1024


async def test_response_not_truncated_when_under_cap() -> None:
    """A response under the cap is delivered whole with body_truncated=False."""
    with respx.mock() as mock:
        mock.get("https://example.com/small").mock(
            return_value=HttpxResponse(200, text="hello")
        )
        async with HttpClient(
            _scope(), _limits(max_response_size_bytes=1024)
        ) as client:
            response = await client.send(_request("https://example.com/small"))
    assert response.body_truncated is False
    assert response.body == "hello"


# ---------------------------------------------------------------------------
# Request/Response plumbing
# ---------------------------------------------------------------------------


async def test_response_request_id_matches_request() -> None:
    """The Response's request_id echoes the Request's request_id."""
    with respx.mock() as mock:
        mock.get("https://example.com/api").mock(
            return_value=HttpxResponse(200, text="ok")
        )
        async with HttpClient(_scope(), _limits()) as client:
            response = await client.send(
                _request("https://example.com/api", request_id="abc-123")
            )
    assert response.request_id == "abc-123"


async def test_response_body_excerpt_is_capped() -> None:
    """body_excerpt is at most 500 chars, even if body is longer."""
    long = "X" * 1000
    with respx.mock() as mock:
        mock.get("https://example.com/long").mock(
            return_value=HttpxResponse(200, text=long)
        )
        async with HttpClient(_scope(), _limits()) as client:
            response = await client.send(_request("https://example.com/long"))
    assert len(response.body_excerpt) == 500
    assert response.body_excerpt == "X" * 500


async def test_response_records_headers_and_elapsed() -> None:
    """Status, headers, and elapsed_ms are populated on success."""
    with respx.mock() as mock:
        mock.get("https://example.com/api").mock(
            return_value=HttpxResponse(
                201,
                headers={"X-Test": "yes", "Content-Type": "text/plain"},
                text="created",
            )
        )
        async with HttpClient(_scope(), _limits()) as client:
            response = await client.send(_request("https://example.com/api"))
    assert response.status_code == 201
    assert response.headers.get("x-test") == "yes"
    assert response.elapsed_ms >= 0


# ---------------------------------------------------------------------------
# Redirect handling
# ---------------------------------------------------------------------------


async def test_in_scope_redirect_is_followed() -> None:
    """A 302 redirect to an in-scope host is followed and recorded in the chain."""
    with respx.mock(assert_all_called=False) as mock:
        # respx matches the second (final) request; the redirect itself is
        # mocked at the transport layer.
        mock.get("https://example.com/final").mock(
            return_value=HttpxResponse(200, text="final")
        )
        # We model the redirect by having the first call return 302 with a
        # Location header; respx does this directly.
        mock.get("https://example.com/start").mock(
            return_value=HttpxResponse(
                302, headers={"Location": "https://example.com/final"}
            )
        )
        async with HttpClient(_scope(), _limits()) as client:
            response = await client.send(
                _request("https://example.com/start")
            )
    assert response.status_code == 200
    assert response.body == "final"
    assert response.redirect_chain == ["https://example.com/final"]


async def test_redirect_to_out_of_scope_host_is_rejected() -> None:
    """A redirect to a host outside the allowlist raises ScopeViolation."""
    with respx.mock() as mock:
        mock.get("https://example.com/start").mock(
            return_value=HttpxResponse(
                302, headers={"Location": "https://attacker.com/steal"}
            )
        )
        async with HttpClient(_scope(), _limits()) as client:
            with pytest.raises(ScopeViolation) as exc_info:
                await client.send(_request("https://example.com/start"))
    assert "attacker.com" in str(exc_info.value)


async def test_redirect_disabled_returns_first_response() -> None:
    """With follow_redirects=False, the 302 is returned as-is."""
    with respx.mock() as mock:
        mock.get("https://example.com/start").mock(
            return_value=HttpxResponse(
                302, headers={"Location": "https://example.com/final"}
            )
        )
        async with HttpClient(
            _scope(), _limits(), follow_redirects=False
        ) as client:
            response = await client.send(
                _request("https://example.com/start")
            )
    assert response.status_code == 302
    assert response.redirect_chain == []


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


async def test_send_outside_context_raises() -> None:
    """Using HttpClient.send() without entering the async context raises."""
    client = HttpClient(_scope(), _limits())
    with pytest.raises(RuntimeError):
        await client.send(_request("https://example.com/api"))


async def test_context_manager_initializes_and_closes_client() -> None:
    """__aenter__ sets up the inner client; __aexit__ tears it down."""
    async with HttpClient(_scope(), _limits()) as client:
        # The inner httpx client is set.
        assert client._client is not None
    # After exit, the inner client is closed and reset.
    assert client._client is None


# ---------------------------------------------------------------------------
# Redirect-count cap
# ---------------------------------------------------------------------------


async def test_redirect_chain_exceeding_max_raises() -> None:
    """Chains longer than scope.max_redirects raise ScopeViolation."""
    # Configure scope with max_redirects=2.
    scope_cfg = ScopeConfig(
        allowed_hosts=["example.com"], max_redirects=2
    )
    client_scope = ScopeController(scope_cfg)

    # Build a 3-hop chain: A -> B -> C -> D. With max_redirects=2 we
    # can follow at most 2 hops, so the 3rd is rejected.
    with respx.mock(assert_all_called=False) as mock:
        route_a = mock.get("https://example.com/a")
        route_b = mock.get("https://example.com/b")
        route_c = mock.get("https://example.com/c")
        route_d = mock.get("https://example.com/d")
        route_a.mock(
            return_value=HttpxResponse(
                302, headers={"Location": "https://example.com/b"}
            )
        )
        route_b.mock(
            return_value=HttpxResponse(
                302, headers={"Location": "https://example.com/c"}
            )
        )
        route_c.mock(
            return_value=HttpxResponse(
                302, headers={"Location": "https://example.com/d"}
            )
        )
        route_d.mock(return_value=HttpxResponse(200, text="done"))

        async with HttpClient(client_scope, _limits()) as client:
            with pytest.raises(ScopeViolation) as exc_info:
                await client.send(_request("https://example.com/a"))
    assert "max_redirects" in str(exc_info.value)
