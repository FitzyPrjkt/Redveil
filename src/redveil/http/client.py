"""Async HTTP client with built-in scope enforcement, rate limiting, and
redirect-chain revalidation.

HttpClient is the only network egress in redveil. Every outbound request
flows through:

    1. ScopeController.check()  — host, path, mutating-method gates
    2. LimitsConfig.max_requests — overall budget gate
    3. TokenBucket.acquire()     — global rate limit
    4. asyncio.Semaphore         — concurrency cap
    5. httpx.AsyncClient         — actual transport

Plugins never see httpx directly. They receive an HttpClient and call
.send(); the client does the gatekeeping. There is no "raw" mode.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

from redveil.config import LimitsConfig
from redveil.core.scope import ScopeController, ScopeViolation
from redveil.http.rate_limit import TokenBucket
from redveil.http.request import Request
from redveil.http.response import Response
from redveil.http.session import AnonymousAuth, AuthProvider


class HttpClient:
    """Async HTTP client with mandatory scope enforcement.

    Use as an async context manager:

        async with HttpClient(scope, limits, auth=auth) as client:
            response = await client.send(request)

    The client must be entered as an async context manager; using it bare
    raises RuntimeError on .send() so misconfiguration is caught loudly.
    """

    def __init__(
        self,
        scope: ScopeController,
        limits: LimitsConfig,
        auth: AuthProvider | None = None,
        follow_redirects: bool = True,
    ):
        self._scope = scope
        self._limits = limits
        self._auth: AuthProvider = auth or AnonymousAuth()
        self._follow_redirects = follow_redirects
        self._bucket = TokenBucket(
            rate=limits.requests_per_second,
            capacity=limits.max_concurrent_requests,
        )
        self._semaphore = asyncio.Semaphore(limits.max_concurrent_requests)
        self._request_count = 0
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> HttpClient:
        limits = httpx.Limits(
            max_connections=self._limits.connection_pool_size,
            max_keepalive_connections=self._limits.connection_pool_size,
        )
        # follow_redirects=False: we do redirects manually so every hop can
        # be scope-checked. Letting httpx follow automatically would be a
        # scope-bypass vector.
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self._limits.timeout_seconds),
            limits=limits,
            follow_redirects=False,
            verify=True,
            headers={"User-Agent": "redveil/0.1.0 (+authorized-testing)"},
        )
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @property
    def request_count(self) -> int:
        """Total requests dispatched by this client instance."""
        return self._request_count

    @property
    def scope_controller(self) -> ScopeController:
        """Exposed for tests and plugins that need to pre-validate URLs."""
        return self._scope

    async def send(self, request: Request) -> Response:
        """Validate, rate-limit, send, and record a single request.

        Raises:
            ScopeViolation: if the URL is out of scope.
            RuntimeError: if the client is used outside its async context,
                or if the max_requests budget is exhausted.
        """
        if self._client is None:
            raise RuntimeError("HttpClient used outside 'async with' context")

        decision = self._scope.check(request.url, method=request.method)
        if not decision.allowed:
            raise ScopeViolation(
                f"out-of-scope request blocked: {request.url} ({decision.reason})"
            )

        if self._request_count >= self._limits.max_requests:
            raise RuntimeError(
                f"max_requests limit ({self._limits.max_requests}) reached; "
                f"refusing further requests"
            )

        await self._bucket.acquire()
        async with self._semaphore:
            self._request_count += 1
            return await self._do_send(request, follow_chain=[])

    async def _do_send(
        self, request: Request, follow_chain: list[str]
    ) -> Response:
        """Perform a single HTTP round-trip (one hop). Recurses for redirects.

        Args:
            request: The Request to dispatch.
            follow_chain: URLs already visited in this redirect chain. Empty
                for the initial request; populated for each redirect hop.

        Returns:
            A Response describing the final destination (or the last
            successful hop if redirect-following is disabled).
        """
        assert self._client is not None
        headers = dict(request.headers)
        cookies = dict(request.cookies)
        self._auth.apply(headers, cookies)
        # Per-request auth overrides (used by BOLA/IDOR multi-principal tests).
        # They are applied AFTER the configured AuthProvider so the override
        # always wins. Empty dicts are a no-op so single-principal tests are
        # unaffected.
        if request.auth_override_headers:
            headers.update(request.auth_override_headers)
        if request.auth_override_cookies:
            cookies.update(request.auth_override_cookies)

        start = time.monotonic()
        error: str | None = None
        status = 0
        body = ""
        resp_headers: dict[str, str] = {}
        body_truncated = False
        remote_addr: str | None = None
        resp: httpx.Response | None = None

        try:
            resp = await self._client.request(
                method=request.method,
                url=request.url,
                params=request.params or None,
                headers=headers,
                cookies=cookies,
                content=request.body.encode("utf-8") if request.body else None,
                timeout=request.timeout_seconds or self._limits.timeout_seconds,
            )
            status = resp.status_code
            resp_headers = dict(resp.headers)

            # httpx populates resp.extensions['remote_addr'] for real
            # transports. It's a tuple (host, port) in some versions and a
            # string in others; normalize to a string for storage.
            remote_addr_ext = resp.extensions.get("remote_addr")
            if remote_addr_ext is not None:
                remote_addr = str(remote_addr_ext)

            raw = resp.content
            if len(raw) > self._limits.max_response_size_bytes:
                body = raw[: self._limits.max_response_size_bytes].decode(
                    "utf-8", errors="replace"
                )
                body_truncated = True
            else:
                body = raw.decode("utf-8", errors="replace")
                body_truncated = False
        except httpx.TimeoutException:
            error = "timeout"
        except httpx.ConnectError as e:
            error = f"connect_error: {e}"
        except httpx.RemoteProtocolError as e:
            error = f"remote_protocol_error: {e}"
        # Narrow to httpx.HTTPError (parent of all httpx transport-layer
        # exceptions). Anything else propagates — the orchestrator's outer
        # try/except converts unexpected errors into a FAILED state with
        # an ERROR event, preserving observability without silencing bugs.
        except httpx.HTTPError as e:
            error = f"{type(e).__name__}: {e}"

        elapsed_ms = (time.monotonic() - start) * 1000.0

        # Handle redirects manually so each hop is scope-checked.
        # We only look at Location for redirect resolution. Per RFC 7231:
        #   301/302/303 -> commonly convert to GET (we always do)
        #   307/308     -> preserve original method and body
        if (
            self._follow_redirects
            and resp is not None
            and 300 <= status < 400
            and resp.headers.get("location")
        ):
            # Enforce the redirect-count cap from ScopeConfig to prevent
            # redirect loops and unbounded chains.
            if len(follow_chain) >= self._scope.max_redirects:
                raise ScopeViolation(
                    f"redirect chain exceeded max_redirects="
                    f"{self._scope.max_redirects}"
                )
            loc = resp.headers.get("location")
            if loc:
                next_url = str(httpx.URL(request.url).join(loc))
                follow_chain = [*follow_chain, next_url]
                chain_decision = self._scope.check_redirect_chain(
                    request.url, follow_chain
                )
                if not chain_decision.allowed:
                    raise ScopeViolation(
                        f"redirect chain escaped scope: {chain_decision.reason}"
                    )
                # Choose the next method per RFC 7231. 301/302/303 -> GET,
                # 307/308 -> preserve original method.
                next_method = "GET" if status in {301, 302, 303} else request.method
                next_req = Request(
                    request_id=f"{request.request_id}-r{len(follow_chain)}",
                    method=next_method,
                    url=next_url,
                    headers=request.headers,
                    body=None if next_method == "GET" else request.body,
                    cookies=request.cookies,
                    auth_principal=request.auth_principal,
                    purpose=request.purpose,
                )
                return await self._do_send(next_req, follow_chain=follow_chain)

        return Response(
            request_id=request.request_id,
            status_code=status,
            headers=resp_headers,
            body=body,
            body_excerpt=body[:500],
            body_truncated=body_truncated,
            elapsed_ms=elapsed_ms,
            remote_addr=remote_addr,
            redirect_chain=follow_chain,
            error=error,
        )

    async def close(self) -> None:
        """Explicit close hook for callers that don't use `async with`."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
