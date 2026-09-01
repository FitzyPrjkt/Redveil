"""AttackSurfaceMapper — populates an ApplicationModel from the target.

PASSIVE phase. Crawls the target (homepage + same-origin links) and
extracts endpoints, parameters, and observed response shapes. Does NOT
authenticate, mutate state, or perform active testing — that's the
Behavior Engine's job.

This is the foundation. Currently it builds endpoints from the homepage
HTML. A fuller implementation would also parse OpenAPI/Swagger specs
when available, follow the sitemap, and merge with subdomain-finder
results.
"""
from __future__ import annotations
import re
from typing import Iterable
from urllib.parse import urlparse, urljoin

from redveil.attack_surface.endpoint import Endpoint
from redveil.attack_surface.identity import Identity
from redveil.attack_surface.model import ApplicationModel
from redveil.attack_surface.parameter import Parameter, ParamLocation
from redveil.attack_surface.trust_boundaries import (
    ANONYMOUS_TO_USER,
    TENANT_A_TO_TENANT_B,
    USER_TO_ADMIN,
    TrustBoundary,
)
from redveil.http.request import Request
from redveil.http.response import Response


# Common parameter names that look interesting
_COMMON_PARAM_RE = re.compile(
    r'[\?&]([a-zA-Z_][\w-]{0,40})(?==)',
)
_LINK_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
_FORM_RE = re.compile(r'<form[^>]+action=["\']([^"\']*)["\']', re.IGNORECASE)
_SCRIPT_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)


class AttackSurfaceMapper:
    """Builds an ApplicationModel from observed target behavior.

    The mapper is a stateful object — the orchestrator instantiates it,
    calls `async build()` once, and then the resulting ApplicationModel
    is passed to every check via `CheckDependencies`.
    """

    def __init__(self, http_client, config):
        self._http = http_client
        self._config = config
        self._model = ApplicationModel()
        self._seen_paths: set[tuple[str, str]] = set()

    @property
    def model(self) -> ApplicationModel:
        return self._model

    async def build(self) -> ApplicationModel:
        """Build the model by observing the target.

        Returns the populated ApplicationModel. Currently does a single GET
        of the homepage and extracts endpoints from links/forms. A full
        implementation would also crawl discovered endpoints and parse
        OpenAPI specs.
        """
        base = str(self._config.target.base_url).rstrip("/")
        parsed = urlparse(base)
        self._model.base_url = base
        self._model.target_name = self._config.target.name or parsed.hostname or "target"

        # 1. Seed standard trust boundaries.
        for b in (ANONYMOUS_TO_USER, USER_TO_ADMIN, TENANT_A_TO_TENANT_B):
            self._model.add_trust_boundary(b)

        # 2. Seed identities from config (principals already configured).
        for principal_cfg in getattr(self._config.auth, "principals", []):
            identity = Identity(
                name=principal_cfg.name,
                role=self._role_from_name(principal_cfg.name),
                cookies={c["name"]: c["value"] for c in principal_cfg.cookies}
                if getattr(principal_cfg, "cookies", None) else {},
            )
            self._model.add_identity(identity)

        # 3. GET the homepage, extract endpoints.
        try:
            req = Request(method="GET", url=f"{base}/", purpose="attack_surface_map")
            resp = await self._http.send(req)
        except Exception:
            resp = None

        if resp is not None:
            self._absorb_response(base, resp)
            self._extract_endpoints_from_body(base, resp.body)

        # 4. Probe a small set of common API paths to seed the model
        #     (these are the paths BOLA/BFLA checks will look at).
        for path in (
            "/api/profile/me", "/api/user/me", "/api/users/me", "/api/me",
            "/api/orders", "/api/orders/1", "/api/admin/users",
            "/api/v1/profile", "/api/v1/user", "/api/v1/users/me",
            "/api/v1/admin/users", "/graphql",
        ):
            self._add_endpoint_if_new("GET", path, source="seed")

        return self._model

    # -- internals --------------------------------------------------------

    def _absorb_response(self, base: str, resp: Response) -> None:
        """Extract Set-Cookie name, hint, etc. from a response."""
        # Add the homepage as an endpoint if not present.
        self._add_endpoint_if_new("GET", "/", source="homepage", response=resp)

    def _extract_endpoints_from_body(self, base: str, body: str) -> None:
        """Pull endpoints from the response body — links, forms, scripts."""
        if not body:
            return

        # Links
        for m in _LINK_RE.finditer(body):
            url = m.group(1)
            endpoint = self._url_to_endpoint(base, url, "GET")
            if endpoint:
                self._add_endpoint(endpoint)

        # Form actions (default GET; HTML form methods can be POST)
        for m in _FORM_RE.finditer(body):
            url = m.group(1)
            endpoint = self._url_to_endpoint(base, url, "GET")
            if endpoint:
                self._add_endpoint(endpoint)

        # Scripts (JS endpoints hit via XHR)
        for m in _SCRIPT_RE.finditer(body):
            url = m.group(1)
            endpoint = self._url_to_endpoint(base, url, "GET")
            if endpoint:
                self._add_endpoint(endpoint)

    def _url_to_endpoint(self, base: str, url: str, default_method: str) -> Endpoint | None:
        """Convert a URL string to an Endpoint, only if it's same-origin."""
        if not url or url.startswith("#") or url.startswith("javascript:"):
            return None
        # Resolve relative URLs
        try:
            full = urljoin(base + "/", url)
        except Exception:
            return None
        parsed = urlparse(full)
        if not parsed.path:
            return None
        # Only same-origin
        if parsed.netloc and parsed.netloc != urlparse(base).netloc:
            return None
        # Extract query parameters
        params: list[Parameter] = []
        if parsed.query:
            for m in _COMMON_PARAM_RE.finditer(parsed.query):
                params.append(Parameter(
                    name=m.group(1),
                    location=ParamLocation.QUERY,
                ))
        return Endpoint(
            method=default_method,
            path=parsed.path,
            parameters=tuple(params),
            source="link",
        )

    def _add_endpoint(self, endpoint: Endpoint) -> None:
        key = (endpoint.method.upper(), endpoint.path)
        if key in self._seen_paths:
            return
        self._seen_paths.add(key)
        self._model.add_endpoint(endpoint)

    def _add_endpoint_if_new(
        self, method: str, path: str, source: str, response: Response | None = None
    ) -> None:
        # Seed params: extract from path if it contains {id}-style placeholders
        params: list[Parameter] = []
        for m in re.finditer(r"\{(\w+)\}", path):
            params.append(Parameter(name=m.group(1), location=ParamLocation.PATH))
        ep = Endpoint(method=method, path=path, parameters=tuple(params), source=source)
        self._add_endpoint(ep)

    def _role_from_name(self, name: str) -> str:
        lower = name.lower()
        if "admin" in lower:
            return "admin"
        if "tenant" in lower:
            return lower  # tenant-a, tenant-b
        if "anonymous" in lower:
            return "anonymous"
        return "user"
