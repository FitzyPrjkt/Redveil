"""HTTP methods check — detects endpoints that allow dangerous methods.

The check probes common API endpoints for support of HTTP methods that are
either rarely needed on public surfaces or that can directly lead to
security incidents:

* ``PUT`` / ``DELETE`` / ``PATCH`` — when allowed without authentication on
  a public endpoint, an unauthenticated attacker can write or mutate
  server-side state (HIGH).
* ``CONNECT`` — used to tunnel arbitrary TCP through the proxy; almost
  never a legitimate public endpoint method (HIGH).
* ``TRACE`` — echoes the request back to the client. Combined with
  JavaScript that reads the response (e.g. via XHR on a same-origin
  resource), this enables Cross-Site Tracing (XST), an older but
  recurring XSS-vector (MEDIUM).

The check is read-only: it issues requests with no body. A successful
response (``2xx``) without authentication is a candidate. Authenticated
responses (``401`` / ``403``) and ``405 Method Not Allowed`` are not
findings. A ``Vary: Origin`` header in an OPTIONS response is treated as
informational.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from redveil.config import SafetyProfile
from redveil.evidence.evidence import Evidence, ObservationKind
from redveil.findings.confidence import Confidence
from redveil.findings.finding import CheckRef, Finding, ReproductionStep, TargetRef
from redveil.findings.severity import Severity
from redveil.http.request import Request
from redveil.http.response import Response
from redveil.knowledge.vuln_descriptions import get_entry
from redveil.plugins.base import (
    Check,
    CheckCategory,
    CheckMeta,
    ValidationOutcome,
    ValidationResult,
)
from redveil.util.urls import join_url

# Endpoints probed by the methods check. We deliberately keep the list
# short and conventional: the goal is to surface obviously-dangerous
# server-wide or path-level method configurations, not to crawl.
_DISCOVERY_PATHS: tuple[str, ...] = (
    "/",
    "/api",
    "/api/data",
    "/api/v1",
)

# Methods that are tested individually with a direct request. We probe
# them in addition to whatever the ``Allow`` header advertises.
_PROBE_METHODS: tuple[str, ...] = (
    "PUT",
    "DELETE",
    "PATCH",
    "CONNECT",
    "TRACE",
)

# Status codes that indicate the method is *not* allowed and require no
# further action.
_NOT_ALLOWED = frozenset({403, 405, 501})


# Map (method, issue) -> knowledge-base kind
_KIND_MAP = {
    ("TRACE", "trace_enabled"): "trace_enabled",
    ("CONNECT", "connect_enabled"): "connect_enabled",
    ("PUT", "method_allowed_without_auth"): "put_no_auth",
    ("PUT", "method_advertised_in_allow"): "method_advertised_in_allow",
    ("DELETE", "method_allowed_without_auth"): "delete_no_auth",
    ("DELETE", "method_advertised_in_allow"): "method_advertised_in_allow",
    ("PATCH", "method_allowed_without_auth"): "patch_no_auth",
    ("PATCH", "method_advertised_in_allow"): "method_advertised_in_allow",
    ("_ANY_", "method_advertised_in_allow"): "method_advertised_in_allow",
}


def _get_header(headers: dict[str, str], name: str) -> str | None:
    """Case-insensitive header lookup."""
    target = name.lower()
    for k, v in headers.items():
        if k.lower() == target:
            return v
    return None


def _parse_allow(headers: dict[str, str]) -> set[str]:
    """Parse an ``Allow`` response header into a set of uppercased methods.

    The header is a comma-separated list of method names per RFC 7231. We
    ignore surrounding whitespace and case-fold everything.
    """
    raw = _get_header(headers, "Allow")
    if not raw:
        return set()
    methods: set[str] = set()
    for part in raw.split(","):
        m = part.strip().upper()
        if m:
            methods.add(m)
    return methods


class HTTPMethodsCheck(Check):
    """Detects endpoints that allow dangerous HTTP methods."""

    meta = CheckMeta(
        id="http-methods",
        name="HTTP Methods Check",
        category=CheckCategory.METHODS,
        safety_profile=SafetyProfile.PASSIVE,
        version="0.1.0",
        description=(
            "Detects endpoints that allow dangerous HTTP methods (PUT, "
            "DELETE, PATCH, TRACE, CONNECT) without authentication. TRACE "
            "in particular can enable Cross-Site Tracing (XST) attacks."
        ),
        references=[
            "CWE-650: Trusting HTTP Permission Methods on the Server Side",
            "CWE-284: Improper Access Control",
            "OWASP A05:2021 - Security Misconfiguration",
        ],
    )

    def __init__(self) -> None:
        super().__init__()
        # Cache requests/responses for collect_evidence(). Keyed by
        # (path, method) — we store the request that *succeeded*.
        self._captured: dict[tuple[str, str], tuple[Request, Response]] = {}

    # -- discover --------------------------------------------------------

    async def discover(self, ctx) -> list[dict[str, Any]]:  # type: ignore[override]
        """Probe each path with OPTIONS and each dangerous method."""
        base = str(self.deps.config.target.base_url).rstrip("/")
        candidates: list[dict[str, Any]] = []
        self._captured = {}

        for path in _DISCOVERY_PATHS:
            url = join_url(base, path)

            # 1. OPTIONS — collect the Allow header if present.
            options_req = Request(
                method="OPTIONS",
                url=url,
                headers={},
                purpose="methods-options",
            )
            options_resp = await self.deps.http.send(options_req)
            self._captured[(path, "OPTIONS")] = (options_req, options_resp)

            allowed = _parse_allow(options_resp.headers)
            # Any "dangerous" method advertised in the Allow header is a
            # candidate, regardless of whether a direct probe would have
            # also succeeded. This catches servers that have been
            # configured to advertise a method via OPTIONS but reject the
            # actual request (e.g. 405 on direct call) — still
            # misconfiguration worth reporting.
            for method in _PROBE_METHODS:
                if method in allowed:
                    candidates.append(
                        {
                            "endpoint": path,
                            "method": method,
                            "status_code": options_resp.status_code,
                            "issue": "method_advertised_in_allow",
                        }
                    )

            # 2. Probe each dangerous method directly.
            for method in _PROBE_METHODS:
                # Skip if we already raised an "advertised" candidate for
                # this method on this path; the direct probe only adds a
                # stronger signal (proved-allowed) if it differs.
                probe_req = Request(
                    method=method,
                    url=url,
                    headers={},
                    body=None,
                    purpose="methods-probe",
                )
                probe_resp = await self.deps.http.send(probe_req)
                self._captured[(path, method)] = (probe_req, probe_resp)

                issue = self._classify(method, probe_resp.status_code)
                if issue is None:
                    continue
                # If a weaker "advertised" candidate already exists for
                # this (path, method), upgrade it to "proved allowed" by
                # replacing the entry. This keeps the strongest evidence
                # and avoids duplicate findings.
                self._upsert(
                    candidates,
                    {
                        "endpoint": path,
                        "method": method,
                        "status_code": probe_resp.status_code,
                        "issue": issue,
                    },
                )

        return candidates

    def _classify(self, method: str, status_code: int) -> str | None:
        """Map a probe status to an issue string, or None if not a finding."""
        if status_code in _NOT_ALLOWED:
            return None
        if 200 <= status_code < 300:
            # TRACE echo is its own issue, even though a normal 200/204
            # would also be a finding. We prefer the more specific label.
            if method == "TRACE":
                return "trace_enabled"
            if method == "CONNECT":
                return "connect_enabled"
            if method in {"PUT", "DELETE", "PATCH"}:
                return "method_allowed_without_auth"
            # Future: other dangerous methods go here.
            return None
        # 401/403/404/etc — server explicitly rejected or doesn't recognize
        # the method. Not a finding.
        return None

    def _upsert(
        self, candidates: list[dict[str, Any]], new: dict[str, Any]
    ) -> None:
        """Replace any existing candidate for (path, method) with `new`.

        "proved_allowed" / "trace_enabled" are stronger than
        "method_advertised_in_allow", so we always prefer the upgrade.
        """
        for i, existing in enumerate(candidates):
            if (
                existing["endpoint"] == new["endpoint"]
                and existing["method"] == new["method"]
            ):
                candidates[i] = new
                return
        candidates.append(new)

    # -- validate --------------------------------------------------------

    async def validate(  # type: ignore[override]
        self, ctx, candidate: dict[str, Any]
    ) -> ValidationResult | None:
        """The method was observable in the response. CONFIRMED."""
        return ValidationResult(
            outcome=ValidationOutcome.CONFIRMED,
            confidence="high",
            observation=(
                f"Method {candidate['method']} returned status "
                f"{candidate['status_code']} without authentication on "
                f"{candidate['endpoint']}"
            ),
        )

    # -- evidence --------------------------------------------------------

    async def collect_evidence(  # type: ignore[override]
        self, candidate: dict[str, Any]
    ) -> list[Evidence]:
        """Attach the request/response pair that proved the method allowed."""
        path = candidate["endpoint"]
        method = candidate["method"]
        pair = self._captured.get((path, method))
        if pair is None:
            return []
        req, resp = pair

        # If we have a TRACE response, the echoed request is itself the
        # evidence — pull the first 200 bytes for the excerpt.
        body_excerpt = resp.body[:200] if resp.body else ""
        relevant: dict[str, str] = {}
        allow = _get_header(resp.headers, "Allow")
        if allow:
            relevant["Allow"] = allow
        for header_name in ("Server", "Date"):
            v = _get_header(resp.headers, header_name)
            if v:
                relevant[header_name] = v

        return [
            Evidence(
                request=req,
                response=resp,
                kind=ObservationKind.STATUS_DIFF,
                endpoint=path,
                method=method,
                status_code=resp.status_code,
                relevant_headers=relevant,
                body_excerpt=body_excerpt,
                observation=(
                    f"{method} {path} -> {resp.status_code} without auth"
                ),
            )
        ]

    # -- assess ----------------------------------------------------------

    async def assess(  # type: ignore[override]
        self, candidate: dict[str, Any]
    ) -> Finding | None:
        """Build a Finding from a validated methods candidate."""
        method = candidate["method"]
        path = candidate["endpoint"]
        status = candidate["status_code"]
        issue = candidate["issue"]

        if method == "TRACE":
            severity = Severity.MEDIUM
            cwe = ["CWE-650"]
        elif method == "CONNECT":
            severity = Severity.HIGH
            cwe = ["CWE-284"]
        else:
            # PUT / DELETE / PATCH without auth
            severity = Severity.HIGH
            cwe = ["CWE-284"]

        title = f"Dangerous HTTP Method Allowed: {method}"

        # Pull rich content from the knowledge base.
        kb_kind = _KIND_MAP.get((method, issue)) or _KIND_MAP.get(("_ANY_", issue)) or issue
        entry = get_entry(self.meta.id, kb_kind)
        if entry:
            summary = entry["summary"]
            technical = entry["technical"]
            impact = entry["impact"]
            remediation = list(entry["remediation"])
            attack_scenario = entry["attack_scenario"]
            code_examples = dict(entry["code_examples"])
        else:
            summary = (
                f"Endpoint {path} accepts the {method} method without requiring "
                f"authentication (HTTP {status})."
            )
            technical = f"Direct {method} request to the target returned HTTP {status}."
            impact = (
                "An unauthenticated attacker can perform actions on the target "
                "server that should be restricted to authenticated users."
            )
            remediation = [
                f"Disable {method} unless the endpoint is documented to support it.",
                "Authenticate every state-changing request.",
            ]
            attack_scenario = None
            code_examples = {}

        base = str(self.deps.config.target.base_url)
        parsed = urlparse(base)
        full_url = join_url(base, path)

        reproduction = [
            ReproductionStep(
                step=1,
                description=(
                    f"Send a {method} request to {full_url} with no "
                    "credentials."
                ),
                request=Request(
                    method=method,
                    url=full_url,
                    headers={},
                    body=None,
                    purpose="methods-probe",
                ).to_curl(),
            ),
            ReproductionStep(
                step=2,
                description=f"Observe HTTP {status} response.",
            ),
        ]

        return Finding(
            check=CheckRef(
                id=self.meta.id,
                name=self.meta.name,
                version=self.meta.version,
                category=self.meta.category.value,
            ),
            title=title,
            severity=severity,
            confidence=Confidence.HIGH,
            target=TargetRef(
                host=parsed.hostname or "",
                port=parsed.port,
                scheme=parsed.scheme or "https",
                endpoint=path,
                method=method,
            ),
            parameter=None,
            input_used=None,
            summary=summary,
            technical_explanation=technical,
            impact=impact,
            attack_scenario=attack_scenario,
            code_examples=code_examples,
            reproduction=reproduction,
            remediation=remediation,
            cwe=cwe,
            owasp=["A05:2021"],
            references=[
                "https://owasp.org/www-community/attacks/Cross_Site_Tracing",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods",
            ],
        )
