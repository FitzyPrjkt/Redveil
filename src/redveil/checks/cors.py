"""CORS policy check — detects overly permissive Cross-Origin Resource Sharing.

The check probes common API endpoints with an ``OPTIONS`` preflight and a
``GET`` that carries a custom ``Origin`` header. Three misconfigurations are
flagged:

1. ``Access-Control-Allow-Origin: *`` alone (LOW risk; modern browsers block
   the credentialed variant, but it still leaks public data to any origin).
2. ``Access-Control-Allow-Origin: <request_origin>`` (origin reflection) —
   the server blindly echoes whatever origin the client sends. With a
   permissive browser policy and cookie-based auth, this is equivalent to
   disabling the same-origin policy for that endpoint. HIGH severity.
3. ``Access-Control-Allow-Origin: *`` combined with
   ``Access-Control-Allow-Credentials: true`` — most browsers refuse to
   honor this combination, but some legacy / proxy deployments still
   accept it, and a misconfigured CDN may strip the wildcard. CRITICAL.

The check is passive: it never mutates state and never bypasses the scope
controller. The malicious origin used in probes is a constant sentinel
(``https://evil.example``) — we do not make outbound calls to it.
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

# Endpoints probed in the discovery pass. Conservative defaults — we add
# entries only when the base URL itself looks like an API surface.
_DISCOVERY_PATHS: tuple[str, ...] = (
    "/",
    "/api",
    "/api/data",
    "/api/v1",
    "/api/profile",
)

# Sentinel origin used to provoke reflection. The host does not need to
# exist; we are testing how the *server* responds to an arbitrary Origin
# header value.
_EVIL_ORIGIN = "https://evil.example"


def _get_header(headers: dict[str, str], name: str) -> str | None:
    """Case-insensitive header lookup. Returns the value or None."""
    target = name.lower()
    for k, v in headers.items():
        if k.lower() == target:
            return v
    return None


class CORSCheck(Check):
    """Detects overly permissive CORS configuration on common endpoints."""

    meta = CheckMeta(
        id="cors-policy",
        name="CORS Policy Check",
        category=CheckCategory.CORS,
        safety_profile=SafetyProfile.PASSIVE,
        version="0.1.0",
        description=(
            "Verifies Cross-Origin Resource Sharing configuration. Detects "
            "overly permissive Access-Control-Allow-Origin: *, reflected "
            "origin without validation, and the dangerous combination of "
            "Allow-Origin: * with Allow-Credentials: true."
        ),
        references=[
            "CWE-942: Permissive Cross-domain Policy with Untrusted Domains",
            "OWASP A05:2021 - Security Misconfiguration",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
        ],
    )

    def __init__(self) -> None:
        super().__init__()
        # Cached request/response pairs collected during discover() so that
        # collect_evidence() can reference them without re-issuing requests.
        # Keyed by (path, request_kind) where kind is "preflight" or "get".
        self._captured: dict[tuple[str, str], tuple[Request, Response]] = {}

    # -- discover --------------------------------------------------------

    async def discover(self, ctx) -> list[dict[str, Any]]:  # type: ignore[override]
        """Issue an OPTIONS preflight and a custom-origin GET per path."""
        base = str(self.deps.config.target.base_url).rstrip("/")
        candidates: list[dict[str, Any]] = []
        # Reset capture cache for this scan.
        self._captured = {}

        for path in _DISCOVERY_PATHS:
            url = join_url(base, path)

            # 1. OPTIONS preflight — what does the server *advertise*?
            preflight_req = Request(
                method="OPTIONS",
                url=url,
                headers={
                    "Origin": _EVIL_ORIGIN,
                    "Access-Control-Request-Method": "GET",
                },
                purpose="cors-preflight",
            )
            preflight_resp = await self.deps.http.send(preflight_req)
            self._captured[(path, "preflight")] = (preflight_req, preflight_resp)

            # 2. Actual GET with a custom Origin — does the server *echo*
            #    the request origin in Access-Control-Allow-Origin?
            get_req = Request(
                method="GET",
                url=url,
                headers={"Origin": _EVIL_ORIGIN},
                purpose="cors-get",
            )
            get_resp = await self.deps.http.send(get_req)
            self._captured[(path, "get")] = (get_req, get_resp)

            # Analyze the strongest signal. The GET response is the
            # authoritative source for "what does the browser see" when it
            # actually performs a cross-origin request; the preflight only
            # matters for non-simple methods. We union both so we never miss
            # a misconfig reported in either.
            seen_issues: set[str] = set()
            for source_resp, source_kind in (
                (preflight_resp, "preflight"),
                (get_resp, "get"),
            ):
                cand = self._analyze(path, source_resp, source_kind)
                if cand and cand["issue"] not in seen_issues:
                    seen_issues.add(cand["issue"])
                    candidates.append(cand)

        return candidates

    def _analyze(
        self,
        path: str,
        response: Response,
        source: str,
    ) -> dict[str, Any] | None:
        """Inspect a single response and return a candidate dict if risky."""
        acao = _get_header(response.headers, "Access-Control-Allow-Origin")
        if not acao:
            return None  # server does not advertise CORS for this response

        acac = (
            _get_header(response.headers, "Access-Control-Allow-Credentials")
            or ""
        ).lower() == "true"

        acao_normalized = acao.strip()
        # Critical: wildcard AND credentials — browsers reject this combo,
        # but a misconfigured proxy/CDN may honor it. CRITICAL.
        if acao_normalized == "*" and acac:
            return {
                "endpoint": path,
                "issue": "wildcard_with_credentials",
                "acao": acao_normalized,
                "acac": "true",
                "request_origin": _EVIL_ORIGIN,
                "source": source,
                "status_code": response.status_code,
            }

        # Origin reflection — server echoes the request's Origin header.
        # This is only valid if the response also varies on Origin, AND the
        # reflection is restricted to a trusted allowlist. An echo of the
        # arbitrary evil.example origin is HIGH risk.
        if acao_normalized == _EVIL_ORIGIN:
            return {
                "endpoint": path,
                "issue": "reflected_origin",
                "acao": acao_normalized,
                "acac": "true" if acac else "false",
                "request_origin": _EVIL_ORIGIN,
                "source": source,
                "status_code": response.status_code,
            }

        # Wildcard alone — risk depends on whether the endpoint serves
        # sensitive data. Report it as LOW; assess() decides whether the
        # data class warrants a higher rating in a future revision.
        if acao_normalized == "*":
            return {
                "endpoint": path,
                "issue": "wildcard_origin",
                "acao": acao_normalized,
                "acac": "true" if acac else "false",
                "request_origin": _EVIL_ORIGIN,
                "source": source,
                "status_code": response.status_code,
            }

        return None

    # -- validate --------------------------------------------------------

    async def validate(  # type: ignore[override]
        self, ctx, candidate: dict[str, Any]
    ) -> ValidationResult | None:
        """The misconfiguration is observable directly in the response.
        CONFIRMED with high confidence — no further probing required."""
        return ValidationResult(
            outcome=ValidationOutcome.CONFIRMED,
            confidence="high",
            observation="CORS misconfiguration observed in response",
        )

    # -- evidence --------------------------------------------------------

    async def collect_evidence(  # type: ignore[override]
        self, candidate: dict[str, Any]
    ) -> list[Evidence]:
        """Attach the preflight + custom-origin GET pair that surfaced the
        misconfiguration."""
        evidence: list[Evidence] = []
        path = candidate["endpoint"]
        for kind in ("preflight", "get"):
            pair = self._captured.get((path, kind))
            if pair is None:
                continue
            req, resp = pair
            relevant = {
                k: v
                for k, v in resp.headers.items()
                if k.lower().startswith("access-control-")
                or k.lower() == "vary"
            }
            evidence.append(
                Evidence(
                    request=req,
                    response=resp,
                    kind=ObservationKind.HEADER_PRESENT,
                    endpoint=path,
                    method=req.method,
                    parameter="Origin",
                    input_used=_EVIL_ORIGIN,
                    status_code=resp.status_code,
                    relevant_headers=relevant,
                    observation=(
                        f"{candidate['issue']} on {path} "
                        f"({candidate.get('acao', '')})"
                    ),
                )
            )
        return evidence

    # -- assess ----------------------------------------------------------

    async def assess(  # type: ignore[override]
        self, candidate: dict[str, Any]
    ) -> Finding | None:
        """Build a Finding from a validated CORS candidate."""
        issue = candidate["issue"]
        if issue == "wildcard_with_credentials":
            severity = Severity.CRITICAL
            title = "Wildcard CORS Origin Combined With Credentials"
        elif issue == "reflected_origin":
            severity = Severity.HIGH
            title = "CORS Origin Reflection Without Validation"
        else:
            severity = Severity.LOW
            title = "Overly Permissive CORS Policy"

        base = str(self.deps.config.target.base_url)
        parsed = urlparse(base)
        endpoint = candidate["endpoint"]
        full_url = join_url(base, endpoint)

        # Pull rich content from the knowledge base.
        entry = get_entry(self.meta.id, issue)
        if entry:
            summary = entry["summary"]
            technical = entry["technical"]
            impact = entry["impact"]
            remediation = list(entry["remediation"])
            attack_scenario = entry["attack_scenario"]
            code_examples = dict(entry["code_examples"])
        else:
            summary = (
                f"Endpoint {endpoint} advertises a permissive CORS policy "
                f"({candidate.get('acao', '')})."
            )
            technical = (
                f"Request: OPTIONS/GET {full_url} with Origin: {_EVIL_ORIGIN}. "
                f"Response: Access-Control-Allow-Origin: {candidate.get('acao', '')}."
            )
            impact = "Cross-origin reads possible from any website."
            remediation = ["Restrict ACAO to a known allowlist."]
            attack_scenario = None
            code_examples = {}

        cwe_list = ["CWE-942"]
        owasp_list = ["A05:2021"]
        if issue == "reflected_origin":
            cwe_list.append("CWE-346")  # origin validation error

        reproduction = [
            ReproductionStep(
                step=1,
                description=(
                    f"Send an OPTIONS preflight to {full_url} with "
                    f"Origin: {_EVIL_ORIGIN}."
                ),
                request=Request(
                    method="OPTIONS",
                    url=full_url,
                    headers={
                        "Origin": _EVIL_ORIGIN,
                        "Access-Control-Request-Method": "GET",
                    },
                    purpose="cors-preflight",
                ).to_curl(),
            ),
            ReproductionStep(
                step=2,
                description=(
                    f"Observe Access-Control-Allow-Origin: {candidate.get('acao', '')}"
                ),
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
                endpoint=endpoint,
                method="OPTIONS",
                parameter="Origin",
            ),
            parameter="Origin",
            input_used=_EVIL_ORIGIN,
            summary=summary,
            technical_explanation=technical,
            impact=impact,
            attack_scenario=attack_scenario,
            code_examples=code_examples,
            reproduction=reproduction,
            remediation=remediation,
            cwe=cwe_list,
            owasp=owasp_list,
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
            ],
        )
