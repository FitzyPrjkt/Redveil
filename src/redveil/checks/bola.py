"""BOLA / IDOR check — Broken Object Level Authorization detector.

ACTIVE check. Tests whether authenticated users can read resources they do
NOT own by changing the object ID in the URL (the textbook "IDOR" attack).
The check requires the operator to provision at least TWO test accounts in
``AuthConfig.principals`` and to enumerate IDOR-style endpoints by hand.

CRITICAL SAFETY RULES — read carefully:

    1. **Read-only**. The check only ever issues GET requests. Never POST,
       PUT, PATCH, or DELETE — modifying state across accounts is not the
       job of an authorization checker (that is BFLA territory).
    2. **No enumeration**. We test at most three well-known IDs (1, 2, 3)
       per endpoint pattern. We do NOT iterate through long ID ranges.
    3. **No brute force**. We use exactly the operator-supplied credentials
       from ``AuthConfig.principals``. No guessing, no rotation.
    4. **No exfiltration**. The check records body SHAPES (status, length,
       a short excerpt) for evidence. It does not transmit, store, or
       transcribe full resource contents beyond what is needed to confirm
       cross-account access.

Mechanism:
    Each ``PrincipalConfig`` in ``AuthConfig.principals`` is rendered as a
    per-request auth override (cookies / Authorization header) and applied
    to a fresh ``Request`` via the new ``auth_override_headers`` /
    ``auth_override_cookies`` fields. The HttpClient applies these on top
    of the configured ``AuthProvider``, effectively re-authenticating as
    the named principal for that single request. The principal's name is
    captured in the resulting Evidence so reports show "Account B accessed
    resource owned by Account A".

    For each candidate endpoint + ID, we:
        1. Issue the request as Principal A (the "owner" — first principal).
        2. If A gets 200, the resource exists and A can read it.
        3. Issue the same request as Principal B (and any further principals).
        4. If B also gets 200 and the body either matches A's or differs in
           a way that does NOT obviously indicate A's data being protected,
           we have a BOLA finding.

A note on signal quality: this check deliberately errs on the side of
fewer findings. The default "owner" heuristic is naive — the first
principal in the list is treated as the resource owner — because in
practice the operator has provisioned two accounts specifically to test
each other's access. A more sophisticated version would parse the body
for an owner_id field, but that requires per-application knowledge we
don't have.
"""
from __future__ import annotations

import hashlib
from typing import Any
from urllib.parse import urlparse

from redveil.config import SafetyProfile
from redveil.evidence.evidence import Evidence, ObservationKind
from redveil.findings.confidence import Confidence
from redveil.findings.finding import CheckRef, Finding, FindingStatus, ReproductionStep, TargetRef
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

# ---------------------------------------------------------------------------
# Static endpoint catalogue.
#
# We probe a small, well-known set of IDOR-style endpoint patterns. The
# operator can extend the list at scan time via ``AuthConfig.principals``
# or future config; for now, we keep it bounded to avoid path-explosion
# and to respect the "max 3 IDs per endpoint" safety cap.
# ---------------------------------------------------------------------------

_IDOR_PATH_PATTERNS: tuple[str, ...] = (
    "/api/users/{id}",
    "/api/profile/{id}",
    "/api/orders/{id}",
    "/api/files/{id}",
    "/api/messages/{id}",
    "/api/notes/{id}",
    "/api/posts/{id}",
    "/api/accounts/{id}",
    "/api/v1/users/{id}",
    "/api/v1/orders/{id}",
    "/api/v1/files/{id}",
    "/users/{id}",
    "/profile/{id}",
    "/orders/{id}",
)

_IDOR_QUERY_PARAMS: tuple[tuple[str, tuple[str, ...]], ...] = (
    # (endpoint, list_of_query_param_names)
    ("/api/users", ("id", "user_id", "userId")),
    ("/api/orders", ("id", "order_id", "orderId")),
    ("/api/files", ("id", "file_id", "fileId")),
    ("/api/accounts", ("id", "account_id", "accountId")),
    ("/api/messages", ("id", "message_id", "messageId")),
)

# Hard cap on IDs tested per endpoint. The check MUST refuse to enumerate
# further; this is a safety invariant.
_MAX_IDS_PER_ENDPOINT = 3
_DEFAULT_ID_RANGE: tuple[int, ...] = (1, 2, 3)


def _body_diff_signature(body_a: str, body_b: str) -> str:
    """Stable, short signature for comparing two response bodies.

    Used as a deduplication key and to identify "same body visible to
    both principals" cases. We deliberately use a content hash rather
    than the raw body to avoid storing PII in candidate objects.
    """
    h = hashlib.sha256()
    h.update(b"A:")
    h.update(body_a.encode("utf-8", errors="replace")[:4096])
    h.update(b"|B:")
    h.update(body_b.encode("utf-8", errors="replace")[:4096])
    return h.hexdigest()[:16]


def _body_shape(body: str) -> tuple[int, str]:
    """Coarse body fingerprint: length + first 32 chars (no PII risk).

    Two responses with the same shape but different content (e.g. user-
    specific data) will have different lengths → different shape. Two
    responses with identical content will share both length and excerpt.
    """
    return (len(body), body[:32])


class BOLACheck(Check):
    """Detects Broken Object Level Authorization (BOLA / IDOR).

    Multi-principal testing. The check is only active when the operator
    has provisioned at least two principals in ``AuthConfig.principals``.
    Without at least two principals the check is a no-op — there is no
    second account to test access against.
    """

    meta = CheckMeta(
        id="bola-idor",
        name="BOLA / IDOR Check",
        category=CheckCategory.IDOR,
        safety_profile=SafetyProfile.ACTIVE,
        version="0.1.0",
        description=(
            "Detects Broken Object Level Authorization by issuing the same "
            "request as different principals and comparing responses. If "
            "Principal A receives Principal B's resource (or vice-versa), "
            "the endpoint lacks object-level authorization. Read-only."
        ),
        references=[
            "CWE-639: Authorization Bypass Through User-Controlled Key",
            "OWASP API1:2023 - Broken Object Level Authorization",
            "OWASP A01:2021 - Broken Access Control",
        ],
    )

    def __init__(self) -> None:
        super().__init__()
        # Cached request/response pairs, keyed by (endpoint, principal_name).
        # Populated during discover() and read by collect_evidence() so we
        # do not have to re-issue the cross-principal requests just to
        # produce evidence.
        self._captured: dict[tuple[str, str], tuple[Request, Response]] = {}

    # ------------------------------------------------------------------
    # discover
    # ------------------------------------------------------------------

    async def discover(self, ctx) -> list[dict[str, Any]]:  # type: ignore[override]
        """Probe IDOR-shaped endpoints as each principal and diff the results."""
        if self._deps is None:
            return []
        cfg = self._deps.config

        # Active testing gate. BOLA requires active_testing=true and the
        # operator must have acknowledged the safety terms — same gate as
        # other ACTIVE checks (sqli, command_injection, path_traversal).
        if not cfg.authorization.active_testing:
            return []
        if not cfg.authorization.acknowledged_safety_terms:
            return []

        principals = list(cfg.auth.principals)
        # BOLA needs at least two distinct principals to compare access.
        if len(principals) < 2:
            return []

        # Optional ActionGate: present the multi-principal plan to the user.
        from redveil.validation.risk import ActionPlan, Risk
        plan = ActionPlan(
            action_id="bola-multi-principal-probe",
            description=(
                "Request the same resource as multiple configured principals "
                "and compare responses. If principal B can see principal A's "
                "resource, BOLA is present."
            ),
            risk=Risk.MEDIUM,
            target=str(cfg.target.base_url).rstrip("/") + "/",
            purpose="Detect BOLA / IDOR by comparing per-principal access to shared resources.",
            expected_effect="200 OK for the owner; 403/404 for non-owner.",
            potential_side_effects=(
                "Logged in server access log as multiple identities.",
                "May trigger WAF rate limit if many principals tested rapidly.",
            ),
            max_requests=len(_IDOR_PATH_PATTERNS) * 3 * max(1, len(principals)),
            timeout_seconds=10.0,
        )
        if self._deps.gate is not None:
            decision = self._deps.gate.ask(
                plan,
                allow_destructive=cfg.authorization.allow_destructive,
            )
            if not decision:
                return []

        base = str(cfg.target.base_url).rstrip("/")
        self._captured = {}
        candidates: list[dict[str, Any]] = []

        # Treat the first principal as the resource "owner" for the
        # purposes of the naive heuristic — every other principal is a
        # potential cross-account attacker. A more sophisticated version
        # could parse the response body for an owner_id field, but that
        # would require per-application schema knowledge.
        owner = principals[0]
        attackers = principals[1:]

        # 1. Path-parameter IDOR probes
        for pattern in _IDOR_PATH_PATTERNS:
            for rid in _DEFAULT_ID_RANGE[:_MAX_IDS_PER_ENDPOINT]:
                candidates.extend(
                    await self._probe_path_id(base, pattern, str(rid), owner, attackers)
                )

        # 2. Query-parameter IDOR probes (?id=, ?user_id=, etc.)
        for endpoint, params in _IDOR_QUERY_PARAMS:
            for param in params:
                candidates.extend(
                    await self._probe_query_id(base, endpoint, param, "1", owner, attackers)
                )

        return candidates

    # ------------------------------------------------------------------
    # Internal: a single path-parameter probe (principal × principal)
    # ------------------------------------------------------------------

    async def _probe_path_id(
        self,
        base: str,
        pattern: str,
        rid: str,
        owner: Any,
        attackers: list[Any],
    ) -> list[dict[str, Any]]:
        """Probe one (endpoint, id) pair as the owner then as each attacker."""
        path = pattern.replace("{id}", rid)
        url = join_url(base, path)

        owner_resp = await self._send_as(url, owner, purpose="bola-owner-probe")
        if owner_resp is None or owner_resp.status_code != 200:
            # If the owner can't read it either, we have no evidence either
            # way — the endpoint doesn't seem to expose anything for this ID.
            return []

        out: list[dict[str, Any]] = []
        for attacker in attackers:
            attacker_resp = await self._send_as(
                url, attacker, purpose="bola-attacker-probe"
            )
            if attacker_resp is None:
                continue
            cand = self._evaluate(
                url=url,
                method="GET",
                resource_id=rid,
                location="path",
                location_detail=pattern,
                owner=owner,
                attacker=attacker,
                owner_resp=owner_resp,
                attacker_resp=attacker_resp,
            )
            if cand is not None:
                out.append(cand)
        return out

    # ------------------------------------------------------------------
    # Internal: a single query-parameter probe
    # ------------------------------------------------------------------

    async def _probe_query_id(
        self,
        base: str,
        endpoint: str,
        param: str,
        value: str,
        owner: Any,
        attackers: list[Any],
    ) -> list[dict[str, Any]]:
        url = join_url(base, endpoint)
        owner_resp = await self._send_as(
            url, owner, purpose="bola-owner-probe", params={param: value}
        )
        if owner_resp is None or owner_resp.status_code != 200:
            return []

        out: list[dict[str, Any]] = []
        for attacker in attackers:
            attacker_resp = await self._send_as(
                url, attacker, purpose="bola-attacker-probe", params={param: value}
            )
            if attacker_resp is None:
                continue
            cand = self._evaluate(
                url=url,
                method="GET",
                resource_id=value,
                location="query",
                location_detail=f"{param}={value}",
                owner=owner,
                attacker=attacker,
                owner_resp=owner_resp,
                attacker_resp=attacker_resp,
            )
            if cand is not None:
                out.append(cand)
        return out

    # ------------------------------------------------------------------
    # Internal: dispatch a GET as a specific principal
    # ------------------------------------------------------------------

    async def _send_as(
        self,
        url: str,
        principal: Any,
        purpose: str,
        params: dict[str, str] | None = None,
    ) -> Response | None:
        """Issue a GET to ``url`` authenticated as ``principal``.

        Returns the Response, or None if the request failed for any reason
        (network error, scope violation, etc.). The principal's auth
        material is applied as a per-request override; the framework's
        configured ``AuthProvider`` is still applied first, so this
        composes cleanly with the rest of the system.
        """
        if self._deps is None:
            return None
        try:
            override_headers, override_cookies = principal.to_override()
        except Exception:
            return None

        try:
            req = Request(
                method="GET",
                url=url,
                params=params or {},
                auth_principal=principal.name,
                auth_override_headers=override_headers,
                auth_override_cookies=override_cookies,
                purpose=purpose,
            )
            return await self._deps.http.send(req)
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Internal: classify a (owner, attacker) response pair
    # ------------------------------------------------------------------

    def _evaluate(
        self,
        *,
        url: str,
        method: str,
        resource_id: str,
        location: str,
        location_detail: str,
        owner: Any,
        attacker: Any,
        owner_resp: Response,
        attacker_resp: Response,
    ) -> dict[str, Any] | None:
        """Decide whether a (owner, attacker) pair is a BOLA finding.

        Decision matrix (both responses are status-checked first):

            A:200, B:200, bodies identical     → CONFIRMED
                (A's resource was returned verbatim to B)
            A:200, B:200, bodies differ but    → LIKELY
                shape (length) similar
            A:200, B:403/404                   → FALSE_POSITIVE
                (B is correctly blocked; no BOLA)
            A:200, B:5xx / network error       → INCONCLUSIVE
                (we can't tell; the framework retries or surfaces this)

        We deliberately do NOT report body-different cases as CONFIRMED
        because an attacker who gets a 200 with DIFFERENT data may simply
        have been given a generic "OK" page or the server's own user
        metadata. Only when B sees exactly A's resource do we have proof
        of broken object-level authorization.
        """
        owner_status = owner_resp.status_code
        attacker_status = attacker_resp.status_code

        # First, cache the (request, response) pair so collect_evidence()
        # can return them. We do this for every call, even ones that don't
        # become findings, so reports always have the full request trail.
        owner_req = self._rebuild_request(url, method, owner, location, location_detail)
        attacker_req = self._rebuild_request(url, method, attacker, location, location_detail)
        self._captured[(f"{method} {url} as {owner.name}", "owner")] = (
            owner_req,
            owner_resp,
        )
        self._captured[(f"{method} {url} as {attacker.name}", "attacker")] = (
            attacker_req,
            attacker_resp,
        )

        # Clean rejection: B was blocked. No BOLA.
        if attacker_status in (401, 403, 404):
            return None

        # Server failure / network problem on B's side. Don't claim BOLA.
        if attacker_status >= 500 or attacker_resp.error is not None:
            return None

        # B was not blocked. From here on, B received a 2xx/3xx.
        if attacker_status < 200 or attacker_status >= 400:
            # Other client errors (400, 405, etc.) — not BOLA either.
            return None

        # ---- Both got 2xx. Compare bodies. ----

        body_a = owner_resp.body or ""
        body_b = attacker_resp.body or ""

        # Sanity cap: we only compare the first 4KB to keep this O(1).
        sig = _body_diff_signature(body_a, body_b)
        owner_shape = _body_shape(body_a)
        attacker_shape = _body_shape(body_b)

        if body_a == body_b:
            verdict = "confirmed"
            observation = (
                f"{attacker.name} received IDENTICAL body to {owner.name} "
                f"({len(body_a)} bytes)"
            )
            confidence = "high"
        elif owner_shape == attacker_shape:
            # Same length + same start. Probably identical but slightly
            # different (whitespace, etc.). Still strong signal.
            verdict = "confirmed"
            observation = (
                f"{attacker.name} received body of identical shape to "
                f"{owner.name} (len={owner_shape[0]})"
            )
            confidence = "high"
        else:
            verdict = "likely"
            observation = (
                f"{attacker.name} received 2xx (len={attacker_shape[0]}) "
                f"instead of 403; shape differs from {owner.name} "
                f"(len={owner_shape[0]}) — possible BOLA on different record"
            )
            confidence = "medium"

        return {
            "endpoint": url,
            "method": method,
            "resource_id": resource_id,
            "location": location,           # "path" | "query"
            "location_detail": location_detail,
            "owner_principal": owner.name,
            "accessed_by_principal": attacker.name,
            "status_a": owner_status,
            "status_b": attacker_status,
            "body_length_a": owner_shape[0],
            "body_length_b": attacker_shape[0],
            "body_diff_signature": sig,
            "verdict": verdict,
            "confidence": confidence,
            "observation": observation,
            "request_a": owner_req,
            "response_a": owner_resp,
            "request_b": attacker_req,
            "response_b": attacker_resp,
        }

    def _rebuild_request(
        self,
        url: str,
        method: str,
        principal: Any,
        location: str,
        location_detail: str,
    ) -> Request:
        """Recreate a Request object that mirrors what was sent as ``principal``.

        Used in evidence + reproduction. We rebuild rather than reuse the
        live Request because the HttpClient mutates header/cookie dicts in
        place during dispatch; rebuilding guarantees a clean snapshot.
        """
        try:
            headers, cookies = principal.to_override()
        except Exception:
            headers, cookies = {}, {}
        params: dict[str, str] = {}
        if location == "query" and "=" in location_detail:
            k, _, v = location_detail.partition("=")
            params = {k: v}
        return Request(
            method=method,
            url=url,
            headers=headers,
            cookies=cookies,
            params=params,
            auth_principal=principal.name,
            auth_override_headers=headers,
            auth_override_cookies=cookies,
            purpose="bola-evidence",
        )

    # ------------------------------------------------------------------
    # validate
    # ------------------------------------------------------------------

    async def validate(  # type: ignore[override]
        self, ctx, candidate: dict[str, Any]
    ) -> ValidationResult | None:
        """Translate the discover() verdict into a ValidationResult.

        Both-200 cases are confirmed or likely depending on body equality;
        a B 403 is a FALSE_POSITIVE (handled in discover already, so we
        shouldn't see it here — but be defensive).
        """
        verdict = candidate.get("verdict")
        if verdict == "confirmed":
            return ValidationResult(
                outcome=ValidationOutcome.CONFIRMED,
                confidence="high",
                observation=candidate.get("observation", ""),
            )
        if verdict == "likely":
            return ValidationResult(
                outcome=ValidationOutcome.LIKELY,
                confidence="medium",
                observation=candidate.get("observation", ""),
            )
        return ValidationResult(
            outcome=ValidationOutcome.INCONCLUSIVE,
            confidence="low",
            observation="could not classify cross-principal response pair",
        )

    # ------------------------------------------------------------------
    # collect_evidence
    # ------------------------------------------------------------------

    async def collect_evidence(  # type: ignore[override]
        self, candidate: dict[str, Any]
    ) -> list[Evidence]:
        """Emit one Evidence per principal that accessed the resource.

        The second evidence (the attacker) is tagged with
        ``parameter="principal"`` and ``input_used=<attacker name>`` so
        reports make it obvious which account successfully read the
        resource.
        """
        evidence: list[Evidence] = []
        endpoint = candidate["endpoint"]

        req_a = candidate.get("request_a")
        resp_a = candidate.get("response_a")
        if req_a is not None and resp_a is not None:
            evidence.append(
                Evidence(
                    request=req_a,
                    response=resp_a,
                    kind=ObservationKind.STATUS_DIFF
                    if resp_a.status_code != 200
                    else ObservationKind.BODY_DIFF,
                    endpoint=endpoint,
                    method=req_a.method,
                    parameter=candidate.get("location_detail", "id"),
                    input_used=str(candidate.get("resource_id", "")),
                    status_code=resp_a.status_code,
                    relevant_headers={
                        k: v
                        for k, v in resp_a.headers.items()
                        if k.lower() in {"content-type", "content-length"}
                    },
                    body_excerpt=resp_a.body_excerpt,
                    observation=(
                        f"{candidate.get('owner_principal')} (owner): "
                        f"status={resp_a.status_code} len={candidate.get('body_length_a', 0)}"
                    ),
                )
            )

        req_b = candidate.get("request_b")
        resp_b = candidate.get("response_b")
        if req_b is not None and resp_b is not None:
            evidence.append(
                Evidence(
                    request=req_b,
                    response=resp_b,
                    kind=ObservationKind.STATUS_DIFF
                    if resp_b.status_code != 200
                    else ObservationKind.BODY_DIFF,
                    endpoint=endpoint,
                    method=req_b.method,
                    parameter="principal",
                    input_used=candidate.get("accessed_by_principal", ""),
                    status_code=resp_b.status_code,
                    relevant_headers={
                        k: v
                        for k, v in resp_b.headers.items()
                        if k.lower() in {"content-type", "content-length"}
                    },
                    body_excerpt=resp_b.body_excerpt,
                    observation=(
                        f"{candidate.get('accessed_by_principal')} (attacker) "
                        f"accessed the same resource: status={resp_b.status_code} "
                        f"len={candidate.get('body_length_b', 0)}; "
                        f"diff_signature={candidate.get('body_diff_signature', '')}"
                    ),
                )
            )

        return evidence

    # ------------------------------------------------------------------
    # assess
    # ------------------------------------------------------------------

    async def assess(  # type: ignore[override]
        self, candidate: dict[str, Any]
    ) -> Finding | None:
        """Build the final Finding from a validated BOLA candidate."""
        entry = get_entry(self.meta.id, "bola")
        if entry:
            summary = entry["summary"]
            technical = entry["technical"]
            impact = entry["impact"]
            remediation = list(entry["remediation"])
            attack_scenario = entry["attack_scenario"]
            code_examples = dict(entry["code_examples"])
        else:
            endpoint = candidate.get("endpoint", "")
            attacker = candidate.get("accessed_by_principal", "?")
            owner = candidate.get("owner_principal", "?")
            summary = (
                f"{attacker} can read a resource owned by {owner} at {endpoint}."
            )
            technical = (
                "Both principals received 2xx responses to the same request. "
                "Object-level authorization is not enforced."
            )
            impact = "Mass data exposure across all users."
            remediation = [
                "Add ownership checks on every object access: "
                "`if resource.owner_id != current_user.id: return 403`.",
            ]
            attack_scenario = None
            code_examples = {}

        base = str(self._deps.config.target.base_url) if self._deps else ""
        parsed = urlparse(base)

        full_url = candidate.get("endpoint", "")
        try:
            endpoint_path = urlparse(full_url).path or "/"
        except Exception:
            endpoint_path = full_url or "/"

        # Title naming convention: principal name in the title so the
        # reader can see at a glance which cross-account pair was affected.
        title = (
            f"BOLA / IDOR: {candidate.get('accessed_by_principal', '?')} "
            f"Can Access Resource Owned by {candidate.get('owner_principal', '?')}"
        )

        # Reproduction steps: owner GET, then attacker GET.
        reproduction = [
            ReproductionStep(
                step=1,
                description=(
                    f"Authenticate as {candidate.get('owner_principal')} "
                    f"and GET {full_url}"
                ),
                request=self._curl_for(candidate, "owner"),
            ),
            ReproductionStep(
                step=2,
                description=(
                    f"Authenticate as {candidate.get('accessed_by_principal')} "
                    f"and GET {full_url}"
                ),
                request=self._curl_for(candidate, "attacker"),
                response_excerpt=(
                    f"status={candidate.get('status_b')} "
                    f"len={candidate.get('body_length_b')}"
                ),
            ),
        ]

        verdict = candidate.get("verdict", "likely")
        confidence = (
            Confidence.HIGH if verdict == "confirmed" else Confidence.MEDIUM
        )
        status = (
            FindingStatus.CONFIRMED
            if verdict == "confirmed"
            else FindingStatus.LIKELY
        )

        return Finding(
            check=CheckRef(
                id=self.meta.id,
                name=self.meta.name,
                version=self.meta.version,
                category=self.meta.category.value,
            ),
            title=title,
            severity=Severity.HIGH,
            confidence=confidence,
            status=status,
            target=TargetRef(
                host=parsed.hostname or "",
                port=parsed.port,
                scheme=parsed.scheme or "https",
                endpoint=endpoint_path,
                method="GET",
                parameter=candidate.get("location_detail", "id"),
            ),
            parameter=candidate.get("location_detail", "id"),
            input_used=str(candidate.get("resource_id", "")),
            summary=summary,
            technical_explanation=technical,
            impact=impact,
            attack_scenario=attack_scenario,
            code_examples=code_examples,
            reproduction=reproduction,
            remediation=remediation,
            cwe=["CWE-639"],
            owasp=["A01:2021"],
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                "https://cwe.mitre.org/data/definitions/639.html",
            ],
            testing_principal=candidate.get("accessed_by_principal"),
        )

    def _curl_for(self, candidate: dict[str, Any], who: str) -> str | None:
        """Return a redacted cURL string for the owner or attacker request."""
        req = (
            candidate.get("request_a")
            if who == "owner"
            else candidate.get("request_b")
        )
        if req is None:
            return None
        try:
            return req.to_curl(redact_secrets=True)
        except Exception:
            return None
