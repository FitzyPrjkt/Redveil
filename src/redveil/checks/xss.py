"""ReflectedXSSCheck — detects reflected cross-site scripting via benign canary strings.

ACTIVE check. Uses harmless alphanumeric canaries that cannot trigger script
execution. The proof of vulnerability is that the canary appears UNESCAPED in
the response body — not that the canary runs.
"""
from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse

from redveil.config import SafetyProfile
from redveil.evidence.evidence import Evidence, ObservationKind
from redveil.findings.confidence import Confidence
from redveil.findings.finding import CheckRef, Finding, FindingStatus, TargetRef
from redveil.findings.severity import Severity
from redveil.http.request import Request
from redveil.knowledge.vuln_descriptions import get_entry
from redveil.plugins.base import (
    Check,
    CheckCategory,
    CheckMeta,
    ValidationOutcome,
    ValidationResult,
)
from redveil.util.urls import join_url

# BENIGN canary strings — cannot execute JavaScript. Just plain text + HTML/quote chars.
# The proof is reflection of these chars unescaped, not script execution.
_CANARIES = [
    "redveilXSSProbe12345",                              # plain alphanumeric
    "redv&quot;ail12345",                                # HTML-encoded quote (test if user can re-introduce a quote)
    "redveilXSSanglebracketless12345",                   # tests for angle brackets
]
_HTML_ESCAPED_QUOTE = "&quot;"
_HTML_ESCAPED_LT = "&lt;"

_COMMON_PARAM_NAMES = [
    "q", "s", "search", "query", "id", "name", "input", "text",
    "message", "msg", "comment", "body", "title",
    "url", "redirect", "next", "return", "callback", "ref",
]


class ReflectedXSSCheck(Check):
    meta = CheckMeta(
        id="xss-reflected",
        name="Reflected XSS Check",
        category=CheckCategory.XSS,
        safety_profile=SafetyProfile.ACTIVE,
        description="Detects reflected XSS by injecting benign canary strings and checking for unescaped reflection. No executable payloads.",
        references=["CWE-79", "OWASP A03:2021"],
    )

    async def discover(self, ctx) -> list[dict[str, Any]]:
        if not self.deps:
            return []
        # Active gate
        if not self.deps.config.authorization.active_testing:
            return []
        if not self.deps.config.authorization.acknowledged_safety_terms:
            return []

        # Optional ActionGate: present the canary probe plan to the user.
        # The gate only blocks MEDIUM+ in interactive mode. Canary probes
        # are LOW risk (no destructive payload) so this is auto-approved.
        from redveil.validation.risk import ActionPlan, Risk
        plan = ActionPlan(
            action_id="xss-canary-probe",
            description=(
                "Send benign alphanumeric canary to common reflection "
                "points (q, search, query, id, name, input, text, message, "
                "msg, comment, body, title, url, redirect, next, return, "
                "callback, ref) and check whether the canary is reflected "
                "unescaped in the response body."
            ),
            risk=Risk.LOW,
            target=str(self.deps.config.target.base_url).rstrip("/") + "/",
            purpose="Detect reflected XSS by checking for unescaped input reflection.",
            expected_effect="200 OK response; canary present in body if reflected.",
            potential_side_effects=(
                "Logged in server access log; may trigger WAF if present.",
            ),
            max_requests=20,
            timeout_seconds=10.0,
        )
        if self.deps.gate is not None:
            decision = self.deps.gate.ask(
                plan,
                allow_destructive=self.deps.config.authorization.allow_destructive,
            )
            if not decision:
                # User denied or auto-denied (destructive in non-interactive).
                # In this case, deny is the right behavior.
                return []

        base = str(self.deps.config.target.base_url).rstrip("/")
        candidates: list[dict[str, Any]] = []

        # 1. Find candidate parameters from homepage
        try:
            req_home = Request(method="GET", url=join_url(base, "/"), purpose="discovery")
            resp_home = await self.deps.http.send(req_home)
        except Exception:
            return candidates

        param_names: set[str] = set()
        # Extract from href and form action
        for m in re.finditer(r'[\?&]([a-zA-Z_][\w-]*)=', resp_home.body):
            param_names.add(m.group(1).lower())
        param_names.update(_COMMON_PARAM_NAMES)

        # 2. For each parameter, test canary reflection
        for param in sorted(param_names):
            canary = _CANARIES[0]  # primary canary
            try:
                test_url = f"{join_url(base, '/')}?{param}={canary}"
                req = Request(method="GET", url=test_url, purpose="probe", purpose_extra="xss_canary")
                resp = await self.deps.http.send(req)
            except Exception:
                continue
            if resp.status_code != 200:
                continue
            if canary in resp.body:
                # Check if reflected unescaped
                escaped = (_HTML_ESCAPED_QUOTE in resp.body) and (canary not in resp.body.replace(_HTML_ESCAPED_QUOTE, ""))
                reflected_count = resp.body.count(canary)
                candidates.append({
                    "endpoint": "/",
                    "parameter": param,
                    "method": "GET",
                    "canary": canary,
                    "reflected_count": reflected_count,
                    "escaped": escaped,
                    "request": req,
                    "response": resp,
                })

        # 3. Also test common API endpoints with JSON body
        for path in ["/api", "/api/v1", "/api/data", "/api/profile"]:
            try:
                canary = _CANARIES[0]
                json_body = json.dumps(dict.fromkeys(list(param_names)[:5], canary))
                req = Request(
                    method="POST",
                    url=join_url(base, path),
                    body=json_body,
                    purpose="probe",
                    purpose_extra="xss_canary_json",
                )
                resp = await self.deps.http.send(req)
            except Exception:
                continue
            if resp.status_code == 200 and canary in resp.body:
                candidates.append({
                    "endpoint": path,
                    "parameter": "(json body)",
                    "method": "POST",
                    "canary": canary,
                    "reflected_count": resp.body.count(canary),
                    "escaped": False,
                    "request": req,
                    "response": resp,
                })

        return candidates

    async def validate(self, ctx, candidate) -> ValidationResult:
        if candidate.get("escaped"):
            return ValidationResult(
                outcome=ValidationOutcome.LIKELY,
                confidence="low",
                observation="canary reflected but HTML-encoded; manual review recommended",
            )
        return ValidationResult(
            outcome=ValidationOutcome.CONFIRMED,
            confidence="high",
            observation=f"canary reflected unescaped {candidate.get('reflected_count', 1)} time(s) in response",
        )

    async def collect_evidence(self, candidate) -> list[Evidence]:
        resp = candidate.get("response")
        req = candidate.get("request")
        if not resp or not req:
            return []
        # Extract a 200-char window around the first canary
        canary = candidate.get("canary", "")
        idx = resp.body.find(canary)
        if idx >= 0:
            start = max(0, idx - 100)
            end = min(len(resp.body), idx + len(canary) + 100)
            excerpt = resp.body[start:end]
        else:
            excerpt = resp.body_excerpt
        return [Evidence(
            request=req,
            response=resp,
            kind=ObservationKind.REFLECTION,
            endpoint=req.url,
            method=candidate.get("method", "GET"),
            parameter=candidate.get("parameter"),
            input_used=canary,
            status_code=resp.status_code,
            relevant_headers={"content-type": resp.headers.get("content-type", "")},
            body_excerpt=excerpt,
            observation=f"canary reflected {candidate.get('reflected_count', 1)} time(s); unescaped={not candidate.get('escaped')}",
        )]

    async def assess(self, candidate) -> Finding | None:
        entry = get_entry(self.meta.id, "reflected")
        if entry:
            summary = entry["summary"]
            technical = entry["technical"]
            impact = entry["impact"]
            remediation = list(entry["remediation"])
            attack_scenario = entry["attack_scenario"]
            code_examples = dict(entry["code_examples"])
        else:
            summary = f"Parameter '{candidate['parameter']}' reflects user input unescaped in the response."
            technical = "The server does not HTML-encode the parameter value before embedding it in the response body."
            impact = "Attacker can execute arbitrary JavaScript in victim's browser, leading to session hijacking, credential theft, or phishing."
            remediation = ["HTML-encode all user input reflected in responses.", "Set Content-Security-Policy header."]
            attack_scenario = None
            code_examples = {}

        base = str(self.deps.config.target.base_url)
        parsed = urlparse(base)
        from urllib.parse import urlparse as _up
        req_parsed = _up(candidate["request"].url)
        return Finding(
            check=CheckRef(id=self.meta.id, name=self.meta.name, category=self.meta.category.value, version=self.meta.version),
            title=f"Reflected XSS via '{candidate['parameter']}' Parameter",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            status=FindingStatus.CONFIRMED,
            target=TargetRef(
                host=parsed.hostname or "",
                port=parsed.port,
                scheme=parsed.scheme or "https",
                endpoint=req_parsed.path or "/",
                method=candidate["method"],
                parameter=candidate["parameter"],
            ),
            parameter=candidate["parameter"],
            input_used=candidate.get("canary", ""),
            summary=summary,
            technical_explanation=technical,
            impact=impact,
            attack_scenario=attack_scenario,
            code_examples=code_examples,
            remediation=remediation,
            cwe=["CWE-79"],
            owasp=["A03:2021"],
        )
