"""OpenRedirectCheck — detects endpoints/parameters that may be vulnerable to open redirect.

PASSIVE check. Only discovers parameters that look like redirect targets and
optionally probes them with a same-origin path (no external domain). Does NOT
attempt actual open redirect attacks.
"""
from __future__ import annotations

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

_REDIRECT_PARAM_NAMES = {
    "url", "redirect", "redirect_url", "redirecturi", "next", "return",
    "returnurl", "return_to", "goto", "continue", "dest", "destination",
    "redir", "forward", "to", "out", "view", "dir", "show", "navigation",
    "target", "rurl", "link", "callback", "redirect_to", "redirect_to_url",
}


class OpenRedirectCheck(Check):
    meta = CheckMeta(
        id="open-redirect-indicator",
        name="Open Redirect Indicator",
        category=CheckCategory.REDIRECT,
        safety_profile=SafetyProfile.PASSIVE,
        description="Detects parameters commonly used for redirects. Passive only — does not exploit.",
        references=["CWE-601", "OWASP A01:2021"],
    )

    async def discover(self, ctx) -> list[dict[str, Any]]:
        if not self.deps:
            return []
        base = str(self.deps.config.target.base_url).rstrip("/")
        candidates: list[dict[str, Any]] = []

        # 1. Extract links/forms from homepage
        try:
            req = Request(method="GET", url=join_url(base, "/"), purpose="discovery")
            resp = await self.deps.http.send(req)
        except Exception:
            return candidates

        body = resp.body
        # Find hrefs and form actions
        href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
        action_pattern = re.compile(r'action=["\']([^"\']+)["\']', re.IGNORECASE)
        urls = set()
        for m in href_pattern.finditer(body):
            urls.add(m.group(1))
        for m in action_pattern.finditer(body):
            urls.add(m.group(1))

        for url in urls:
            if "?" not in url:
                continue
            path, qs = url.split("?", 1)
            for param in qs.split("&"):
                if "=" not in param:
                    continue
                name, _, value = param.partition("=")
                if name.lower() in _REDIRECT_PARAM_NAMES:
                    candidates.append({
                        "endpoint": path,
                        "parameter": name,
                        "value": value,
                        "kind": "redirect_param",
                        "response": resp,
                        "request": req,
                    })

        # 2. Probe common redirect endpoints with a benign same-origin test
        probe_paths = ["/redirect", "/login", "/logout", "/auth"]
        for path in probe_paths:
            try:
                probe_url = join_url(base, f"{path}?next=/redveil-test-{abs(hash(path)) % 100000}")
                req2 = Request(method="GET", url=probe_url, purpose="probe", purpose_extra="redirect_test")
                resp2 = await self.deps.http.send(req2)
            except Exception:
                continue
            if 300 <= resp2.status_code < 400 and "location" in {k.lower() for k in resp2.headers}:
                # Same-origin probe got a redirect → parameter is used for redirect
                candidates.append({
                    "endpoint": path,
                    "parameter": "next",
                    "value": "(probed)",
                    "kind": "redirect_param_confirmed",
                    "response": resp2,
                    "request": req2,
                })

        return candidates

    async def validate(self, ctx, candidate) -> ValidationResult:
        if candidate["kind"] == "redirect_param_confirmed":
            return ValidationResult(
                outcome=ValidationOutcome.LIKELY,
                confidence="medium",
                observation="same-origin test received 3xx redirect; parameter used for redirect",
            )
        return ValidationResult(
            outcome=ValidationOutcome.LIKELY,
            confidence="low",
            observation="redirect-like parameter discovered; manual validation required",
        )

    async def collect_evidence(self, candidate) -> list[Evidence]:
        resp = candidate.get("response")
        req = candidate.get("request")
        if not resp or not req:
            return []
        return [Evidence(
            request=req,
            response=resp,
            kind=ObservationKind.REDIRECT_TARGET,
            endpoint=candidate["endpoint"],
            method="GET",
            parameter=candidate["parameter"],
            input_used=candidate.get("value", ""),
            status_code=resp.status_code,
            relevant_headers={k: v for k, v in resp.headers.items() if k.lower() == "location"},
            observation=f"redirect parameter '{candidate['parameter']}' discovered",
        )]

    async def assess(self, candidate) -> Finding | None:
        kind = candidate["kind"]
        # Pull rich content from the knowledge base.
        entry = get_entry(self.meta.id, "redirect_param")
        if entry:
            summary = entry["summary"]
            technical = entry["technical"]
            impact = entry["impact"]
            remediation = list(entry["remediation"])
            attack_scenario = entry["attack_scenario"]
            code_examples = dict(entry["code_examples"])
        else:
            summary = (
                f"Endpoint '{candidate['endpoint']}' has a parameter "
                f"'{candidate['parameter']}' that may be used for redirect targets."
            )
            technical = (
                f"The parameter '{candidate['parameter']}' is commonly abused for open redirect attacks."
            )
            impact = "If exploitable, attackers can redirect victims to phishing or malware sites."
            remediation = ["Validate redirect targets against an allowlist."]
            attack_scenario = None
            code_examples = {}

        base = str(self.deps.config.target.base_url)
        parsed = urlparse(base)

        return Finding(
            check=CheckRef(id=self.meta.id, name=self.meta.name, category=self.meta.category.value, version=self.meta.version),
            title=f"Potential Open Redirect via '{candidate['parameter']}' Parameter",
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM if kind == "redirect_param_confirmed" else Confidence.LOW,
            status=FindingStatus.SUSPECTED,
            target=TargetRef(
                host=parsed.hostname or "",
                port=parsed.port,
                scheme=parsed.scheme or "https",
                endpoint=candidate["endpoint"],
                method="GET",
                parameter=candidate["parameter"],
            ),
            parameter=candidate["parameter"],
            input_used=candidate.get("value", ""),
            summary=summary,
            technical_explanation=technical,
            impact=impact,
            attack_scenario=attack_scenario,
            code_examples=code_examples,
            remediation=remediation,
            cwe=["CWE-601"],
            owasp=["A01:2021"],
        )
