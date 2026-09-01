"""SecurityHeadersCheck — verifies HTTP security headers.

PASSIVE check. Issues a single GET to the base URL and inspects the response
headers. Generates one candidate per missing or weak header. No mutation, no
probing — strictly observational.
"""
from __future__ import annotations

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

# (header_name, default_severity_if_missing_or_weak, evaluator(value) -> (issue_label, severity_override|None))
_HEADER_RULES = {
    "content-security-policy": (
        Severity.MEDIUM,
        lambda v: ("wildcard", Severity.HIGH) if v == "*" or "unsafe-inline" in v else ("present", None),
    ),
    "x-frame-options": (
        Severity.MEDIUM,
        lambda v: ("improper", None) if v.upper() not in {"DENY", "SAMEORIGIN"} else ("present", None),
    ),
    "x-content-type-options": (
        Severity.LOW,
        lambda v: ("improper", None) if v.lower() != "nosniff" else ("present", None),
    ),
    "strict-transport-security": (
        Severity.MEDIUM,
        lambda v: ("short_max_age", Severity.LOW) if _hsts_max_age(v) < 31536000 else ("present", None),
    ),
    "referrer-policy": (
        Severity.LOW,
        lambda v: ("unsafe", None) if v.lower() in {"unsafe-url", "no-referrer-when-downgrade"} else ("present", None),
    ),
    "permissions-policy": (
        Severity.LOW,
        lambda v: ("present", None),  # any value is OK
    ),
}


def _hsts_max_age(value: str) -> int:
    """Extract max-age from HSTS header value, default 0."""
    import re
    m = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    return int(m.group(1)) if m else 0


# Map header + issue -> knowledge-base kind for lookup. Lets us share
# descriptions across related issues (e.g. wildcard CSP and unsafe-inline).
_KIND_MAP = {
    ("content-security-policy", "missing"): "content-security-policy-missing",
    ("content-security-policy", "wildcard"): "content-security-policy-wildcard",
    ("content-security-policy", "improper"): "content-security-policy-wildcard",
    ("x-frame-options", "missing"): "x-frame-options-missing",
    ("x-frame-options", "improper"): "x-frame-options-improper",
    ("strict-transport-security", "missing"): "strict-transport-security-missing",
    ("strict-transport-security", "short_max_age"): "strict-transport-security-short-max-age",
    ("x-content-type-options", "missing"): "x-content-type-options-missing",
    ("x-content-type-options", "improper"): "x-content-type-options-missing",
    ("referrer-policy", "missing"): "referrer-policy-missing",
    ("referrer-policy", "unsafe"): "referrer-policy-unsafe",
    ("permissions-policy", "missing"): "permissions-policy-missing",
}


class SecurityHeadersCheck(Check):
    meta = CheckMeta(
        id="security-headers",
        name="Security Headers Check",
        category=CheckCategory.HEADERS,
        safety_profile=SafetyProfile.PASSIVE,
        description="Verifies presence and proper configuration of HTTP security headers (CSP, X-Frame-Options, HSTS, etc.).",
        references=["CWE-693", "OWASP A05:2021"],
    )

    async def discover(self, ctx) -> list[dict[str, Any]]:
        if not self.deps:
            return []
        url = join_url(str(self.deps.config.target.base_url), "/")
        try:
            req = Request(method="GET", url=url, purpose="discovery")
            resp = await self.deps.http.send(req)
        except Exception:
            return []

        # Lower-case keys for case-insensitive matching
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        candidates: list[dict[str, Any]] = []

        for header_lower, (default_sev, evaluator) in _HEADER_RULES.items():
            value = headers_lower.get(header_lower)
            if value is None:
                candidates.append({
                    "header": header_lower,
                    "value": None,
                    "issue": "missing",
                    "severity": default_sev,
                    "response": resp,
                    "request": req,
                })
                continue
            issue, sev_override = evaluator(value)
            if issue != "present":
                candidates.append({
                    "header": header_lower,
                    "value": value,
                    "issue": issue,
                    "severity": sev_override or default_sev,
                    "response": resp,
                    "request": req,
                })

        return candidates

    async def validate(self, ctx, candidate) -> ValidationResult:
        return ValidationResult(
            outcome=ValidationOutcome.CONFIRMED,
            confidence="high",
            observation=f"header issue '{candidate['issue']}' observed in response",
        )

    async def collect_evidence(self, candidate) -> list[Evidence]:
        resp = candidate.get("response")
        req = candidate.get("request")
        if not resp or not req:
            return []
        kind = ObservationKind.HEADER_MISSING if candidate["issue"] == "missing" else ObservationKind.HEADER_PRESENT
        return [Evidence(
            request=req,
            response=resp,
            kind=kind,
            endpoint=req.url,
            method="GET",
            parameter=candidate["header"],
            input_used=candidate.get("value") or "(not set)",
            status_code=resp.status_code,
            relevant_headers={candidate["header"]: candidate.get("value") or "(not set)"},
            body_excerpt="",
            observation=f"header {candidate['header']} issue: {candidate['issue']}",
        )]

    async def assess(self, candidate) -> Finding | None:
        header = candidate["header"]
        issue = candidate["issue"]
        title = {
            "missing": f"Missing {header.title()} Header",
            "wildcard": "Overly Permissive Content-Security-Policy",
            "improper": f"Improperly Configured {header.title()} Header",
            "short_max_age": "Strict-Transport-Security max-age Too Short",
            "unsafe": f"Unsafe {header.title()} Value",
        }.get(issue, f"{header.title()} Header Issue")

        cwe_map = {
            "content-security-policy": "CWE-1021",
            "x-frame-options": "CWE-1021",
            "x-content-type-options": "CWE-693",
            "strict-transport-security": "CWE-319",
            "referrer-policy": "CWE-693",
            "permissions-policy": "CWE-693",
        }

        base = str(self.deps.config.target.base_url)
        parsed = urlparse(base)
        endpoint = join_url(base, "/")

        # Pull rich content from the knowledge base. Falls back to the
        # generic boilerplate if the entry is missing.
        kind_key = _KIND_MAP.get((header, issue), issue)
        entry = get_entry(self.meta.id, kind_key) or get_entry(self.meta.id, issue)

        if entry:
            summary = entry["summary"]
            technical = entry["technical"]
            impact = entry["impact"]
            remediation = list(entry["remediation"])
            attack_scenario = entry["attack_scenario"]
            code_examples = dict(entry["code_examples"])
        else:
            summary = f"The {header} header is {issue}."
            technical = (
                f"The HTTP response from the target is missing or has an improper value for the "
                f"{header} security header. This header is part of defense-in-depth and helps prevent "
                f"common browser-side attacks."
            )
            impact = (
                "Missing security headers can enable cross-site scripting, clickjacking, MIME sniffing, "
                "and downgrade attacks."
            )
            remediation = [
                f"Configure the {header} header according to OWASP recommendations.",
                "Use a security headers generator (e.g. securityheaders.com) to set all recommended headers.",
            ]
            attack_scenario = None
            code_examples = {}

        return Finding(
            check=CheckRef(id=self.meta.id, name=self.meta.name, category=self.meta.category.value, version=self.meta.version),
            title=title,
            severity=candidate["severity"],
            confidence=Confidence.HIGH,
            status=FindingStatus.CONFIRMED,
            target=TargetRef(
                host=parsed.hostname or "",
                port=parsed.port,
                scheme=parsed.scheme or "https",
                endpoint="/",
                method="GET",
            ),
            parameter=header,
            input_used=candidate.get("value") or "(not set)",
            summary=summary,
            technical_explanation=technical,
            impact=impact,
            remediation=remediation,
            attack_scenario=attack_scenario,
            code_examples=code_examples,
            cwe=[cwe_map.get(header, "CWE-693")],
            owasp=["A05:2021"],
        )
