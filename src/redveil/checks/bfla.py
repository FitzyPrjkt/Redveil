"""BFLACheck — Broken Function Level Authorization.

ACTIVE check. Probes admin-only endpoints with a non-admin principal to
detect missing role-based authorization. Read-only — never invokes
mutating admin actions.
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

# Admin path patterns (read-only — no mutating actions)
_ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/dashboard", "/admin/users",
    "/api/admin", "/api/admin/users", "/api/admin/config",
    "/internal", "/internal/", "/internal/dashboard",
    "/api/internal", "/api/internal/users",
    "/management", "/management/", "/management/users",
    "/system", "/system/config", "/api/system",
    "/users",          # list-all-users endpoint pattern
    "/api/v1/admin", "/api/v1/internal",
    "/debug", "/api/debug", "/_debug",
    "/api/v1/users",   # admin list users
    "/api/v1/audit-log",
    "/api/v1/system-config",
]


# Words that suggest admin-shaped content
_ADMIN_CONTENT_MARKERS = (
    "user_id", "userId", "users",
    "admin", "is_admin", "isAdmin", "role",
    "permission", "permissions",
    "config", "configuration",
    "internal_id", "internalId",
    "secret", "api_key", "apikey",
    "audit", "log",
    "all_users", "allUsers",
    "balance", "credit",
)


class BFLACheck(Check):
    meta = CheckMeta(
        id="bfla",
        name="BFLA / Function-Level Authorization Check",
        category=CheckCategory.BFLA,
        safety_profile=SafetyProfile.ACTIVE,
        description="Detects admin-only endpoints accessible to non-admin principals via role-based authorization testing.",
        references=["CWE-285", "OWASP A01:2021"],
    )

    async def discover(self, ctx) -> list[dict[str, Any]]:
        if not self.deps:
            return []
        if not self.deps.config.authorization.active_testing:
            return []
        if not self.deps.config.authorization.acknowledged_safety_terms:
            return []
        # Need a non-admin principal to test with
        principals = self.deps.config.auth.principals
        if not principals:
            return []

        base = str(self.deps.config.target.base_url).rstrip("/")
        candidates: list[dict[str, Any]] = []
        low_priv = principals[0]  # first principal is treated as the low-privilege user

        # Build auth override from the low-priv principal
        override_headers, override_cookies = low_priv.to_override() if hasattr(low_priv, "to_override") else ({}, {})

        for path in _ADMIN_PATHS:
            try:
                url = join_url(base, path)
                req = Request(
                    method="GET",
                    url=url,
                    auth_principal=low_priv.name,
                    auth_override_headers=override_headers,
                    auth_override_cookies=override_cookies,
                    purpose="probe",
                    purpose_extra="bfla",
                )
                resp = await self.deps.http.send(req)
            except Exception:
                continue

            if resp.status_code not in (200, 201):
                continue

            body = resp.body
            # Look for admin-shaped content
            body_lower = body.lower()
            marker_count = sum(1 for m in _ADMIN_CONTENT_MARKERS if m.lower() in body_lower)
            if marker_count >= 2:
                candidates.append({
                    "endpoint": path,
                    "method": "GET",
                    "principal": low_priv.name,
                    "expected_role": "admin",
                    "status_code": resp.status_code,
                    "marker_count": marker_count,
                    "request": req,
                    "response": resp,
                })

        return candidates

    async def validate(self, ctx, candidate) -> ValidationResult:
        if candidate.get("marker_count", 0) >= 3:
            return ValidationResult(
                outcome=ValidationOutcome.CONFIRMED,
                confidence="high",
                observation=f"admin endpoint accessible to non-admin; {candidate['marker_count']} admin-shaped markers in response",
            )
        if candidate.get("marker_count", 0) >= 2:
            return ValidationResult(
                outcome=ValidationOutcome.LIKELY,
                confidence="medium",
                observation=f"admin endpoint accessible; {candidate['marker_count']} markers — manual review recommended",
            )
        return ValidationResult(outcome=ValidationOutcome.FALSE_POSITIVE, confidence="low", observation="insufficient evidence")

    async def collect_evidence(self, candidate) -> list[Evidence]:
        resp = candidate.get("response")
        req = candidate.get("request")
        if not resp or not req:
            return []
        return [Evidence(
            request=req,
            response=resp,
            kind=ObservationKind.HEADER_PRESENT,
            endpoint=candidate["endpoint"],
            method="GET",
            parameter="authorization",
            input_used=f"principal={candidate.get('principal', 'unknown')}",
            status_code=resp.status_code,
            relevant_headers={"content-type": resp.headers.get("content-type", "")},
            body_excerpt=resp.body_excerpt,
            observation=f"admin endpoint accessible; {candidate.get('marker_count', 0)} admin markers",
        )]

    async def assess(self, candidate) -> Finding | None:
        entry = get_entry("bfla", "function_level")
        if entry:
            summary = entry["summary"]
            technical = entry["technical"]
            impact = entry["impact"]
            remediation = list(entry["remediation"])
            attack_scenario = entry["attack_scenario"]
            code_examples = dict(entry["code_examples"])
        else:
            summary = f"Admin-only endpoint {candidate['endpoint']} is accessible to non-admin principal."
            technical = "The endpoint returns admin-shaped content without checking the requester's role."
            impact = "Privilege escalation: non-admin users can perform admin actions or read admin data."
            remediation = ["Verify requester's role on every admin endpoint.", "Use role-based access control middleware."]
            attack_scenario = None
            code_examples = {}

        base = str(self.deps.config.target.base_url)
        parsed = urlparse(base)
        return Finding(
            check=CheckRef(id=self.meta.id, name=self.meta.name, category=self.meta.category.value, version=self.meta.version),
            title=f"BFLA: Non-Admin Can Access {candidate['endpoint']}",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            status=FindingStatus.CONFIRMED,
            target=TargetRef(
                host=parsed.hostname or "",
                port=parsed.port,
                scheme=parsed.scheme or "https",
                endpoint=candidate["endpoint"],
                method="GET",
            ),
            parameter="authorization",
            input_used=f"principal={candidate.get('principal', 'unknown')}",
            summary=summary,
            technical_explanation=technical,
            impact=impact,
            attack_scenario=attack_scenario,
            code_examples=code_examples,
            remediation=remediation,
            cwe=["CWE-285"],
            owasp=["A01:2021"],
        )
