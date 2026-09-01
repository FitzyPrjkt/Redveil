"""MassAssignmentCheck — passive-leaning detector for sensitive fields exposed via API.

Detects when GET responses contain sensitive fields that should not be
user-readable (and by extension, possibly user-modifiable via mass
assignment). Strictly passive — does NOT attempt to write or modify data.
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

# (regex matching field name, severity if found, sensitivity label)
_SENSITIVE_FIELD_PATTERNS: list[tuple[re.Pattern, Severity, str]] = [
    # Admin / role
    (re.compile(r"^is_admin$", re.IGNORECASE), Severity.HIGH, "admin"),
    (re.compile(r"^is_superuser$", re.IGNORECASE), Severity.HIGH, "admin"),
    (re.compile(r"^is_staff$", re.IGNORECASE), Severity.HIGH, "admin"),
    (re.compile(r"^is_moderator$", re.IGNORECASE), Severity.HIGH, "admin"),
    (re.compile(r"^role$", re.IGNORECASE), Severity.HIGH, "admin"),
    (re.compile(r"^user_role$", re.IGNORECASE), Severity.HIGH, "admin"),
    (re.compile(r"^permissions$", re.IGNORECASE), Severity.HIGH, "admin"),
    (re.compile(r"^groups$", re.IGNORECASE), Severity.HIGH, "admin"),
    # Financial
    (re.compile(r"^balance$", re.IGNORECASE), Severity.MEDIUM, "financial"),
    (re.compile(r"^credit_limit$", re.IGNORECASE), Severity.MEDIUM, "financial"),
    (re.compile(r"^internal_balance$", re.IGNORECASE), Severity.HIGH, "financial"),
    (re.compile(r"^account_balance$", re.IGNORECASE), Severity.MEDIUM, "financial"),
    # Verification status
    (re.compile(r"^email_verified$", re.IGNORECASE), Severity.LOW, "verification"),
    (re.compile(r"^phone_verified$", re.IGNORECASE), Severity.LOW, "verification"),
    (re.compile(r"^kyc_status$", re.IGNORECASE), Severity.MEDIUM, "verification"),
    (re.compile(r"^two_factor_enabled$", re.IGNORECASE), Severity.LOW, "verification"),
    (re.compile(r"^mfa_enabled$", re.IGNORECASE), Severity.LOW, "verification"),
    # Internal / segmentation
    (re.compile(r"^internal_id$", re.IGNORECASE), Severity.MEDIUM, "internal"),
    (re.compile(r"^customer_segment$", re.IGNORECASE), Severity.MEDIUM, "internal"),
    (re.compile(r"^risk_score$", re.IGNORECASE), Severity.MEDIUM, "internal"),
    (re.compile(r"^tenant_id$", re.IGNORECASE), Severity.MEDIUM, "internal"),
]

# Endpoints to probe (typically where the user's own profile is)
_PROFILE_PATHS = [
    "/api/profile/me", "/api/profile",
    "/api/user/me", "/api/user",
    "/api/users/me", "/api/users",
    "/api/me", "/api/account", "/api/account/me",
    "/api/v1/profile", "/api/v1/user", "/api/v1/users/me",
    "/api/v1/account", "/api/v1/me",
]


def _extract_field_names(obj: Any, path: str = "") -> set[tuple[str, str]]:
    """Walk a JSON object, return set of (field_name, full_path) tuples for leaf fields."""
    out: set[tuple[str, str]] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            full = f"{path}.{k}" if path else k
            if isinstance(v, (dict, list)):
                out.update(_extract_field_names(v, full))
            else:
                out.add((k, full))
    elif isinstance(obj, list):
        for i, item in enumerate(obj[:10]):  # cap list walking
            out.update(_extract_field_names(item, f"{path}[{i}]"))
    return out


class MassAssignmentCheck(Check):
    meta = CheckMeta(
        id="mass-assignment",
        name="Mass Assignment Check",
        category=CheckCategory.MASS_ASSIGNMENT,
        safety_profile=SafetyProfile.PASSIVE,
        description="Detects when API responses expose sensitive fields (admin/role/balance/etc.) that may also be modifiable via mass assignment. Strictly passive — does not attempt writes.",
        references=["CWE-915", "OWASP A06:2021"],
    )

    async def discover(self, ctx) -> list[dict[str, Any]]:
        if not self.deps:
            return []
        base = str(self.deps.config.target.base_url).rstrip("/")
        candidates: list[dict[str, Any]] = []

        for path in _PROFILE_PATHS:
            try:
                req = Request(method="GET", url=join_url(base, path), purpose="discovery")
                resp = await self.deps.http.send(req)
            except Exception:
                continue
            if resp.status_code != 200:
                continue
            # Try to parse as JSON
            try:
                data = json.loads(resp.body)
            except (json.JSONDecodeError, ValueError):
                continue
            # Extract field names
            field_names = _extract_field_names(data)
            # Check each against sensitive patterns
            seen: set[str] = set()
            for field_name, full_path in field_names:
                if field_name in seen:
                    continue
                for pattern, severity, sensitivity in _SENSITIVE_FIELD_PATTERNS:
                    if pattern.match(field_name):
                        candidates.append({
                            "endpoint": path,
                            "method": "GET",
                            "field": field_name,
                            "field_path": full_path,
                            "severity": severity,
                            "sensitivity": sensitivity,
                            "request": req,
                            "response": resp,
                        })
                        seen.add(field_name)
                        break

        return candidates

    async def validate(self, ctx, candidate) -> ValidationResult:
        sev = candidate.get("severity", Severity.MEDIUM)
        if sev in (Severity.HIGH, Severity.CRITICAL):
            return ValidationResult(
                outcome=ValidationOutcome.LIKELY,
                confidence="medium",
                observation=f"sensitive field '{candidate['field']}' ({candidate['sensitivity']}) exposed in API response",
            )
        return ValidationResult(
            outcome=ValidationOutcome.LIKELY,
            confidence="low",
            observation=f"field '{candidate['field']}' ({candidate['sensitivity']}) exposed — manual review",
        )

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
            parameter=candidate["field"],
            input_used="(response body field)",
            status_code=resp.status_code,
            relevant_headers={"content-type": resp.headers.get("content-type", "")},
            body_excerpt=resp.body_excerpt,
            observation=f"sensitive field '{candidate['field']}' ({candidate['sensitivity']}) exposed in {candidate['endpoint']}",
        )]

    async def assess(self, candidate) -> Finding | None:
        entry = get_entry("mass-assignment", "excessive_exposure")
        if entry:
            summary = entry["summary"]
            technical = entry["technical"]
            impact = entry["impact"]
            remediation = list(entry["remediation"])
            attack_scenario = entry["attack_scenario"]
            code_examples = dict(entry["code_examples"])
        else:
            summary = f"Sensitive field '{candidate['field']}' is exposed in the API response."
            technical = (
                f"The endpoint {candidate['endpoint']} returns the field "
                f"'{candidate['field']}' (sensitivity: {candidate['sensitivity']}). "
                f"This may also indicate the field is modifiable via mass assignment."
            )
            impact = "Information disclosure. If the field is also writable, privilege escalation may be possible."
            remediation = ["Use a serializer with an explicit allowlist of fields.", "Never bind user input directly to ORM models."]
            attack_scenario = None
            code_examples = {}

        base = str(self.deps.config.target.base_url)
        parsed = urlparse(base)
        return Finding(
            check=CheckRef(id=self.meta.id, name=self.meta.name, category=self.meta.category.value, version=self.meta.version),
            title=f"Sensitive Field Exposed: {candidate['field']}",
            severity=candidate["severity"],
            confidence=Confidence.MEDIUM,
            status=FindingStatus.LIKELY,
            target=TargetRef(
                host=parsed.hostname or "",
                port=parsed.port,
                scheme=parsed.scheme or "https",
                endpoint=candidate["endpoint"],
                method="GET",
            ),
            parameter=candidate["field"],
            input_used="(field in response body)",
            summary=summary,
            technical_explanation=technical,
            impact=impact,
            attack_scenario=attack_scenario,
            code_examples=code_examples,
            remediation=remediation,
            cwe=["CWE-915"],
            owasp=["A06:2021"],
        )
