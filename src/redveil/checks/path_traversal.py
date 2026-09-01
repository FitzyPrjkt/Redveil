"""PathTraversalCheck — detects path traversal via canary probing.

ACTIVE check. Uses ONLY unique random canary filenames that cannot exist on
real systems. Does NOT attempt to read any real file (no /etc/passwd etc).
The proof is the RESPONSE PATTERN (status, body length, error message), not
actual file content.
"""
from __future__ import annotations

import secrets
from typing import Any
from urllib.parse import quote, urlparse

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


# ONLY traversal sequences with a unique canary filename. NO references to real files.
# Canary is generated per scan to ensure the file cannot exist on the target.
def _build_canary() -> str:
    return f"redveil_canary_{secrets.token_hex(8)}.txt"

_TRAVERSAL_SEQUENCES = [
    "../{canary}",                          # simple
    "../../{canary}",                       # deeper
    "../../../{canary}",                    # deepest
    "....//{canary}",                       # double-dot bypass
    "..%2f{canary}",                        # URL-encoded /
    "..\\{canary}",                         # Windows backslash
    "/etc/{canary}",                        # absolute path attempt
    "//etc/{canary}",                       # double-slash bypass
]

# Safety: NO references to real sensitive files
_FORBIDDEN_FILES = (
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "system32", "win.ini", "boot.ini", "config.sys", "SAM",
    ".ssh/id_rsa", ".aws/credentials", ".kube/config",
)
for _seq in _TRAVERSAL_SEQUENCES:
    for _bad in _FORBIDDEN_FILES:
        if _bad in _seq:
            raise RuntimeError(f"FORBIDDEN file reference {_bad!r} in traversal sequence {_seq!r}")

# File-serving parameter names
_FILE_PARAMS = [
    "file", "path", "page", "template", "include", "src", "source",
    "url", "img", "image", "name", "doc", "document", "folder", "dir",
    "pg", "style", "pdf", "filename", "filepath", "resource", "load",
]


def _generate_traversal_payloads() -> list[tuple[str, str]]:
    """Generate traversal payloads with a unique canary per call."""
    canary = _build_canary()
    payloads = []
    for seq in _TRAVERSAL_SEQUENCES:
        # Replace {canary} placeholder
        payload = seq.replace("{canary}", canary)
        payloads.append((payload, canary))
    return payloads, canary


class PathTraversalCheck(Check):
    meta = CheckMeta(
        id="path-traversal",
        name="Path Traversal Check",
        category=CheckCategory.PATH_TRAVERSAL,
        safety_profile=SafetyProfile.ACTIVE,
        description="Detects path traversal using unique canary filenames. Does not read any real file.",
        references=["CWE-22", "OWASP A01:2021"],
    )

    async def discover(self, ctx) -> list[dict[str, Any]]:
        if not self.deps:
            return []
        if not self.deps.config.authorization.active_testing:
            return []
        if not self.deps.config.authorization.acknowledged_safety_terms:
            return []

        # Optional ActionGate: present the path-traversal canary probe plan to the user.
        # The gate only blocks MEDIUM+ in interactive mode. Canary probes are LOW
        # risk (only random canary filenames, no real file paths) so this is
        # auto-approved.
        from redveil.validation.risk import ActionPlan, Risk
        plan = ActionPlan(
            action_id="path-traversal-canary-probe",
            description=(
                "Send path-traversal probes using unique random canary "
                "filenames (../canary, ../../canary, etc.) to file-serving "
                "parameters. No real file paths are read. Per parameter: 1 "
                "baseline request + N traversal sequences. Only sends GET "
                "requests with query parameters. No file read, no body "
                "modification."
            ),
            risk=Risk.LOW,
            target=f"{self.deps.config.target.base_url}/",
            purpose=(
                "Detect path traversal by observing whether canary filenames "
                "produce different responses than baseline."
            ),
            expected_effect=(
                "Baseline 404 + canary 200/404 indicates the parameter is "
                "reflected but traversal is filtered. Same 404 for both "
                "indicates no traversal."
            ),
            potential_side_effects=(
                "Logged in server access log.",
                "Canary file request may be logged (the file does not exist).",
            ),
            max_requests=len(_TRAVERSAL_SEQUENCES) * len(_FILE_PARAMS),
            timeout_seconds=10.0,
        )
        if self.deps.gate is not None:
            decision = self.deps.gate.ask(
                plan,
                allow_destructive=self.deps.config.authorization.allow_destructive,
            )
            if not decision:
                # User denied or auto-denied (destructive in non-interactive).
                return []

        base = str(self.deps.config.target.base_url).rstrip("/")
        candidates: list[dict[str, Any]] = []

        payloads, canary = _generate_traversal_payloads()

        for param in _FILE_PARAMS:
            # Baseline: known-bad value (just the canary, no traversal) — should 404
            baseline_url = f"{join_url(base, '/')}?{param}={canary}"
            try:
                req_base = Request(method="GET", url=baseline_url, purpose="baseline")
                resp_base = await self.deps.http.send(req_base)
            except Exception:
                continue

            # Now test each traversal payload
            for payload, c in payloads:
                if c != canary:
                    continue  # safety: only use our own canary
                try:
                    test_url = f"{join_url(base, '/')}?{param}={quote(payload, safe='/\\')}"
                    req = Request(method="GET", url=test_url, purpose="probe", purpose_extra="path_traversal")
                    resp = await self.deps.http.send(req)
                except Exception:
                    continue

                # Compare to baseline
                if resp.status_code == resp_base.status_code and len(resp.body) == len(resp_base.body):
                    # Same response — no traversal evidence
                    continue
                if resp.status_code != resp_base.status_code:
                    behavior = "different_status"
                else:
                    behavior = "different_length"

                # Don't flag if the canary appears in the response — the server is just echoing
                if canary in resp.body and canary not in resp_base.body:
                    behavior = "canary_reflected"

                candidates.append({
                    "endpoint": "/",
                    "parameter": param,
                    "method": "GET",
                    "payload": payload,
                    "canary": canary,
                    "baseline_status": resp_base.status_code,
                    "baseline_length": len(resp_base.body),
                    "canary_status": resp.status_code,
                    "canary_length": len(resp.body),
                    "behavior": behavior,
                    "request": req,
                    "response": resp,
                })
                break  # one finding per param is enough

        return candidates

    async def validate(self, ctx, candidate) -> ValidationResult:
        if candidate.get("behavior") == "canary_reflected":
            return ValidationResult(
                outcome=ValidationOutcome.LIKELY,
                confidence="low",
                observation="canary filename appeared in response; param may be reflected without sanitization",
            )
        if candidate.get("behavior") in {"different_status", "different_length"}:
            return ValidationResult(
                outcome=ValidationOutcome.CONFIRMED,
                confidence="high",
                observation="traversal payload produces different response (status/length) from baseline",
            )
        return ValidationResult(outcome=ValidationOutcome.FALSE_POSITIVE, confidence="low", observation="no traversal evidence")

    async def collect_evidence(self, candidate) -> list[Evidence]:
        resp = candidate.get("response")
        req = candidate.get("request")
        if not resp or not req:
            return []
        return [Evidence(
            request=req,
            response=resp,
            kind=ObservationKind.FILE_EXISTENCE,
            endpoint="/",
            method="GET",
            parameter=candidate.get("parameter"),
            input_used=candidate.get("payload", ""),
            status_code=resp.status_code,
            relevant_headers={"content-type": resp.headers.get("content-type", "")},
            body_excerpt=resp.body_excerpt,
            observation=f"baseline=({candidate['baseline_status']}, {candidate['baseline_length']}B); traversal=({candidate['canary_status']}, {candidate['canary_length']}B); behavior={candidate['behavior']}",
        )]

    async def assess(self, candidate) -> Finding | None:
        entry = get_entry(self.meta.id, "path_traversal")
        if entry:
            summary = entry["summary"]
            technical = entry["technical"]
            impact = entry["impact"]
            remediation = list(entry["remediation"])
            attack_scenario = entry["attack_scenario"]
            code_examples = dict(entry["code_examples"])
        else:
            summary = f"Path traversal detected in '{candidate['parameter']}' parameter."
            technical = "The parameter is used in a file path without proper validation; traversal sequences change the response."
            impact = "Attacker can read arbitrary files on the server."
            remediation = ["Validate file paths against an allowlist.", "Reject paths containing '..' or absolute paths."]
            attack_scenario = None
            code_examples = {}

        base = str(self.deps.config.target.base_url)
        parsed = urlparse(base)
        return Finding(
            check=CheckRef(id=self.meta.id, name=self.meta.name, category=self.meta.category.value, version=self.meta.version),
            title=f"Path Traversal via '{candidate['parameter']}' Parameter",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            status=FindingStatus.CONFIRMED,
            target=TargetRef(
                host=parsed.hostname or "",
                port=parsed.port,
                scheme=parsed.scheme or "https",
                endpoint="/",
                method="GET",
                parameter=candidate["parameter"],
            ),
            parameter=candidate["parameter"],
            input_used=candidate.get("payload", ""),
            summary=summary,
            technical_explanation=technical,
            impact=impact,
            attack_scenario=attack_scenario,
            code_examples=code_examples,
            remediation=remediation,
            cwe=["CWE-22"],
            owasp=["A01:2021"],
        )
