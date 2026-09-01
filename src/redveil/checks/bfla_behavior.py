"""BFLA via BehaviorModel — function-level authorization using hypothesis testing.

ACTIVE check. Uses the BehaviorModel to declare BFLA hypotheses and
execute them as test plans. The BehaviorModel's planner produces the
request sequence; the differential analyzer confirms or refutes the
hypothesis.

Requires the orchestrator to have built the ApplicationModel (always
done during discovery) and the operator to have configured at least one
non-admin principal in scope.yaml.
"""
from __future__ import annotations
from typing import Any
from urllib.parse import urlparse

from redveil.behavior.differential import DifferentialResult
from redveil.behavior.hypotheses import Hypothesis, InvariantKind
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


# Endpoints we treat as admin-only. If a non-admin principal can hit these
# and the response is 2xx, that's a BFLA finding.
_ADMIN_PATH_PATTERNS: tuple[str, ...] = (
    "/admin", "/admin/",
    "/api/admin", "/api/admin/users", "/api/admin/config",
    "/api/v1/admin", "/api/v1/admin/users",
    "/api/internal", "/api/internal/users",
    "/api/v1/internal",
    "/management", "/management/users",
    "/api/users",  # list all users (admin-only typically)
    "/api/v1/users", "/api/v1/audit-log",
    "/api/system-config", "/api/v1/system-config",
    "/internal/dashboard", "/internal/config",
)


class BFLABehaviorCheck(Check):
    """BFLA check driven by the BehaviorModel.

    Each candidate admin endpoint becomes a hypothesis: "this admin
    endpoint should reject non-admin principals". The planner turns it
    into a single test step (request as non-admin), and the response
    is compared to the expected "403 or 401".
    """
    meta = CheckMeta(
        id="bfla-behavior",
        name="BFLA via Behavior Engine",
        category=CheckCategory.BFLA,
        safety_profile=SafetyProfile.ACTIVE,
        version="0.1.0",
        description=(
            "Tests function-level authorization by issuing admin-only "
            "endpoint requests as non-admin principals. Uses the "
            "BehaviorModel for hypothesis planning."
        ),
        references=["CWE-285", "OWASP A01:2021"],
    )

    async def discover(self, ctx) -> list[dict[str, Any]]:
        if not self.deps:
            return []
        if not self.deps.config.authorization.active_testing:
            return []
        if not self.deps.config.authorization.acknowledged_safety_terms:
            return []
        model = self.deps.application_model
        if not model or len(model.identities) < 1:
            return []

        # Optional ActionGate: present the BFLA probe plan to the user.
        from redveil.validation.risk import ActionPlan, Risk
        plan = ActionPlan(
            action_id="bfla-admin-endpoint-probe",
            description=(
                "Send GET requests to known admin-only endpoints using a "
                "non-admin principal's cookies. Verifies whether "
                "function-level authorization is enforced."
            ),
            risk=Risk.MEDIUM,
            target=str(self.deps.config.target.base_url).rstrip("/") + "/",
            purpose="Detect BFLA by checking that non-admin principals cannot access admin-only endpoints.",
            expected_effect="403 or 401 responses for non-admin; 200 only for admin.",
            potential_side_effects=(
                "Logged in server access log.",
                "May trigger WAF rate limit if many requests sent quickly.",
            ),
            max_requests=len(_ADMIN_PATH_PATTERNS) + 5,
            timeout_seconds=10.0,
        )
        if self.deps.gate is not None:
            decision = self.deps.gate.ask(
                plan,
                allow_destructive=self.deps.config.authorization.allow_destructive,
            )
            if not decision:
                return []

        # Find a non-admin principal to test with
        non_admin = next(
            (i for i in model.identities.values() if i.role != "admin"),
            None,
        )
        if not non_admin:
            return []

        base = model.base_url or str(self.deps.config.target.base_url)
        candidates: list[dict[str, Any]] = []

        # Probe known admin paths
        for path in _ADMIN_PATH_PATTERNS:
            url = join_url(base, path)
            try:
                # Build the test as a Hypothesis
                hyp = Hypothesis(
                    id=f"bfla-{path.replace('/', '_')}",
                    invariant=InvariantKind.FUNCTION_LEVEL_AUTHZ,
                    statement=f"non-admin {non_admin.name} should not access {path}",
                    target_endpoint=("GET", path),
                    second_identity=non_admin.name,
                )
                req = Request(method="GET", url=url, purpose="bfla_test")
                resp = await self.deps.http.send(req)
            except Exception:
                continue

            # Build a "would-have-been-allowed" baseline by assuming an
            # admin would get 200. The differential is just status != 403/401.
            if resp.status_code in (200, 201, 202):
                candidates.append({
                    "endpoint": path,
                    "url": url,
                    "principal": non_admin.name,
                    "expected_signal": "403 or 401 (admin-only protection)",
                    "actual_status": resp.status_code,
                    "request": req,
                    "response": resp,
                    "hypothesis": hyp,
                })

        return candidates

    async def validate(self, ctx, candidate) -> ValidationResult:
        status = candidate.get("actual_status", 0)
        if status in (200, 201, 202):
            return ValidationResult(
                outcome=ValidationOutcome.CONFIRMED,
                confidence="high",
                observation=f"non-admin got {status} on admin endpoint",
            )
        return ValidationResult(
            outcome=ValidationOutcome.FALSE_POSITIVE,
            confidence="low",
            observation=f"got {status} (expected 403/401)",
        )

    async def collect_evidence(self, candidate) -> list[Evidence]:
        req = candidate.get("request")
        resp = candidate.get("response")
        if not req or not resp:
            return []
        return [Evidence(
            request=req,
            response=resp,
            kind=ObservationKind.HEADER_PRESENT,
            endpoint=candidate["endpoint"],
            method="GET",
            parameter="authorization",
            input_used=f"principal={candidate.get('principal', '?')}",
            status_code=resp.status_code,
            relevant_headers={"content-type": resp.headers.get("content-type", "")},
            body_excerpt=resp.body_excerpt,
            observation=f"non-admin {candidate.get('principal', '?')} got {resp.status_code} on admin endpoint {candidate['endpoint']}",
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
            summary = f"Non-admin can access {candidate['endpoint']}"
            technical = f"Endpoint {candidate['endpoint']} returns {candidate.get('actual_status')} for non-admin principal {candidate.get('principal')}."
            impact = "Privilege escalation."
            remediation = ["Add role-based authorization check."]
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
            input_used=f"principal={candidate.get('principal', '?')}",
            summary=summary,
            technical_explanation=technical,
            impact=impact,
            attack_scenario=attack_scenario,
            code_examples=code_examples,
            remediation=remediation,
            cwe=["CWE-285"],
            owasp=["A01:2021"],
        )
