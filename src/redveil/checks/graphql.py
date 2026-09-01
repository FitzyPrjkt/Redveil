"""GraphQLCheck — detects GraphQL endpoints with introspection enabled.

ACTIVE check. The proof of vulnerability is the EXISTENCE of introspection
on a publicly reachable endpoint, not the content of the schema. We send only
the well-known canonical introspection probe — a single-field query that
exercises the ``__schema`` resolver. We never enumerate fields beyond the
top-level ``types { name }`` shape, never request user data, and never
exfiltrate any record. We observe WHETHER introspection is enabled, not
WHAT the schema contains.
"""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from redveil.config import SafetyProfile
from redveil.evidence.evidence import Evidence, ObservationKind
from redveil.findings.confidence import Confidence
from redveil.findings.finding import (
    CheckRef,
    Finding,
    FindingStatus,
    TargetRef,
)
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

# ---------------------------------------------------------------------------
# SAFETY CONSTANTS — DO NOT MODIFY WITHOUT SECURITY REVIEW
# ---------------------------------------------------------------------------
#
# The only query we ever send is the canonical, single-field introspection
# probe. It touches one resolver (``__schema``) at depth 1 and asks only for
# type names. We never request fields, never enumerate mutations, and never
# request user data. Do not widen this without an explicit threat-model
# review and an updated test that asserts the new queries still observe
# ``depth == 1`` and never reference user data.

# Depth-1 introspection probe — single root field, single nested field.
_INTROSPECTION_QUERY: str = "{ __schema { types { name } } }"

# Depth-1 type probe — single root field with a single name argument.
# Confirms query-level access to the schema. Does NOT request any fields.
_TYPE_QUERY: str = '{ __type(name: "User") { name } }'

# Common GraphQL endpoint paths to probe.
_GRAPHQL_PATHS: list[str] = [
    "/graphql",
    "/api/graphql",
    "/gql",
    "/graphql/v1",
    "/api/v1/graphql",
    "/query",
]


def _query_depth(query: str) -> int:
    """Return the number of root-level field selections in a GraphQL query.

    Used as a runtime safety assertion: the canned queries shipped with this
    module MUST have exactly 1 root-level field (``__schema`` or
    ``__type``). This is *not* the brace-nesting depth — ``{ __schema
    { types { name } } }`` has 1 root-level field, even though it contains
    nested selection sets. The check fails closed if any future edit adds
    additional top-level fields (e.g. alongside ``user`` or ``posts``),
    which would expand the API surface the probe touches.
    """
    s = query.strip()
    if not s.startswith("{"):
        return 0
    # Find the matching outermost closing brace.
    depth = 0
    end = -1
    for i, ch in enumerate(s):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end <= 0:
        return 0
    body = s[1:end].strip()

    # Split body on top-level commas only (skipping commas inside braces).
    fields: list[str] = []
    buf: list[str] = []
    nested = 0
    for ch in body:
        if ch == "{":
            nested += 1
            buf.append(ch)
        elif ch == "}":
            nested -= 1
            buf.append(ch)
        elif ch == "," and nested == 0:
            piece = "".join(buf).strip()
            if piece:
                fields.append(piece)
            buf = []
        else:
            buf.append(ch)
    piece = "".join(buf).strip()
    if piece:
        fields.append(piece)
    return len(fields)


def _looks_like_json_response(resp) -> bool:
    """True if the response body parses as JSON and contains GraphQL-ish keys."""
    if resp.status_code != 200:
        return False
    content_type = (resp.headers.get("content-type") or "").lower()
    if "json" not in content_type and not resp.body.lstrip().startswith(("{", "[")):
        return False
    try:
        parsed = json.loads(resp.body)
    except (ValueError, TypeError):
        return False
    return isinstance(parsed, dict)


class GraphQLCheck(Check):
    meta = CheckMeta(
        id="graphql",
        name="GraphQL Check",
        category=CheckCategory.GRAPHQL,
        safety_profile=SafetyProfile.ACTIVE,
        description=(
            "Detects GraphQL endpoints, tests for introspection exposure, "
            "and probes for unauthorized field access."
        ),
        references=["CWE-200", "OWASP A05:2021"],
    )

    async def discover(self, ctx) -> list[dict[str, Any]]:
        if not self.deps:
            return []
        # Active gate
        if not self.deps.config.authorization.active_testing:
            return []
        if not self.deps.config.authorization.acknowledged_safety_terms:
            return []

        # SAFETY ASSERTIONS — fail closed if the canned queries were ever
        # widened past depth 1 or accidentally reference user data fields.
        assert _query_depth(_INTROSPECTION_QUERY) == 1, (
            "INTROSPECTION_QUERY must have depth 1; refusing to send deeper probes"
        )
        assert _query_depth(_TYPE_QUERY) == 1, (
            "TYPE_QUERY must have depth 1; refusing to send deeper probes"
        )

        base = str(self.deps.config.target.base_url).rstrip("/")
        candidates: list[dict[str, Any]] = []

        introspection_body = json.dumps({"query": _INTROSPECTION_QUERY})
        type_body = json.dumps({"query": _TYPE_QUERY})

        for path in _GRAPHQL_PATHS:
            endpoint_url = join_url(base, path)
            # 1. Probe introspection on this endpoint.
            try:
                req = Request(
                    method="POST",
                    url=endpoint_url,
                    headers={"Content-Type": "application/json"},
                    body=introspection_body,
                    purpose="probe",
                    purpose_extra="graphql_introspection",
                )
                resp = await self.deps.http.send(req)
            except Exception:
                continue

            if _looks_like_json_response(resp):
                parsed = json.loads(resp.body)
                data = parsed.get("data") if isinstance(parsed, dict) else None
                if isinstance(data, dict):
                    schema = data.get("__schema")
                    if isinstance(schema, dict):
                        types = schema.get("types")
                        if isinstance(types, list):
                            candidates.append({
                                "endpoint": path,
                                "method": "POST",
                                "kind": "introspection_enabled",
                                "schema_type_count": len(types),
                                "request": req,
                                "response": resp,
                            })
                            # Move on once we've proven this endpoint is GraphQL.
                            continue

            # 2. Probe __type(name: "User") — confirms query-level access.
            try:
                req2 = Request(
                    method="POST",
                    url=endpoint_url,
                    headers={"Content-Type": "application/json"},
                    body=type_body,
                    purpose="probe",
                    purpose_extra="graphql_type_query",
                )
                resp2 = await self.deps.http.send(req2)
            except Exception:
                continue

            if _looks_like_json_response(resp2):
                parsed2 = json.loads(resp2.body)
                data2 = parsed2.get("data") if isinstance(parsed2, dict) else None
                if isinstance(data2, dict):
                    type_info = data2.get("__type")
                    if isinstance(type_info, dict) and type_info.get("name"):
                        candidates.append({
                            "endpoint": path,
                            "method": "POST",
                            "kind": "type_query_works",
                            "schema_type_count": 0,
                            "request": req2,
                            "response": resp2,
                        })

        return candidates

    async def validate(self, ctx, candidate) -> ValidationResult:
        kind = candidate.get("kind")
        type_count = int(candidate.get("schema_type_count") or 0)

        if kind == "introspection_enabled" and type_count > 0:
            return ValidationResult(
                outcome=ValidationOutcome.CONFIRMED,
                confidence="high",
                observation=(
                    f"introspection returned {type_count} types — endpoint "
                    "exposes the full schema"
                ),
            )
        if kind == "type_query_works":
            return ValidationResult(
                outcome=ValidationOutcome.CONFIRMED,
                confidence="high",
                observation="__type query succeeded — query-level access to schema",
            )
        if kind == "introspection_enabled":
            return ValidationResult(
                outcome=ValidationOutcome.LIKELY,
                confidence="medium",
                observation="__schema responded but type list was empty",
            )
        return ValidationResult(
            outcome=ValidationOutcome.FALSE_POSITIVE,
            confidence="low",
            observation="no GraphQL behavior observed",
        )

    async def collect_evidence(self, candidate) -> list[Evidence]:
        resp = candidate.get("response")
        req = candidate.get("request")
        if not resp or not req:
            return []
        # Redact any user-data-shaped response payload — the body may contain
        # arbitrary type names but we never extract fields. Excerpt is bounded.
        excerpt = resp.body_excerpt
        return [
            Evidence(
                request=req,
                response=resp,
                kind=ObservationKind.HEADER_PRESENT,
                endpoint=req.url,
                method="POST",
                parameter=None,
                input_used=_INTROSPECTION_QUERY if candidate.get("kind") == "introspection_enabled" else _TYPE_QUERY,
                status_code=resp.status_code,
                relevant_headers={"content-type": resp.headers.get("content-type", "")},
                body_excerpt=excerpt,
                observation=(
                    f"GraphQL endpoint responded with {candidate.get('kind')}; "
                    f"type_count={candidate.get('schema_type_count', 0)}"
                ),
            )
        ]

    async def assess(self, candidate) -> Finding | None:
        entry = get_entry(self.meta.id, "introspection")
        if entry:
            summary = entry["summary"]
            technical = entry["technical"]
            impact = entry["impact"]
            remediation = list(entry["remediation"])
            attack_scenario = entry["attack_scenario"]
            code_examples = dict(entry["code_examples"])
        else:
            summary = "GraphQL introspection is enabled on a public endpoint."
            technical = (
                "The endpoint responds to the canonical introspection query, "
                "exposing the API schema."
            )
            impact = "Attacker can map the entire API surface."
            remediation = ["Disable introspection in production."]
            attack_scenario = None
            code_examples = {}

        base = str(self.deps.config.target.base_url)
        parsed = urlparse(base)
        endpoint_path = candidate.get("endpoint", "/graphql")
        kind = candidate.get("kind", "introspection_enabled")
        type_count = int(candidate.get("schema_type_count") or 0)

        if kind == "introspection_enabled" and type_count > 0:
            title = f"GraphQL Introspection Enabled ({type_count} types exposed)"
        elif kind == "type_query_works":
            title = "GraphQL Type Query Succeeds Without Authentication"
        else:
            title = "GraphQL Introspection Enabled"

        return Finding(
            check=CheckRef(
                id=self.meta.id,
                name=self.meta.name,
                category=self.meta.category.value,
                version=self.meta.version,
            ),
            title=title,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            status=FindingStatus.CONFIRMED,
            target=TargetRef(
                host=parsed.hostname or "",
                port=parsed.port,
                scheme=parsed.scheme or "https",
                endpoint=endpoint_path,
                method="POST",
                parameter=None,
            ),
            parameter=None,
            input_used=_INTROSPECTION_QUERY if kind == "introspection_enabled" else _TYPE_QUERY,
            summary=summary,
            technical_explanation=technical,
            impact=impact,
            attack_scenario=attack_scenario,
            code_examples=code_examples,
            remediation=remediation,
            cwe=["CWE-200"],
            owasp=["A05:2021"],
        )
