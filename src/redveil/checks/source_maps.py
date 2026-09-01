"""SourceMapCheck — detects exposed JavaScript source map files.

PASSIVE check. Parses the homepage for <script> tags, looks for inline
sourceMappingURL comments, and probes common .map paths.
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

_SCRIPT_SRC_PATTERN = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
_SOURCEMAP_URL_PATTERN = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*([^\s\'\"]+)")
_COMMON_MAP_PATHS = [
    "/static/js/main.js.map", "/app.js.map", "/bundle.js.map",
    "/assets/index.js.map", "/js/main.js.map", "/dist/bundle.js.map",
    "/build/app.js.map", "/main.js.map", "/index.js.map",
]


def _resolve_script_url(base: str, script_url: str) -> str:
    """Resolve a possibly-relative script URL against the base URL."""
    if script_url.startswith("http://") or script_url.startswith("https://"):
        return script_url
    if script_url.startswith("/"):
        return join_url(base, script_url)
    return join_url(base, "/" + script_url)


class SourceMapCheck(Check):
    meta = CheckMeta(
        id="source-map-exposure",
        name="Source Map Exposure",
        category=CheckCategory.DISCLOSURE,
        safety_profile=SafetyProfile.PASSIVE,
        description="Detects exposed JavaScript source map files (.js.map) and inline source map references.",
        references=["CWE-540", "OWASP A01:2021"],
    )

    async def discover(self, ctx) -> list[dict[str, Any]]:
        if not self.deps:
            return []
        base = str(self.deps.config.target.base_url).rstrip("/")
        candidates: list[dict[str, Any]] = []

        # 1. Parse homepage
        try:
            req = Request(method="GET", url=join_url(base, "/"), purpose="discovery")
            resp = await self.deps.http.send(req)
        except Exception:
            return candidates

        script_urls: list[str] = []
        for m in _SCRIPT_SRC_PATTERN.finditer(resp.body):
            script_urls.append(m.group(1))

        # 2. Look for inline sourceMappingURL
        for script_url in script_urls:
            # Try to fetch the script itself
            full_url = _resolve_script_url(base, script_url)
            try:
                script_req = Request(method="GET", url=full_url, purpose="discovery")
                script_resp = await self.deps.http.send(script_req)
            except Exception:
                continue
            m = _SOURCEMAP_URL_PATTERN.search(script_resp.body)
            if m:
                map_ref = m.group(1)
                candidates.append({
                    "kind": "inline_source_map_ref",
                    "script_url": script_url,
                    "map_ref": map_ref,
                    "severity": Severity.MEDIUM,
                    "response": script_resp,
                    "request": script_req,
                })

        # 3. Try to fetch .map file directly
        for script_url in script_urls:
            map_url = script_url + ".map"
            full_map_url = _resolve_script_url(base, map_url)
            try:
                map_req = Request(method="GET", url=full_map_url, purpose="discovery")
                map_resp = await self.deps.http.send(map_req)
            except Exception:
                continue
            if map_resp.status_code == 200 and map_resp.body.strip().startswith("{"):
                # Looks like a source map JSON
                candidates.append({
                    "kind": "exposed_source_map",
                    "script_url": script_url,
                    "map_url": full_map_url,
                    "severity": Severity.MEDIUM,
                    "response": map_resp,
                    "request": map_req,
                })

        # 4. Probe common paths
        for path in _COMMON_MAP_PATHS:
            try:
                req = Request(method="GET", url=join_url(base, path), purpose="discovery")
                resp = await self.deps.http.send(req)
            except Exception:
                continue
            if resp.status_code == 200 and resp.body.strip().startswith("{"):
                candidates.append({
                    "kind": "exposed_source_map",
                    "script_url": path.replace(".map", ""),
                    "map_url": path,
                    "severity": Severity.MEDIUM,
                    "response": resp,
                    "request": req,
                })

        return candidates

    async def validate(self, ctx, candidate) -> ValidationResult:
        if candidate["kind"] == "exposed_source_map":
            return ValidationResult(
                outcome=ValidationOutcome.CONFIRMED,
                confidence="high",
                observation="source map file accessible and contains valid JSON",
            )
        return ValidationResult(
            outcome=ValidationOutcome.LIKELY,
            confidence="medium",
            observation="source map reference found in script",
        )

    async def collect_evidence(self, candidate) -> list[Evidence]:
        resp = candidate.get("response")
        req = candidate.get("request")
        if not resp or not req:
            return []
        return [Evidence(
            request=req,
            response=resp,
            kind=ObservationKind.FILE_EXISTENCE,
            endpoint=candidate.get("map_url") or candidate.get("script_url", "/"),
            method="GET",
            parameter="source_map",
            input_used=candidate.get("map_ref", ""),
            status_code=resp.status_code,
            body_excerpt=resp.body_excerpt[:200],
            observation=f"source map at {candidate.get('map_url') or candidate.get('map_ref')}",
        )]

    async def assess(self, candidate) -> Finding | None:
        kind = candidate["kind"]
        if kind == "exposed_source_map":
            title = f"Exposed Source Map File: {candidate['map_url']}"
        else:
            title = f"Inline Source Map Reference: {candidate['script_url']} → {candidate['map_ref']}"

        entry = get_entry(self.meta.id, kind)
        if entry:
            summary = entry["summary"]
            technical = entry["technical"]
            impact = entry["impact"]
            remediation = list(entry["remediation"])
            attack_scenario = entry["attack_scenario"]
            code_examples = dict(entry["code_examples"])
        else:
            summary = "JavaScript source map is exposed, which can leak original source code."
            technical = "Source maps translate minified production code back to the original source."
            impact = "Leakage of source code, internal logic, and security controls."
            remediation = ["Do not deploy .map files to production."]
            attack_scenario = None
            code_examples = {}

        base = str(self.deps.config.target.base_url)
        parsed = urlparse(base)
        # endpoint must be the path only (renderer combines scheme+host+endpoint)
        raw_endpoint = candidate.get("map_url") or candidate.get("script_url", "/")
        from urllib.parse import urlparse as _up
        parsed_endpoint = _up(raw_endpoint)
        endpoint_value = parsed_endpoint.path or "/"

        return Finding(
            check=CheckRef(id=self.meta.id, name=self.meta.name, category=self.meta.category.value, version=self.meta.version),
            title=title,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH if kind == "exposed_source_map" else Confidence.MEDIUM,
            status=FindingStatus.CONFIRMED if kind == "exposed_source_map" else FindingStatus.LIKELY,
            target=TargetRef(
                host=parsed.hostname or "",
                port=parsed.port,
                scheme=parsed.scheme or "https",
                endpoint=endpoint_value,
                method="GET",
            ),
            parameter="source_map",
            input_used=candidate.get("map_ref", ""),
            summary=summary,
            technical_explanation=technical,
            impact=impact,
            attack_scenario=attack_scenario,
            code_examples=code_examples,
            remediation=remediation,
            cwe=["CWE-540"],
            owasp=["A01:2021"],
        )
