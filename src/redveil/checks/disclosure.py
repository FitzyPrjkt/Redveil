"""InfoDisclosureCheck — detects information leakage.

PASSIVE check. Inspects response headers, body patterns, and probes a list of
common debug/info endpoints. No mutation, no auth bypass.
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

# (path, kind, severity)
_DEBUG_PATHS = [
    ("/.env", "exposed_env", Severity.HIGH),
    ("/debug", "exposed_debug", Severity.HIGH),
    ("/server-status", "exposed_panel", Severity.MEDIUM),
    ("/server-info", "exposed_panel", Severity.MEDIUM),
    ("/phpinfo.php", "exposed_phpinfo", Severity.HIGH),
    ("/info.php", "exposed_phpinfo", Severity.HIGH),
    ("/api/debug", "exposed_debug_api", Severity.HIGH),
    ("/api/_debug", "exposed_debug_api", Severity.HIGH),
    ("/admin/debug", "exposed_debug", Severity.HIGH),
    ("/.git/HEAD", "exposed_vcs", Severity.HIGH),
    ("/.svn/entries", "exposed_vcs", Severity.HIGH),
    ("/config.json", "exposed_config", Severity.MEDIUM),
    ("/config.yaml", "exposed_config", Severity.MEDIUM),
    ("/swagger.json", "exposed_api_docs", Severity.LOW),
    ("/api-docs", "exposed_api_docs", Severity.LOW),
    ("/openapi.json", "exposed_api_docs", Severity.LOW),
    ("/.well-known/", "well_known", Severity.INFO),
    ("/api/source-map", "exposed_source_map", Severity.MEDIUM),
]

_VERSION_PATTERN = re.compile(r"([A-Za-z][A-Za-z0-9._-]*)/(\d+\.\d+(?:\.\d+)?)")
_STACK_TRACE_PATTERNS = [
    re.compile(r"Traceback \(most recent call last\):"),
    re.compile(r"at\s+[a-zA-Z_][\w$.]*\([\w./:$-]+\)"),  # Java stack
    re.compile(r"Exception in thread"),
    re.compile(r"Fatal error:.*on line \d+"),  # PHP
]
_DB_ERROR_PATTERNS = [
    re.compile(r"SQLSTATE\[", re.IGNORECASE),
    re.compile(r"mysql_fetch_array", re.IGNORECASE),
    re.compile(r"pg_query\(\)", re.IGNORECASE),
    re.compile(r"\bORA-\d{5}"),
    re.compile(r"SQLite/JDBCDriver"),
]
_HTML_COMMENT_PATTERN = re.compile(r"<!--(.*?)-->", re.DOTALL)
_SENSITIVE_COMMENT_KEYWORDS = ("TODO", "FIXME", "BUG", "HACK", "internal", "localhost", "127.0.0.1", "192.168.", "10.0.0.")
_BACKUP_PATHS = [
    "/index.php~", "/index.php.bak", "/.DS_Store", "/wp-config.php.bak",
    "/.htaccess.bak", "/.env.bak", "/app.py.bak", "/server.py.bak",
]


def _looks_like_version(value: str) -> tuple[str, str] | None:
    """If the value looks like 'name/version', return (name, version). Otherwise None."""
    m = _VERSION_PATTERN.search(value)
    if m:
        return (m.group(1), m.group(2))
    return None


class InfoDisclosureCheck(Check):
    meta = CheckMeta(
        id="information-disclosure",
        name="Information Disclosure Check",
        category=CheckCategory.DISCLOSURE,
        safety_profile=SafetyProfile.PASSIVE,
        description="Detects information leakage via response headers, version banners, debug endpoints, exposed source maps, error messages, and technology fingerprints.",
        references=["CWE-200", "OWASP A01:2021"],
    )

    async def discover(self, ctx) -> list[dict[str, Any]]:
        if not self.deps:
            return []
        base = str(self.deps.config.target.base_url).rstrip("/")
        candidates: list[dict[str, Any]] = []

        # 1. Homepage
        try:
            home_url = join_url(base, "/")
            req_home = Request(method="GET", url=home_url, purpose="discovery")
            home_resp = await self.deps.http.send(req_home)
        except Exception:
            return candidates

        # Server / X-Powered-By
        for header_name, sev in [("server", Severity.MEDIUM), ("x-powered-by", Severity.LOW),
                                  ("x-aspnet-version", Severity.LOW), ("x-aspnetmvc-version", Severity.LOW)]:
            value = home_resp.headers.get(header_name) or home_resp.headers.get(header_name.title())
            if not value:
                continue
            version = _looks_like_version(value) if header_name == "server" else None
            candidates.append({
                "kind": "version_banner" if version else "info_header",
                "header": header_name,
                "value": value,
                "severity": sev,
                "response": home_resp,
                "request": req_home,
            })

        # Body patterns
        body = home_resp.body
        for pattern in _STACK_TRACE_PATTERNS:
            if pattern.search(body):
                candidates.append({
                    "kind": "stack_trace",
                    "value": pattern.search(body).group(0)[:200],
                    "severity": Severity.HIGH,
                    "response": home_resp,
                    "request": req_home,
                })
                break
        for pattern in _DB_ERROR_PATTERNS:
            if pattern.search(body):
                candidates.append({
                    "kind": "db_error",
                    "value": pattern.search(body).group(0)[:200],
                    "severity": Severity.HIGH,
                    "response": home_resp,
                    "request": req_home,
                })
                break
        for m in _HTML_COMMENT_PATTERN.finditer(body):
            comment = m.group(1)
            lower = comment.lower()
            if any(kw.lower() in lower for kw in _SENSITIVE_COMMENT_KEYWORDS):
                candidates.append({
                    "kind": "html_comment",
                    "value": comment.strip()[:200],
                    "severity": Severity.LOW,
                    "response": home_resp,
                    "request": req_home,
                })
                break

        # 2. Debug/info paths
        for path, kind, sev in _DEBUG_PATHS:
            try:
                req = Request(method="GET", url=join_url(base, path), purpose="discovery")
                resp = await self.deps.http.send(req)
            except Exception:
                continue
            if resp.status_code == 200 and len(resp.body) > 0:
                # Some "well-known" paths are normal — skip unless they look like info leak
                if kind == "well_known":
                    continue
                candidates.append({
                    "kind": kind,
                    "value": path,
                    "severity": sev,
                    "response": resp,
                    "request": req,
                })

        # 3. Backup files
        for path in _BACKUP_PATHS:
            try:
                req = Request(method="GET", url=join_url(base, path), purpose="discovery")
                resp = await self.deps.http.send(req)
            except Exception:
                continue
            if resp.status_code == 200 and len(resp.body) > 0:
                candidates.append({
                    "kind": "backup_file",
                    "value": path,
                    "severity": Severity.HIGH,
                    "response": resp,
                    "request": req,
                })

        return candidates

    async def validate(self, ctx, candidate) -> ValidationResult:
        return ValidationResult(
            outcome=ValidationOutcome.CONFIRMED,
            confidence="high",
            observation=f"info disclosure observed: {candidate['kind']}",
        )

    async def collect_evidence(self, candidate) -> list[Evidence]:
        resp = candidate.get("response")
        req = candidate.get("request")
        if not resp or not req:
            return []
        kind_map = {
            "version_banner": ObservationKind.HEADER_PRESENT,
            "info_header": ObservationKind.HEADER_PRESENT,
            "stack_trace": ObservationKind.ERROR_DISCLOSURE,
            "db_error": ObservationKind.ERROR_DISCLOSURE,
            "html_comment": ObservationKind.DISCLOSURE if hasattr(ObservationKind, "DISCLOSURE") else ObservationKind.ERROR_DISCLOSURE,
            "exposed_env": ObservationKind.FILE_EXISTENCE,
            "exposed_debug": ObservationKind.FILE_EXISTENCE,
            "exposed_panel": ObservationKind.FILE_EXISTENCE,
            "exposed_phpinfo": ObservationKind.FILE_EXISTENCE,
            "exposed_debug_api": ObservationKind.FILE_EXISTENCE,
            "exposed_vcs": ObservationKind.FILE_EXISTENCE,
            "exposed_config": ObservationKind.FILE_EXISTENCE,
            "exposed_api_docs": ObservationKind.FILE_EXISTENCE,
            "exposed_source_map": ObservationKind.FILE_EXISTENCE,
            "backup_file": ObservationKind.FILE_EXISTENCE,
        }
        return [Evidence(
            request=req,
            response=resp,
            kind=kind_map.get(candidate["kind"], ObservationKind.ERROR_DISCLOSURE),
            endpoint=req.url,
            method="GET",
            parameter=candidate.get("header") or candidate.get("value"),
            input_used=candidate.get("value", ""),
            status_code=resp.status_code,
            body_excerpt=resp.body_excerpt,
            observation=f"info disclosure: {candidate['kind']}",
        )]

    async def assess(self, candidate) -> Finding | None:
        kind = candidate["kind"]
        title_map = {
            "version_banner": f"Version Disclosure in {candidate.get('header', 'Server').title()} Header",
            "info_header": f"Information Disclosure via {candidate.get('header', 'Header').title()} Header",
            "stack_trace": "Stack Trace Disclosure in Response Body",
            "db_error": "Database Error Message Disclosure",
            "html_comment": "Sensitive Information in HTML Comment",
            "exposed_env": "Exposed Environment File (.env)",
            "exposed_debug": "Exposed Debug Endpoint",
            "exposed_panel": "Exposed Management Panel",
            "exposed_phpinfo": "Exposed PHP Info Page",
            "exposed_debug_api": "Exposed Debug API Endpoint",
            "exposed_vcs": "Exposed Version Control Metadata",
            "exposed_config": "Exposed Configuration File",
            "exposed_api_docs": "Exposed API Documentation",
            "exposed_source_map": "Exposed Source Map File",
            "backup_file": "Exposed Backup File",
        }
        # Pull rich content from the knowledge base.
        entry = get_entry(self.meta.id, kind)
        if entry:
            summary = entry["summary"]
            technical = entry["technical"]
            impact = entry["impact"]
            remediation = list(entry["remediation"])
            attack_scenario = entry["attack_scenario"]
            code_examples = dict(entry["code_examples"])
        else:
            summary = f"Information disclosure detected: {kind}."
            technical = (
                f"The target returned information that could aid an attacker: {kind} "
                f"with value '{candidate.get('value', '')[:80]}'."
            )
            impact = "Helps attackers fingerprint the technology stack and plan targeted attacks."
            remediation = ["Strip sensitive content from responses."]
            attack_scenario = None
            code_examples = {}

        base = str(self.deps.config.target.base_url)
        parsed = urlparse(base)
        # endpoint must be the path only (renderer combines scheme+host+endpoint)
        req = candidate.get("request")
        if req:
            req_parsed = urlparse(req.url)
            endpoint_path = req_parsed.path or "/"
        else:
            endpoint_path = "/"

        return Finding(
            check=CheckRef(id=self.meta.id, name=self.meta.name, category=self.meta.category.value, version=self.meta.version),
            title=title_map.get(kind, "Information Disclosure"),
            severity=candidate["severity"],
            confidence=Confidence.HIGH,
            status=FindingStatus.CONFIRMED,
            target=TargetRef(
                host=parsed.hostname or "",
                port=parsed.port,
                scheme=parsed.scheme or "https",
                endpoint=endpoint_path,
                method="GET",
            ),
            parameter=candidate.get("header") or "body",
            input_used=candidate.get("value", ""),
            summary=summary,
            technical_explanation=technical,
            impact=impact,
            attack_scenario=attack_scenario,
            code_examples=code_examples,
            remediation=remediation,
            cwe=["CWE-200"],
            owasp=["A01:2021"],
        )
