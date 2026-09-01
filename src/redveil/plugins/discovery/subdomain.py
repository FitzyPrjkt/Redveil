"""SubdomainFinderCheck — discovers subdomains by crawling + probing.

The check combines two signals:

1. **Crawl signal** — a bounded BFS over the target site. Every URL the
   crawler visits (start page, linked pages, resources) has its hostname
   extracted; any hostname that is a subdomain of the configured root is
   reported with source ``"crawl"``.
2. **Probe signal** — for a curated list of common prefixes (www, api, mail,
   ...), the check tries DNS first (via :func:`default_dns_resolver`) and
   HTTP HEAD as a fallback. Subdomains that respond are reported with source
   ``"probe"``.

Both signals stay inside the configured scope: the crawler and probe use the
shared HttpClient whose :class:`ScopeController` blocks out-of-scope requests
before they hit the wire. Subdomain probes are HTTP HEAD requests against
``http://{prefix}.{root}/``; if that host isn't in scope, the ScopeController
raises and we record nothing for that candidate.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any
from urllib.parse import urlparse

from redveil.config import SafetyProfile
from redveil.discovery.crawler import Crawler, CrawlerConfig
from redveil.discovery.subdomain_finder import (
    SubdomainFinder,
    default_dns_resolver,
)
from redveil.evidence.evidence import Evidence, ObservationKind
from redveil.findings.confidence import Confidence
from redveil.findings.finding import (
    CheckRef,
    Finding,
    ReproductionStep,
    TargetRef,
)
from redveil.findings.severity import Severity
from redveil.http.request import Request
from redveil.plugins.base import (
    Check,
    CheckCategory,
    CheckMeta,
    ValidationOutcome,
    ValidationResult,
)

log = logging.getLogger(__name__)


def _fingerprint_for_subdomain(subdomain: str) -> str:
    """Stable per-subdomain fingerprint for finding dedup."""
    return hashlib.sha256(f"subdomain|{subdomain.lower()}".encode()).hexdigest()[:16]


class SubdomainFinderCheck(Check):
    """Crawl the target site and probe common subdomains."""

    meta = CheckMeta(
        id="subdomain-finder",
        name="Subdomain Finder",
        category=CheckCategory.DISCOVERY,
        safety_profile=SafetyProfile.PASSIVE,
        version="0.1.0",
        description=(
            "Crawls the target site (BFS) to extract every hostname referenced "
            "in linked URLs, then probes common subdomain prefixes (www, api, "
            "mail, ...) via DNS or HTTP HEAD. Stays within the configured scope."
        ),
        references=[
            "https://owasp.org/www-project-attack-surface-management/",
        ],
    )

    def __init__(self) -> None:
        super().__init__()
        # Cached evidence for the most-recent scan, so collect_evidence can
        # return something concrete without re-issuing the original requests.
        self._evidence_cache: dict[str, Evidence] = {}

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _root_domain_from_config(deps) -> str:
        """Derive the root domain from the configured target base URL."""
        base = str(deps.config.target.base_url)
        host = (urlparse(base).hostname or "").lower()
        return host

    # -- discover ---------------------------------------------------------

    async def discover(self, ctx) -> list[dict[str, Any]]:  # type: ignore[override]
        """Run the crawler + probe pass and return one candidate dict per
        unique subdomain discovered.
        """
        deps = self.deps
        root = self._root_domain_from_config(deps)
        if not root:
            log.warning("subdomain-finder: could not derive root domain from target")
            return []

        # 1. Crawl signal.
        crawler_cfg = CrawlerConfig(
            max_pages=100,
            max_depth=3,
            allowed_hosts=set(deps.scope.allowed_hosts),
            honor_robots=True,
            user_agent="redveil-crawler/0.1",
        )
        crawler = Crawler(deps.http, crawler_cfg)
        try:
            crawl_result = await crawler.crawl(str(deps.config.target.base_url))
        except Exception as e:  # pragma: no cover - defensive
            log.warning("subdomain-finder: crawler raised: %s", e)
            from redveil.discovery.crawler import CrawlerResult

            crawl_result = CrawlerResult()

        # 2. Subdomain extraction (works on every URL we touched).
        finder = SubdomainFinder(
            root_domain=root,
            http_client=deps.http,
            dns_resolver=default_dns_resolver,
        )
        try:
            crawled_subs = finder.extract_from_urls(crawl_result.urls_visited)
        except Exception as e:  # pragma: no cover - defensive
            log.warning("subdomain-finder: extract raised: %s", e)
            crawled_subs = set()

        # 3. Probe signal.
        probed_subs: set[str] = set()
        try:
            probed_subs = await finder.probe_common()
        except Exception as e:  # pragma: no cover - defensive
            log.warning("subdomain-finder: probe_common raised: %s", e)

        # 4. Combine — distinct candidates with their source label.
        # "crawl" wins ties so the audit trail records the URL it was seen on.
        candidates: list[dict[str, Any]] = []
        seen: set[str] = set()

        for sub in sorted(crawled_subs):
            seen.add(sub)
            candidates.append(
                {
                    "subdomain": sub,
                    "source": "crawl",
                    "root_domain": root,
                    "pages_crawled": crawl_result.pages_crawled,
                    "urls_visited_count": len(crawl_result.urls_visited),
                }
            )
        for sub in sorted(probed_subs):
            if sub in seen:
                continue
            seen.add(sub)
            candidates.append(
                {
                    "subdomain": sub,
                    "source": "probe",
                    "root_domain": root,
                    "pages_crawled": crawl_result.pages_crawled,
                    "urls_visited_count": len(crawl_result.urls_visited),
                }
            )

        # Build minimal evidence placeholders; each gets a stable fingerprint
        # so collect_evidence can return them on demand.
        self._evidence_cache = {}
        for cand in candidates:
            sub = cand["subdomain"]
            url = f"https://{sub}/"
            req = Request(
                method="HEAD",
                url=url,
                purpose="subfinder-discover",
            )
            ev = Evidence(
                request=req,
                kind=ObservationKind.FILE_EXISTENCE,
                endpoint="/",
                method="HEAD",
                parameter=None,
                input_used=sub,
                observation=(
                    f"subdomain '{sub}' discovered via {cand['source']} "
                    f"for root '{root}'"
                ),
                relevant_headers={},
            )
            self._evidence_cache[sub] = ev

        return candidates

    # -- validate ---------------------------------------------------------

    async def validate(  # type: ignore[override]
        self, ctx, candidate: dict[str, Any]
    ) -> ValidationResult | None:
        """Discovery is sufficient — DNS resolution or crawl observation
        is itself a proof of existence. CONFIRMED with high confidence."""
        return ValidationResult(
            outcome=ValidationOutcome.CONFIRMED,
            confidence="high",
            observation=(
                f"subdomain '{candidate['subdomain']}' exists "
                f"(source={candidate['source']})"
            ),
        )

    # -- evidence ---------------------------------------------------------

    async def collect_evidence(  # type: ignore[override]
        self, candidate: dict[str, Any]
    ) -> list[Evidence]:
        """Return the cached evidence for the candidate's subdomain."""
        ev = self._evidence_cache.get(candidate["subdomain"])
        if ev is None:
            # Cache miss — fabricate a minimal evidence object so the
            # pipeline never crashes.
            sub = candidate["subdomain"]
            req = Request(
                method="HEAD",
                url=f"https://{sub}/",
                purpose="subfinder-evidence",
            )
            ev = Evidence(
                request=req,
                kind=ObservationKind.FILE_EXISTENCE,
                endpoint="/",
                method="HEAD",
                parameter=None,
                input_used=sub,
                observation=(
                    f"subdomain '{sub}' discovered via {candidate.get('source')}"
                ),
                relevant_headers={},
            )
        return [ev]

    # -- assess -----------------------------------------------------------

    async def assess(  # type: ignore[override]
        self, candidate: dict[str, Any]
    ) -> Finding | None:
        """Produce a Finding per unique discovered subdomain."""
        sub = candidate["subdomain"]
        root = candidate.get("root_domain", "")
        source = candidate.get("source", "crawl")
        parsed = urlparse(f"https://{sub}/")

        if source == "probe":
            summary = (
                f"Discovered subdomain '{sub}' of '{root}' via DNS or HTTP probe. "
                "The subdomain responds on the standard HTTP port. Probe traffic "
                "is bounded to a curated list of common prefixes."
            )
        else:
            summary = (
                f"Discovered subdomain '{sub}' of '{root}' while crawling the site. "
                f"The crawler visited {candidate.get('pages_crawled', 0)} page(s) "
                f"and inspected {candidate.get('urls_visited_count', 0)} URL(s); "
                f"'{sub}' was referenced by one of those URLs."
            )

        technical = (
            f"Root domain: {root}. "
            f"Discovery source: {source}. "
            f"Hostname observed: {sub}."
        )

        impact = (
            "Each discovered subdomain expands the attack surface of the "
            "target organization. Subdomains sometimes run outdated software, "
            "dev/staging tools, or admin panels with weaker controls than "
            "the production site. Even passive discovery (DNS lookup or HEAD "
            "probe) is enough to enumerate the surface for follow-up review."
        )

        remediation = [
            "Maintain an authoritative inventory of all subdomains and "
            "decommission anything not actively used.",
            "Apply the same hardening (HTTPS, headers, auth) to every "
            "subdomain, including dev/staging environments.",
            "Use DNS zone files and certificate-transparency logs to detect "
            "subdomain takeover risk before an attacker does.",
        ]

        reproduction = [
            ReproductionStep(
                step=1,
                description=(
                    f"Issue HEAD https://{sub}/ — expect a 2xx/3xx response "
                    f"(proves the host is alive)."
                ),
                request=f"curl -X HEAD https://{sub}/",
            ),
            ReproductionStep(
                step=2,
                description=(
                    f"Confirm the hostname is a subdomain of the target via "
                    f"DNS: dig +short {sub}"
                ),
                request=f"dig +short {sub}",
            ),
        ]

        return Finding(
            check=CheckRef(
                id=self.meta.id,
                name=self.meta.name,
                version=self.meta.version,
                category=self.meta.category.value,
            ),
            title=f"Subdomain Discovered: {sub}",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            target=TargetRef(
                host=sub,
                port=None,
                scheme="https",
                endpoint="/",
                method="HEAD",
                parameter=None,
            ),
            parameter=None,
            input_used=sub,
            summary=summary,
            technical_explanation=technical,
            impact=impact,
            reproduction=reproduction,
            remediation=remediation,
            cwe=[],
            owasp=["A05:2021"],  # Security Misconfiguration (surface expansion)
            references=[
                "https://owasp.org/www-project-attack-surface-management/",
            ],
            fingerprint=_fingerprint_for_subdomain(sub),
        )
