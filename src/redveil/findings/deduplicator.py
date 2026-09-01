"""Finding deduplicator + root-cause clustering.

Two-level deduplication:
1. By `fingerprint` (per-endpoint): the same vuln on the same endpoint
2. By `root_cause` (across endpoints): the same underlying issue
   affecting many endpoints (e.g., missing CSP on /, /user, /profile)

When findings share a root_cause, they're merged into one cluster
finding. The cluster:
- keeps the highest-severity / highest-confidence original
- accumulates evidence_ids from all merged findings
- records the cluster size (number of endpoints affected)
- records the affected endpoints in a list

The report layer renders clusters as: "Missing CSP header (12 endpoints
affected)" with a list of affected endpoints.
"""
from __future__ import annotations

from redveil.findings.finding import Finding


class FindingDeduplicator:
    """Two-level dedup: per-endpoint (fingerprint) and per-root-cause.

    When `cluster_by_root_cause=True` (default), findings sharing a
    `root_cause` are merged into one cluster finding. The cluster
    carries:
      - the highest-severity member as the "head" finding
      - aggregated evidence_ids from all members
      - affected_endpoints: list of endpoint paths
      - cluster_size: number of merged findings
    """

    def __init__(self, cluster_by_root_cause: bool = True) -> None:
        self._by_fingerprint: dict[str, Finding] = {}
        self._by_root_cause: dict[str, Finding] = {}
        self._no_key: list[Finding] = []
        self._cluster_by_root_cause = cluster_by_root_cause

    def add(self, finding: Finding) -> Finding:
        if not finding.fingerprint:
            self._no_key.append(finding)
            return finding

        # 1. Try fingerprint match (per-endpoint)
        existing = self._by_fingerprint.get(finding.fingerprint)
        if existing is not None:
            merged = self._merge_two(existing, finding)
            self._by_fingerprint[finding.fingerprint] = merged
            return merged

        # 2. Try root-cause match (across endpoints) — only if both have root_cause
        if (
            self._cluster_by_root_cause
            and finding.root_cause
        ):
            cluster_head = self._by_root_cause.get(finding.root_cause)
            if cluster_head is not None:
                merged = self._merge_cluster(cluster_head, finding)
                self._by_root_cause[finding.root_cause] = merged
                # The cluster head is also indexed by fingerprint for
                # future endpoint-level dedup
                self._by_fingerprint[merged.fingerprint] = merged
                return merged

        # 3. New finding — store by fingerprint and (optionally) by root_cause
        self._by_fingerprint[finding.fingerprint] = finding
        if self._cluster_by_root_cause and finding.root_cause:
            self._by_root_cause[finding.root_cause] = finding
        return finding

    def all(self) -> list[Finding]:
        # Avoid duplicates: a finding stored under both _by_fingerprint and
        # _by_root_cause should only be returned once.
        seen_ids: set[str] = set()
        out: list[Finding] = []
        for f in list(self._by_fingerprint.values()) + self._no_key:
            if f.id not in seen_ids:
                seen_ids.add(f.id)
                out.append(f)
        return out

    def cluster_sizes(self) -> dict[str, int]:
        """Return a map of root_cause → cluster size (for reporting)."""
        return {
            rc: int(f.metadata.get("cluster_size", 1)) if hasattr(f, "metadata") else 1
            for rc, f in self._by_root_cause.items()
            if int((f.model_extra or {}).get("cluster_size", 1)) > 1
        }

    def __len__(self) -> int:
        return len(self.all())

    def clear(self) -> None:
        self._by_fingerprint.clear()
        self._by_root_cause.clear()
        self._no_key.clear()

    # -- internals --------------------------------------------------------

    def _merge_two(self, a: Finding, b: Finding) -> Finding:
        """Merge two findings with the same fingerprint (per-endpoint dedup)."""
        merged_ids = list(set(a.evidence_ids) | set(b.evidence_ids))
        # Keep the higher-severity one as the head
        head = a if a.severity.value >= b.severity.value else b
        return head.model_copy(update={"evidence_ids": merged_ids})

    def _merge_cluster(self, head: Finding, new_member: Finding) -> Finding:
        """Merge a finding into an existing root-cause cluster.

        The head keeps its identity but its evidence_ids grow. cluster_size
        increments and the new endpoint is added to affected_endpoints.
        The head's own endpoint is also recorded on first merge.
        """
        merged_evidence = list(set(head.evidence_ids) | set(new_member.evidence_ids))
        affected = list(head.affected_endpoints)

        # Seed with the head's own endpoint if not yet recorded
        if head.target.endpoint and head.target.endpoint not in affected:
            affected.append(head.target.endpoint)
        if new_member.target.endpoint and new_member.target.endpoint not in affected:
            affected.append(new_member.target.endpoint)

        # Pick the head: prefer higher severity, then higher confidence
        new_head = head
        if _severity_rank(new_member.severity) > _severity_rank(head.severity):
            new_head = new_member
        elif (_severity_rank(new_member.severity) == _severity_rank(head.severity)
              and _confidence_rank(new_member.confidence) > _confidence_rank(head.confidence)):
            new_head = new_member

        # If the head changed, use the new head's existing cluster state
        prev_size = new_head.cluster_size if new_head is head else 1

        return new_head.model_copy(update={
            "evidence_ids": merged_evidence,
            "cluster_size": prev_size + 1,
            "affected_endpoints": affected,
        })


def _severity_rank(sev) -> int:
    """Numeric rank for severity comparison (higher = worse)."""
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(sev.value, 0)


def _confidence_rank(conf) -> int:
    order = {"tentative": 0, "low": 1, "medium": 2, "high": 3, "confirmed": 4}
    return order.get(conf.value, 0)
