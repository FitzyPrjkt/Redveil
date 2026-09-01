from __future__ import annotations

from redveil.findings.finding import Finding


class FindingDeduplicator:
    """Deduplicate findings by fingerprint. Findings with the same fingerprint
    are merged into one with combined evidence_ids. Findings without a
    fingerprint are added individually (no dedup possible)."""

    def __init__(self) -> None:
        self._by_fingerprint: dict[str, Finding] = {}
        self._no_fingerprint: list[Finding] = []

    def add(self, finding: Finding) -> Finding:
        if not finding.fingerprint:
            self._no_fingerprint.append(finding)
            return finding
        existing = self._by_fingerprint.get(finding.fingerprint)
        if existing is None:
            self._by_fingerprint[finding.fingerprint] = finding
            return finding
        # Merge evidence_ids
        merged_ids = list(set(existing.evidence_ids) | set(finding.evidence_ids))
        merged = existing.model_copy(update={"evidence_ids": merged_ids})
        self._by_fingerprint[finding.fingerprint] = merged
        return merged

    def all(self) -> list[Finding]:
        return list(self._by_fingerprint.values()) + list(self._no_fingerprint)

    def __len__(self) -> int:
        return len(self._by_fingerprint) + len(self._no_fingerprint)

    def clear(self) -> None:
        self._by_fingerprint.clear()
        self._no_fingerprint.clear()
