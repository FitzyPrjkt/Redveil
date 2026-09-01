"""In-memory registry of check plugins.

The registry is the single source of truth for what gets executed. Plugins
are added manually (register()) or discovered via the loader. The orchestrator
iterates the registry to plan its execution graph.

The registry is intentionally simple — it does not own execution state, only
identity and metadata. The orchestrator wires up dependencies and lifecycle.
"""

from __future__ import annotations

from collections.abc import Iterable

from redveil.plugins.base import Check, CheckCategory


class DuplicatePluginError(Exception):
    """Raised when a plugin ID is registered twice."""
    pass


class Registry:
    """In-memory registry of check plugins.

    Plugins are registered manually (register()) or discovered via the loader.
    The registry is the single source of truth for what gets executed.
    """

    def __init__(self) -> None:
        self._checks: dict[str, Check] = {}

    def register(self, check: Check) -> None:
        if check.id in self._checks:
            raise DuplicatePluginError(f"plugin {check.id!r} already registered")
        self._checks[check.id] = check

    def unregister(self, check_id: str) -> None:
        self._checks.pop(check_id, None)

    def get(self, check_id: str) -> Check:
        if check_id not in self._checks:
            raise KeyError(f"plugin {check_id!r} not found")
        return self._checks[check_id]

    def all(self) -> list[Check]:
        return list(self._checks.values())

    def by_category(self, category: CheckCategory) -> list[Check]:
        return [c for c in self._checks.values() if c.category == category]

    def __len__(self) -> int:
        return len(self._checks)

    def __contains__(self, check_id: object) -> bool:
        return check_id in self._checks

    def extend(self, checks: Iterable[Check]) -> None:
        for c in checks:
            self.register(c)
