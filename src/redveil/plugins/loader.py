"""Dynamic discovery of check plugins.

Two discovery paths are supported:

* Python entry points under the group ``redveil.checks`` — the standard way
  third-party packages register checks via ``pyproject.toml``.
* Module imports by dotted path — used for tests and in-repo bundles.

Both paths return lists of :class:`~redveil.plugins.base.Check` instances;
duplicates are handled by the registry, not here.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import logging

from redveil.plugins.base import Check
from redveil.plugins.registry import DuplicatePluginError, Registry

log = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "redveil.checks"


def load_from_entry_points() -> list[Check]:
    """Discover all installed redveil check plugins via Python entry points.

    Third-party packages can register checks by declaring entry points in
    their pyproject.toml under [project.entry-points."redveil.checks"].
    """
    found: list[Check] = []
    try:
        eps = importlib.metadata.entry_points()
        if hasattr(eps, "select"):
            candidates = eps.select(group=ENTRY_POINT_GROUP)
        else:
            candidates = eps.get(ENTRY_POINT_GROUP, [])
    except Exception as e:
        log.warning("entry-point discovery failed: %s", e)
        return found

    for ep in candidates:
        try:
            obj = ep.load()
            instance = obj() if isinstance(obj, type) else obj
            if not isinstance(instance, Check):
                log.warning("entry point %s did not yield a Check instance", ep.name)
                continue
            found.append(instance)
        except Exception as e:
            log.warning("failed to load entry point %s: %s", ep.name, e)
    return found


def load_from_module(module_path: str) -> list[Check]:
    """Import a module by dotted path and harvest all Check subclasses
    defined in it."""
    mod = importlib.import_module(module_path)
    found: list[Check] = []
    for attr_name in dir(mod):
        attr = getattr(mod, attr_name)
        if (
            isinstance(attr, type)
            and issubclass(attr, Check)
            and attr is not Check
            and getattr(attr, "meta", None) is not None
        ):
            try:
                found.append(attr())
            except Exception as e:
                log.warning("failed to instantiate %s: %s", attr_name, e)
    return found


def build_default_registry(
    extra_modules: list[str] | None = None,
) -> Registry:
    """Build a registry with all entry-point plugins plus any explicit
    extra module paths to scan."""
    reg = Registry()
    for c in load_from_entry_points():
        try:
            reg.register(c)
        except DuplicatePluginError:
            log.warning("duplicate plugin: %s", c.id)
    for m in extra_modules or []:
        for c in load_from_module(m):
            try:
                reg.register(c)
            except DuplicatePluginError:
                log.warning("duplicate plugin: %s", c.id)
    return reg
