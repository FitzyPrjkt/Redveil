"""Tests for plugin discovery via entry points and module import."""

from __future__ import annotations

from redveil.config import SafetyProfile
from redveil.plugins.base import Check, CheckCategory, CheckMeta
from redveil.plugins.loader import build_default_registry, load_from_module
from redveil.plugins.registry import Registry


# A trivial plugin module used by load_from_module tests.
class _Demo(Check):
    meta = CheckMeta(
        id="loader-demo",
        name="Loader Demo",
        category=CheckCategory.DISCLOSURE,
        safety_profile=SafetyProfile.PASSIVE,
    )


class _NoMeta(Check):
    """A Check subclass WITHOUT meta — should be skipped by loader."""
    meta = None  # type: ignore[assignment]


import sys
import types

demo_module = types.ModuleType("_redveil_test_demo_module")
demo_module.Demo = _Demo
demo_module.NoMeta = _NoMeta
sys.modules["_redveil_test_demo_module"] = demo_module


def test_load_from_module_discovers_check_subclass_with_meta():
    found = load_from_module("_redveil_test_demo_module")
    ids = [c.id for c in found]
    assert "loader-demo" in ids
    assert all(isinstance(c, Check) for c in found)


def test_load_from_module_ignores_check_without_meta():
    found = load_from_module("_redveil_test_demo_module")
    # Only Demo (which has meta) should be loaded. NoMeta is skipped.
    assert all(c.id != "" for c in found)


def test_load_from_module_ignores_base_check():
    # The base Check class itself has no .meta attribute (it's abstract);
    # it must never appear in loader output.
    base_only_module = types.ModuleType("_redveil_test_base_only")
    # Intentionally do NOT add any Check subclass to this module.
    sys.modules["_redveil_test_base_only"] = base_only_module
    found = load_from_module("_redveil_test_base_only")
    assert found == []


def test_build_default_registry_returns_registry():
    reg = build_default_registry()
    assert isinstance(reg, Registry)
