"""Tests for the in-memory plugin registry."""

from __future__ import annotations

import pytest

from redveil.config import SafetyProfile
from redveil.plugins.base import Check, CheckCategory, CheckMeta
from redveil.plugins.registry import DuplicatePluginError, Registry


class _StubCheck(Check):
    meta = CheckMeta(
        id="stub",
        name="Stub",
        category=CheckCategory.HEADERS,
        safety_profile=SafetyProfile.PASSIVE,
    )


class _OtherCheck(Check):
    meta = CheckMeta(
        id="other",
        name="Other",
        category=CheckCategory.TLS,
        safety_profile=SafetyProfile.PASSIVE,
    )


def test_register_adds_a_check():
    reg = Registry()
    check = _StubCheck()
    reg.register(check)
    assert len(reg) == 1
    assert reg.get("stub") is check


def test_register_duplicate_raises():
    reg = Registry()
    reg.register(_StubCheck())
    with pytest.raises(DuplicatePluginError):
        reg.register(_StubCheck())


def test_unregister_removes():
    reg = Registry()
    reg.register(_StubCheck())
    reg.unregister("stub")
    assert len(reg) == 0
    assert "stub" not in reg


def test_unregister_missing_is_noop():
    reg = Registry()
    reg.unregister("does-not-exist")  # should not raise


def test_get_returns_registered():
    reg = Registry()
    c = _StubCheck()
    reg.register(c)
    assert reg.get("stub") is c


def test_get_missing_raises():
    reg = Registry()
    with pytest.raises(KeyError):
        reg.get("missing")


def test_by_category_filters_correctly():
    reg = Registry()
    a = _StubCheck()
    b = _OtherCheck()
    reg.register(a)
    reg.register(b)
    headers = reg.by_category(CheckCategory.HEADERS)
    tls = reg.by_category(CheckCategory.TLS)
    assert headers == [a]
    assert tls == [b]


def test_all_returns_registered():
    reg = Registry()
    a = _StubCheck()
    b = _OtherCheck()
    reg.register(a)
    reg.register(b)
    assert set(reg.all()) == {a, b}


def test_extend_registers_all():
    reg = Registry()
    reg.extend([_StubCheck(), _OtherCheck()])
    assert "stub" in reg
    assert "other" in reg
    assert len(reg) == 2


def test_extend_propagates_duplicates():
    reg = Registry()
    reg.register(_StubCheck())
    with pytest.raises(DuplicatePluginError):
        reg.extend([_OtherCheck(), _StubCheck()])


def test_len_and_contains():
    reg = Registry()
    assert len(reg) == 0
    reg.register(_StubCheck())
    assert len(reg) == 1
    assert "stub" in reg
    assert "missing" not in reg
