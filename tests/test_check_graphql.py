"""Tests for GraphQLCheck — including SAFETY assertions on the canned probes."""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from redveil.checks.graphql import (
    _GRAPHQL_PATHS,
    _INTROSPECTION_QUERY,
    _TYPE_QUERY,
    GraphQLCheck,
    _query_depth,
)
from redveil.http.response import Response
from redveil.plugins.base import CheckDependencies

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resp(body: str = "", status: int = 200, headers: dict | None = None):
    return Response(
        request_id="r1",
        status_code=status,
        headers=headers or {"content-type": "application/json"},
        body=body,
        elapsed_ms=10.0,
    )


def _bind(check, side_effects, active: bool = True, ack: bool = True):
    mock_http = MagicMock()
    mock_http._scope = MagicMock()
    cfg = MagicMock()
    cfg.target.base_url = "https://example.com"
    cfg.authorization.active_testing = active
    cfg.authorization.acknowledged_safety_terms = ack
    mock_http.send = AsyncMock(side_effect=side_effects)
    deps = CheckDependencies(
        http=mock_http,
        scope=mock_http._scope,
        config=cfg,
        context=MagicMock(),
    )
    check.bind(deps)
    return mock_http


def _introspection_enabled_body(type_count: int = 5) -> str:
    return json.dumps({
        "data": {
            "__schema": {
                "types": [{"name": f"Type{i}"} for i in range(type_count)],
            }
        }
    })


def _introspection_disabled_body() -> str:
    # Standard GraphQL "introspection not allowed" error envelope.
    return json.dumps({
        "errors": [{"message": "GraphQL introspection is not allowed"}],
        "data": None,
    })


def _type_query_success_body() -> str:
    return json.dumps({
        "data": {
            "__type": {"name": "User"},
        }
    })


def _extract_inner_selection(query: str) -> str:
    """Return the inner-most selection set body of a GraphQL query string.

    For ``{ __type(name: "User") { name } }`` this returns ``"name"``.
    Raises if no nested selection set is found.
    """
    s = query.strip()
    depth = 0
    start = -1
    end = -1
    for i, ch in enumerate(s):
        if ch == "{":
            if depth == 1:
                start = i + 1
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 1 and start >= 0:
                end = i
                break
    if start < 0 or end < 0:
        raise AssertionError(f"no nested selection set found in {query!r}")
    return s[start:end].strip()


# ---------------------------------------------------------------------------
# Authorization gates
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_active_required():
    check = GraphQLCheck()
    _bind(check, [], active=False)
    cands = await check.discover(MagicMock())
    assert cands == []


@pytest.mark.asyncio
async def test_acknowledgement_required():
    check = GraphQLCheck()
    _bind(check, [], active=True, ack=False)
    cands = await check.discover(MagicMock())
    assert cands == []


# ---------------------------------------------------------------------------
# Behavior
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_introspection_disabled_no_finding():
    check = GraphQLCheck()
    err = _resp(body=_introspection_disabled_body())
    # Each endpoint: introspection probe + type probe. 2 responses per path.
    side_effects = [err] * (len(_GRAPHQL_PATHS) * 2)
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    assert cands == []


@pytest.mark.asyncio
async def test_introspection_enabled_detected():
    check = GraphQLCheck()
    hit = _resp(body=_introspection_enabled_body(type_count=8))
    # First endpoint matches, so we break early after one introspection OK.
    side_effects = [hit]
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    assert len(cands) == 1
    c = cands[0]
    assert c["kind"] == "introspection_enabled"
    assert c["schema_type_count"] == 8
    assert c["method"] == "POST"


@pytest.mark.asyncio
async def test_type_query_works():
    check = GraphQLCheck()
    err = _resp(body=_introspection_disabled_body())
    type_ok = _resp(body=_type_query_success_body())
    # Per path: introspection probe first, then type probe.
    # We want the type probe to succeed for one endpoint, so pair them.
    side_effects = []
    for i in range(len(_GRAPHQL_PATHS)):
        if i == 0:
            # introspection disabled, then type query works
            side_effects += [err, type_ok]
        else:
            side_effects += [err, err]
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    assert len(cands) == 1
    assert cands[0]["kind"] == "type_query_works"


@pytest.mark.asyncio
async def test_no_graphql_endpoint():
    check = GraphQLCheck()
    not_found = _resp(body="not found", status=404, headers={"content-type": "text/plain"})
    # Each path: introspection 404, type-query 404
    side_effects = [not_found] * (len(_GRAPHQL_PATHS) * 2)
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    assert cands == []


@pytest.mark.asyncio
async def test_validate_confirmed():
    check = GraphQLCheck()
    candidate = {
        "endpoint": "/graphql",
        "method": "POST",
        "kind": "introspection_enabled",
        "schema_type_count": 12,
    }
    result = await check.validate(MagicMock(), candidate)
    assert result.outcome.value == "confirmed"
    assert result.confidence == "high"

    candidate_type = {
        "endpoint": "/graphql",
        "method": "POST",
        "kind": "type_query_works",
        "schema_type_count": 0,
    }
    result2 = await check.validate(MagicMock(), candidate_type)
    assert result2.outcome.value == "confirmed"


@pytest.mark.asyncio
async def test_validate_false_positive_when_no_schema():
    check = GraphQLCheck()
    candidate = {"endpoint": "/graphql", "method": "POST", "kind": "unknown"}
    result = await check.validate(MagicMock(), candidate)
    assert result.outcome.value == "false_positive"


@pytest.mark.asyncio
async def test_assess_produces_finding():
    check = GraphQLCheck()
    _bind(check, [_resp()])
    candidate = {
        "endpoint": "/graphql",
        "method": "POST",
        "kind": "introspection_enabled",
        "schema_type_count": 12,
        "request": MagicMock(url="https://example.com/graphql"),
        "response": MagicMock(),
    }
    f = await check.assess(candidate)
    assert f is not None
    assert f.severity.value == "medium"
    assert "CWE-200" in f.cwe
    assert "A05:2021" in f.owasp
    assert f.status.value == "confirmed"
    assert "Introspection" in f.title


# ---------------------------------------------------------------------------
# SAFETY: assertions on the canned probes
# ---------------------------------------------------------------------------


def test_safety_no_deep_queries():
    """Canned queries must be depth 1 — no nested selection sets."""
    for q, label in [(_INTROSPECTION_QUERY, "INTROSPECTION"), (_TYPE_QUERY, "TYPE")]:
        depth = _query_depth(q)
        assert depth == 1, f"{label}_QUERY has depth {depth} (must be 1)"


def test_safety_no_user_data_extraction():
    """Canned queries must NEVER request user data fields.

    Forbidden anywhere in the query: obvious sensitive field names. The
    introspection probe should never reference user data fields; the type
    probe is allowed to mention "User" only as a *type name argument*.
    """
    forbidden_field_names = [
        "password", "passwd", "pwd",
        "ssn", "socialSecurityNumber",
        "email",
        "phone", "phoneNumber",
        "creditCard", "cardNumber",
        "apiKey", "api_key", "secret", "token",
        "balance", "internalBalance",
        "address", "street",
        "sessionToken", "sessionId",
    ]
    # The introspection probe is a literal `{ __schema { types { name } } }`
    # — no user fields at all.
    for bad in forbidden_field_names:
        assert bad not in _INTROSPECTION_QUERY, (
            f"INTROSPECTION_QUERY references forbidden field {bad!r}"
        )
        assert bad not in _TYPE_QUERY, (
            f"TYPE_QUERY references forbidden field {bad!r}"
        )

    # The TYPE_QUERY targets "User" only as a type-name argument. Its inner
    # selection set must request only `name` (no user-data fields).
    assert '"User"' in _TYPE_QUERY or "'User'" in _TYPE_QUERY, (
        "TYPE_QUERY should still target the 'User' type"
    )
    inner = _extract_inner_selection(_TYPE_QUERY)
    assert inner == "name", (
        f"TYPE_QUERY inner selection must be exactly `name`, got {inner!r}"
    )


def test_safety_introspection_query_is_canonical():
    """The introspection query must be the well-known canonical probe.

    Whitespace and argument formatting can vary, but the field selections
    must be exactly `__schema { types { name } }`.
    """
    normalized = _INTROSPECTION_QUERY.replace(" ", "")
    assert normalized == "{__schema{types{name}}}", (
        f"INTROSPECTION_QUERY must be {{ __schema {{ types {{ name }} }} }}; "
        f"got {normalized!r}"
    )


def test_safety_module_queries_are_immutable_strings():
    """Canned queries should be plain strings (not templates) so they cannot
    be widened by accidental f-string interpolation elsewhere."""
    assert isinstance(_INTROSPECTION_QUERY, str)
    assert isinstance(_TYPE_QUERY, str)
    # No placeholder syntax that suggests dynamic interpolation.
    assert "{" not in _INTROSPECTION_QUERY.replace("{ __schema { types { name } } }", "")
    assert "{" not in _TYPE_QUERY.replace('{ __type(name: "User") { name } }', "")


def test_safety_introspection_query_does_not_request_fields():
    """The introspection query must NOT request the `fields` sub-selection
    that would leak every field of every type. The depth-1 probe is bounded
    to just type names."""
    assert "fields" not in _INTROSPECTION_QUERY, (
        "INTROSPECTION_QUERY must not request `fields` — that would leak "
        "every field of every type"
    )
    assert "mutations" not in _INTROSPECTION_QUERY
    assert "subscriptionType" not in _INTROSPECTION_QUERY
    assert "queryType" not in _INTROSPECTION_QUERY
    assert "directives" not in _INTROSPECTION_QUERY


def test_safety_endpoint_paths_do_not_target_data():
    """The probed endpoint paths must not include user-data shaped paths."""
    forbidden_paths = [
        "/users", "/accounts", "/admin", "/api/users",
        "/api/accounts", "/api/admin",
    ]
    for path in _GRAPHQL_PATHS:
        for bad in forbidden_paths:
            assert bad not in path, (
                f"endpoint path {path!r} looks like a user-data endpoint "
                f"(matches {bad!r})"
            )
