# redveil Architecture

## 1. Overview

redveil is a defensive web security assessment framework that runs an
auditable discover -> detect -> validate -> evidence -> report pipeline
against a target web application. Every outbound HTTP request is gated by a
single `ScopeController`, every component reports progress through an
in-process async `EventBus`, and every vulnerability check is a pluggable
`Check` subclass wired up through dependency injection so that scope and
rate-limit policy cannot be bypassed by construction. Phase 1 ships the
pipeline skeleton: configuration, scope/rate-limit enforcement, plugin
discovery, event bus, lifecycle state machine, orchestrator, and CLI. The
finding model, evidence store, validators, and report renderers are
stubbed for Phase 2+.

## 2. Layered Architecture

```
                                +-----------------------+
                                |        CLI            |   redveil scan / check / list-checks / findings / report
                                |    (cli.py, Typer)    |
                                +-----------+-----------+
                                            |
                                            v
                                +-----------+-----------+
                                |     Orchestrator      |   pipeline: discovery -> checking -> validating -> reporting
                                |  (core/orchestrator)  |   drives ScanState transitions, emits events
                                +-----------+-----------+
                                            |
                +---------------------------+---------------------------+
                |                           |                           |
                v                           v                           v
        +-------+-------+          +--------+-------+          +--------+-------+
        |   Plugins     |          |  EventBus      |          | RichRenderer   |
        | (plugins/base)|  subs    | (core/event_   |  subs    | (core/renderer)|  colored console lines
        | + registry,   | <------> |   bus.py)      | <------> |  passive sub.  |
        |   loader)     |          |  async pub/sub |          |                |
        +-------+-------+          +----------------+          +----------------+
                |
                | receives CheckDependencies(http, scope, config, ctx)
                v
        +-------+-------+          +----------------+
        |  HttpClient   |  gate    | ScopeController|   host allowlist, path glob, exclude list,
        | (http/client) | -------->| (core/scope)   |   destructive-path heuristics,
        |  async +      |          |                |   redirect-chain revalidation
        |  rate-limit   |          +-------+--------+
        |  + redirects  |                  |
        +-------+-------+                  | (also exposed via deps.scope)
                |                          |
                |     +--------------------+
                |     |
                v     v
        +-------+-------+        +----------------+        +----------------------+
        |  TokenBucket  |        |   httpx        | -----> |      Network         |
        | (rate_limit)  |        | AsyncClient    |        |  (in-scope hosts)    |
        +---------------+        | follow_redirects|       |                      |
                                 | =False (manual) |        +----------------------+
                                 +----------------+

        Sidecar: AuthProvider (http/session.py) — AnonymousAuth / CookieAuth /
                  BearerAuth / BasicAuth / CustomHeaderAuth applied inside
                  HttpClient._do_send() before each request.

        Sidecar: ScanContext (core/lifecycle) — owned by Orchestrator; tracks
                  state machine + accumulated findings. Plugins never transition
                  it directly; only Orchestrator does.
```

## 3. Module Map

| Package / Module                          | Purpose                                                                 |
| ----------------------------------------- | ----------------------------------------------------------------------- |
| `redveil.config`                           | Pydantic v2 models: `RedVeilConfig`, `TargetConfig`, `ScopeConfig`, `LimitsConfig`, `AuthorizationConfig`, `AuthConfig`, `ReportingConfig`, enums `SafetyProfile`/`AuthMethod`. YAML loader, env override (`REDVEIL_*`). |
| `redveil.cli`                              | Typer CLI (`scan`, `check`, `list-checks`, `findings`, `report`). Thin glue; delegates to `Orchestrator`. |
| `redveil.core.event_bus`                   | `EventBus` async pub/sub. `Event` dataclass, `EventType` enum, subscribers called sequentially in registration order. |
| `redveil.core.lifecycle`                   | `ScanState` enum, `assert_transition()`, `ScanContext` (target, run_id, state, findings, metadata), `InvalidStateTransition`. |
| `redveil.core.orchestrator`                | `Orchestrator` + `OrchestratorDeps`. Runs the pipeline, drives state, emits events, calls `Check.discover()`/`validate()`/`assess()`. |
| `redveil.core.renderer`                    | `RichRenderer` — passive subscriber that prints timestamped, color-coded lines to a `rich.Console`. |
| `redveil.core.scope`                       | `ScopeController`, `ScopeDecision` (frozen), `ScopeViolation`. Host/path/method gates, destructive-pattern heuristics, redirect-chain check. |
| `redveil.http.client`                      | `HttpClient` — async context-manager HTTP transport. Calls `ScopeController.check()` before every send, enforces `LimitsConfig.max_requests`, runs through `TokenBucket`, manually follows redirects and re-checks each hop. The only network egress. |
| `redveil.http.request`                     | `Request` Pydantic model. `to_curl()` produces a reproducible command with secret redaction. |
| `redveil.http.response`                    | `Response` Pydantic model. `body_sha256` and `body_length` are `@computed_field`s for evidence fingerprinting. |
| `redveil.http.session`                     | `AuthProvider` ABC + 5 implementations (`AnonymousAuth`, `CookieAuth`, `BearerAuth`, `BasicAuth`, `CustomHeaderAuth`) and `build_auth_provider` factory. |
| `redveil.http.rate_limit`                  | `TokenBucket` async rate limiter. Lock-based, with wait outside the lock to avoid head-of-line blocking. |
| `redveil.plugins.base`                     | `CheckCategory` enum, `CheckMeta`, `CheckDependencies` dataclass, `Check` ABC with `discover/validate/collect_evidence/assess`. |
| `redveil.plugins.registry`                 | In-memory `Registry` of `Check` instances, with `register/unregister/get/all/by_category/extend`. `DuplicatePluginError`. |
| `redveil.plugins.loader`                   | `load_from_entry_points()` (group `redveil.checks`), `load_from_module(path)`, `build_default_registry()`. |
| `redveil.discovery` (Phase 2+)             | Stub — crawling / endpoint enumeration. |
| `redveil.checks` (Phase 3+)                | Stub — built-in check implementations. |
| `redveil.validation` (Phase 2+)            | Stub — safe-in-place validators and PoC executors. |
| `redveil.evidence` (Phase 2+)              | Stub — request/response capture, hashing, normalization. |
| `redveil.findings` (Phase 2+)              | Stub — finding model, severity, deduplication. |
| `redveil.reporting` (Phase 2+)             | Stub — HTML/Markdown/JSON renderers. |

## 4. Request Lifecycle

A single outbound HTTP call goes through these stages:

1. **Construction.** Caller (plugin or orchestrator) builds a `Request`
   with `request_id`, `method`, `url`, `headers`, `cookies`, optional `body`.
2. **`HttpClient.send(request)`.** Caller enters the client via
   `async with HttpClient(...) as client:`.
3. **Scope gate.** `ScopeController.check(request.url, request.method)` runs.
   Order is: empty-hostset guard, hostname in allowlist, path matches an
   allowed_paths glob (if any), path not in excluded_paths, mutating method
   to destructive-pattern path. If `decision.allowed is False`,
   `ScopeViolation` is raised before any byte is put on the wire.
4. **Budget gate.** `request_count >= max_requests` raises `RuntimeError`.
5. **Rate-limit gate.** `TokenBucket.acquire()` blocks until a token is
   available. Buckets are shared by all plugins in one scan.
6. **Concurrency gate.** `asyncio.Semaphore(max_concurrent_requests)`.
7. **Auth application.** `AuthProvider.apply(headers, cookies)` mutates
   the per-request header/cookie dicts.
8. **Transport.** `httpx.AsyncClient.request(...)` with
   `follow_redirects=False`. Body decoded as UTF-8 with `errors="replace"`;
   bodies larger than `max_response_size_bytes` are truncated and
   `body_truncated=True`.
9. **Redirect handling.** A 3xx with a `Location` header is not delegated
   to httpx. `HttpClient._do_send` resolves the relative URL, appends it
   to `follow_chain`, calls `ScopeController.check_redirect_chain`, and
   recurses. 301/302/303 downgrade to GET; 307/308 preserve method and body.
   Chains longer than `ScopeConfig.max_redirects` raise `ScopeViolation`.
10. **Response assembly.** `Response` is built with `status_code`,
    `headers`, truncated `body`, 500-char `body_excerpt`, `elapsed_ms`,
    `remote_addr` (for SSRF/host-header evidence), and `redirect_chain`.
11. **Error capture.** `httpx.TimeoutException`,
    `httpx.ConnectError`, `httpx.RemoteProtocolError`, and any other
    transport exception are recorded in `Response.error`; no exception
    is re-raised.
12. **Event emission.** Phase 2+ will publish `REQUEST_SENT` /
    `RESPONSE_RECEIVED` events here; Phase 1 leaves it as a hook.

## 5. Safety Model

The framework is fail-closed at every gate.

* **`AuthorizationConfig.active_testing=true` requires
  `acknowledged_safety_terms=true`.** Enforced by
  `model_validator(mode="after")` at config load time. The CLI's `scan`
  command sets both flags together when `--active` is passed.
* **Empty `allowed_hosts` rejects everything.** `ScopeController.check`
  refuses any request if the host allowlist is empty.
* **Hostnames are case-insensitive.** `ScopeConfig._lower_hosts` and
  `ScopeController.__init__` both lowercase.
* **Subdomains do not implicitly match.** `example.com` does not allow
  `api.example.com`.
* **Path globs are opt-in.** Empty `allowed_paths` means "allow all paths
  on the host"; non-empty requires a match.
* **Exclude list beats allow list.** `excluded_paths` is evaluated after
  `allowed_paths` and always wins.
* **Destructive-path heuristics.** `ScopeController.DEFAULT_DESTRUCTIVE_PATTERNS`
  (e.g. `/delete/*`, `/wipe/*`, `/admin/production/*`) reject
  `POST/PUT/DELETE/PATCH` unless explicitly allowed. `GET/HEAD/OPTIONS`
  are always safe.
* **Redirects are re-checked per hop.** `follow_redirects=False` on the
  httpx client means we own the chain; each hop is validated against
  `ScopeController`. `max_redirects` caps the depth to prevent loop DOS.
* **Network budget.** `LimitsConfig.max_requests` is a hard cap on
  total sends per scan; once reached, further `send()` calls raise
  `RuntimeError`.
* **Rate limit.** A single `TokenBucket` shared by all plugins enforces
  `requests_per_second`. The HTTP client also caps concurrent in-flight
  requests via `asyncio.Semaphore`.
* **Response size cap.** `max_response_size_bytes` (default 5 MB) prevents
  a single response from exhausting memory.
* **TLS verification on by default.** `httpx.AsyncClient(verify=True)`.
* **No raw mode.** There is no path around `HttpClient.send`. Plugins
  cannot import httpx through the framework — they only see the
  injected `HttpClient` (see `Check.bind` caveat in Known Limitations).
* **Secret redaction.** `Request.to_curl(redact_secrets=True)` replaces
  `Authorization` and `Cookie` values with `[REDACTED]` for evidence
  exports.
* **Unique request IDs.** Every `Request` gets a fresh
  `req-<12 hex>` id; the corresponding `Response` echoes it so
  request/response pairs can be rejoined in evidence.

## 6. Plugin Contract

A `Check` is any subclass of `redveil.plugins.base.Check` with a `meta`
class attribute of type `CheckMeta`. The orchestrator wires it up with
`CheckDependencies` before any phase runs.

```
class Check(ABC):
    meta: CheckMeta                       # id, name, category, safety_profile, version, ...

    def bind(self, deps: CheckDependencies) -> None   # called by orchestrator
    @property def deps(self) -> CheckDependencies

    async def discover(ctx) -> list[Any]               # default: []
    async def validate(ctx, candidate) -> ValidationResult
    async def collect_evidence(candidate) -> list[Evidence]
    async def assess(candidate) -> Finding
```

`CheckDependencies` carries:

* `http: HttpClient` — wired transport; calls into it go through scope
  and rate-limit.
* `scope: ScopeController` — exposed so checks can pre-validate URLs
  they plan to send (e.g. for hint generation).
* `config: RedVeilConfig` — full configuration. Type-erased to `Any` to
  avoid an import cycle through `core.lifecycle`.
* `context: ScanContext` — the orchestrator-owned context; checks read
  `findings`, `metadata`, `target_name`, but never mutate `state`.

Discovery paths:

* **Entry points.** Third-party packages register checks via
  `[project.entry-points."redveil.checks"]` in `pyproject.toml`.
  `load_from_entry_points()` harvests them at startup.
* **Module import.** `load_from_module("pkg.module")` walks `dir(module)`
  and instantiates every `Check` subclass with a non-None `meta`. Used
  for in-repo bundles and tests.

Duplicates are deduped by `Registry.register`, which raises
`DuplicatePluginError` on collision.

## 7. Event Taxonomy

`EventType` is a closed `str` enum. New event types are added by
extending the enum; plugins must not invent their own.

| Event                  | Emitted by       | `data` payload (key : type)                              |
| ---------------------- | ---------------- | -------------------------------------------------------- |
| `SCAN_STARTED`         | orchestrator     | `target : str`, `run_id : str`                           |
| `DISCOVERY_STARTED`    | orchestrator     | (none)                                                   |
| `DISCOVERY_ENDED`      | orchestrator     | (none)                                                   |
| `REQUEST_SENT`         | http (Phase 2+)  | `request_id`, `url`, `method`, `purpose`                 |
| `RESPONSE_RECEIVED`    | http (Phase 2+)  | `request_id`, `status_code`, `elapsed_ms`, `redirect_chain` |
| `CHECK_STARTED`        | orchestrator     | (none; `source` = check.id)                              |
| `CHECK_ENDED`          | orchestrator     | (none; `source` = check.id)                              |
| `FINDING_DETECTED`     | orchestrator     | `candidate : str` (Phase 1 raw; Phase 2 Finding)        |
| `VALIDATION_STARTED`   | orchestrator     | `finding_id : str`                                       |
| `VALIDATION_ENDED`     | validator (Ph 2) | `finding_id`, `result : str`                             |
| `EVIDENCE_CAPTURED`    | evidence (Ph 2)  | `finding_id`, `evidence_id`, `kind`                      |
| `FINDING_CONFIRMED`    | assess (Ph 2)    | `finding_id`, `severity`, `confidence`                   |
| `REPORT_GENERATED`     | orchestrator     | `findings_count : int`                                   |
| `SCAN_FINISHED`        | orchestrator     | `findings : int`, `run_id : str` (always fires)          |
| `ERROR`                | any              | `phase : str`, `error : str`, `type : str`              |

Delivery is in-registration order. Per-type subscribers run before
catch-all subscribers. An exception in one subscriber halts delivery
to subsequent subscribers (documented in `event_bus.publish`).

## 8. Testing Strategy

Phase 1 ships with 14 test files exercising every implemented module.

* **Pure unit tests** for models and pure-Python machinery:
  `test_config.py`, `test_scope.py`, `test_lifecycle.py`,
  `test_request.py`, `test_response.py`, `test_auth.py`,
  `test_event_bus.py`, `test_rate_limit.py`,
  `test_plugin_registry.py`, `test_plugin_loader.py`.
* **Async tests with mocked transport.** `test_http_client.py` uses
  `respx` to stub httpx and covers scope enforcement,
  `max_requests`, response size cap, timeouts, connect errors,
  redirect handling (in-scope, out-of-scope, disabled, over-cap),
  and the async-context-manager lifecycle.
* **Orchestrator with fake checks.** `test_orchestrator.py` defines
  `HappyCheck` / `BrokenCheck` / `WeirdErrorCheck` and exercises every
  phase, every transition, the failure path, and the always-fires
  `SCAN_FINISHED` invariant.
* **CLI smoke tests.** `test_cli.py` uses `typer.testing.CliRunner`
  for help text, missing-plugin exit codes, missing-dir exit codes.
  Full `scan` invocation with scope file is not wired through yet.

## 9. Phase 1 Status

Shipped:

* Configuration models with strict validation (`pydantic v2`,
  `pydantic-settings`), YAML loader, env override.
* Scope controller with host allowlist, path globs, exclude list,
  destructive-path heuristics, redirect-chain validation.
* Async `HttpClient` with scope enforcement, rate limit,
  `max_requests`, response-size cap, manual redirect handling.
* `TokenBucket` async rate limiter.
* `AuthProvider` strategies + factory.
* `EventBus` async pub/sub with closed `EventType` enum.
* Lifecycle state machine (`ScanState` / `assert_transition` /
  `ScanContext`).
* `Orchestrator` with placeholder phases for all four pipeline steps.
* `Check` ABC + `CheckDependencies` + plugin loader (entry points and
  module import).
* `Registry` with dedupe.
* `RichRenderer` for colored event output.
* Typer CLI with `scan`, `check`, `list-checks`, `findings`, `report`.

Stubs (package directories present, modules empty):

* `redveil.findings`
* `redveil.evidence`
* `redveil.reporting`
* `redveil.validation`
* `redveil.discovery`
* `redveil.checks`

## 10. Known Limitations

1. **`Check.bind` is convention, not enforcement.** `bind()` just stores
   `deps` on `self._deps`. A misbehaving plugin can ignore `deps.http`
   entirely and call `import httpx` directly, or instantiate its own
   `HttpClient` with a permissive `ScopeController`. The
   `Request.to_curl` helper is also importable from anywhere. Phase 2
   should either (a) make `bind` raise on second call and run a
   self-check, or (b) wrap `httpx.AsyncClient` so it cannot be
   instantiated outside the package.

2. **`CheckDependencies.config` is `Any`.** Type-erased to dodge the
   `core.lifecycle -> plugins.base` cycle. Phase 2 should fix this with
   `from __future__ import annotations` and a string forward ref, or
   by lifting `RedVeilConfig` into a leaf module.

3. **`ScanContext.findings` is untyped.** Same reason; will be
   `list[Finding]` once `redveil.findings` exists.

4. **`Orchestrator` does not wire `HttpClient` / `ScopeController`.**
   `OrchestratorDeps` only carries `bus` and `registry`. The CLI
   constructs the orchestrator with empty deps, so no scan in Phase 1
   can actually hit the wire. Phase 2 must extend `OrchestratorDeps`
   to include the scope and http client, and have the orchestrator
   bind them into each `Check` via `CheckDependencies`.

5. **CLI does not pass `RedVeilConfig` to `Orchestrator`.**
   `cli._run_scan` discards `cfg` after constructing a few fields
   into `ScanContext`. The constructed `RedVeilConfig` (limits,
   authorization, profile) is never enforced at runtime.

6. **`Event.timestamp` uses `datetime.utcnow()`.** Deprecated in
   Python 3.12 in favor of `datetime.now(timezone.utc)`. Same
   issue in `Request.timestamp` and `Response.timestamp`.

7. **`Response.body_sha256` and `body_length` encode the body twice.**
   Each is a `@computed_field` that independently calls
   `.encode("utf-8", errors="replace")`. Cheap to fix with a cached
   `@property` and a private attribute.

8. **HttpClient `_do_send` has a `try/except Exception` broad catch.**
   Captures any unexpected transport error into `Response.error`.
   Documented but easy to hide real bugs. Phase 2 should narrow to
   httpx-specific exceptions plus a small allowlist.

10. **CLI `--scope` parsing branch leaks the default URL host**
    without feeding it through `ScopeConfig._lower_hosts`'s empty-host
    guard. The CLI builds a `ScopeConfig(allowed_hosts=[host])` from a
    raw URL hostname; if the URL is malformed, `host` may be `None` and
    `allowed_hosts` becomes `[None]`. Phase 2 should validate first.

11. **No retry / circuit-breaker policy in `HttpClient`.** A flaky
    target can burn through `max_requests` quickly. Phase 2+ should
    add a configurable retry strategy gated on safety profile.

12. **`EventType` enum is duplicated in `RichRenderer._STYLES`.** A
    new event type added to the enum will be silently unstyled
    (rendered as white). A `KeyError` on lookup would be safer.

13. **No persistence for findings.** `findings` and `report` CLI
    commands read `report_dir/findings.json`, but nothing writes that
    file yet — Phase 2 work.

## Phase 2 Recommendation

The Phase 1 architecture is sound for extending into Finding/Evidence
models and reporting. The safety rails are well-placed: the scope
controller is the only egress gate, the event bus is the only
observability channel, and the lifecycle state machine prevents
illegal pipeline jumps. The HTTP client is well-tested with respx and
covers scope, rate-limit, redirects, and response-size edge cases.

The four concrete carry-overs for Phase 2 are:

1. Extend `OrchestratorDeps` to carry the wired `HttpClient` and
   `ScopeController`, and bind them into `Check._deps` before each
   phase. This is the single highest-priority wiring gap.
2. Define the `Finding` and `Evidence` models in `redveil.findings`
   and `redveil.evidence`, then re-type `CheckDependencies.config`,
   `ScanContext.findings`, and `Check.discover()`'s return value.
3. Replace `datetime.utcnow()` with `datetime.now(timezone.utc)`
   across `event_bus.py`, `request.py`, `response.py`.
4. Tighten `Check.bind` so the dependency injection is observable,
   not just convention — either freeze the deps tuple or assert at
   `discover()` time that `self._deps.http._scope` is the
   orchestrator-injected controller.

With those four changes, the existing scaffolding supports Phase 2's
Finding + Evidence + Reporting without architectural rework.