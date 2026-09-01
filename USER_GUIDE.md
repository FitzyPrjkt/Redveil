# redveil User Guide

> read the safety section (§8) before running anything. redveil is a defensive
> tool. use it only against systems you own or have written authorization to
> test. no exceptions.

## 1. What it is

redveil runs a *discover → detect → validate → evidence → report* pipeline
against a target web application. every outbound request goes through one
scope controller, every check is a plugin, every plugin gets its HTTP client
injected. plugins cannot bypass scope by construction.

use cases: bug bounty, VDP, owned apps, local labs.

use cases that are **not supported**: penetration testing without written
authorization, attacking systems you don't own, red-team engagements where
the client expects exploitation (use a real exploit framework for that).

### What redveil is NOT

- not an exploit framework. no reverse shells, no persistence, no
  credential extraction, no data destruction
- not a destructive payload toolkit. SQLi and command-injection checks
  are time-based only. they don't extract data
- not a scanner that floods targets with noise. default rate limit is 2 RPS
  tables, write files, or execute commands.
- **Not a vulnerability scanner for the public internet.** The framework
  enforces strict host allowlists and is intended for authorized assessment
  only. Out-of-scope requests are rejected before any byte hits the wire.

### Use cases

- authorized pentests with a written RoE
- bug bounty (HackerOne, Bugcrowd, Intigriti, etc.) — reproducible evidence
  helps with triage
- VDP — reporters often need clean reports without invasive payloads
- CI/staging security testing of your own apps
- local labs and CTF training

### Safety model

Every check declares its required safety profile. The runtime refuses to
execute any check that exceeds the operator's chosen profile for the current
run. The three profiles are:

- **PASSIVE** — only observation. No mutation, no payload injection. Safe to
  run against any URL the operator can read.
- **LOW_IMPACT** — safe probes. CORS preflights, HTTP method checks, harmless
  header reflection tests, OPTIONS requests. Idempotent and non-destructive.
- **ACTIVE** — invasive validation. Authenticated multi-principal tests,
  time-based blind SQL injection, OOB SSRF via the operator's callback
  domain, time-based command injection detection. Requires explicit
  authorization and acknowledgement of safety terms. Bounded by time and
  concurrency caps.

See Section 8 for the full safety and authorization discussion.

## 2. Installation

redveil targets Python 3.12 and 3.13. The recommended install path is a
fresh virtual environment:

```bash
git clone https://github.com/FitzyPrjkt/Redveil.git
cd Redveil
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
redveil --help
```

The `[dev]` extra pulls in `pytest`, `pytest-asyncio`, `respx`, `ruff`, and
`mypy` for development and testing. For runtime-only use, install the base
package: `pip install -e .`.

After install, `redveil --help` lists the available commands. The first run
will pick up the 17 built-in check plugins through the entry-point registry.

### Verifying the install

A quick sanity check that the plugin system is wired correctly:

```bash
redveil list-checks
```

You should see 17 plugins, each tagged with its safety profile. If you see
`no plugins registered yet`, the entry-point cache is stale — run
`pip install -e ".[dev]"` again.

## 3. Quickstart

The shortest path: scan a single target with default checks.

```bash
redveil scan https://example.com
```

What happens:

1. The framework builds a minimal scope for `example.com`, with the URL host
   as the sole allowed host.
2. The crawler visits the homepage and harvests links, forms, and assets.
3. All checks whose safety profile does not exceed PASSIVE run against the
   discovered surface. This includes security-headers, CORS policy, HTTP
   methods, information-disclosure, source maps, open-redirect indicator,
   and session cookie checks.
4. Each finding is written to `reports/example.com/` as both Markdown and
   JSON. A self-contained HTML report is also rendered.

Five minutes from `pip install` to a Markdown report.

For an authorized staging assessment, pass a scope file:

```bash
redveil scan https://staging.example.com --scope examples/scope.staging.yaml
```

For active testing (time-based blind probes, OOB callbacks), opt in
explicitly:

```bash
redveil scan https://staging.example.com --scope scope.yaml --profile active --active
```

The `--active` flag sets both `authorization.active_testing=true` and
`authorization.acknowledged_safety_terms=true` together.

## 4. Concepts

### 4.1 Scope configuration

The scope controller is the single egress gate for the framework. Every
outbound HTTP request is validated against the scope configuration before any
byte is put on the wire. If a redirect chain hops outside the configured
hosts, the redirect is rejected and the chain fails closed.

Key fields:

- **`target.base_url`** — the URL that will be scanned. Required.
- **`scope.allowed_hosts`** — explicit allowlist of hosts. Empty list rejects
  everything. Case-insensitive. Subdomains do not implicitly match: allowing
  `example.com` does not allow `api.example.com`.
- **`scope.allowed_paths`** — glob patterns that must match the request path.
  Empty list means "allow all paths on the allowed hosts". Examples:
  `/api/*`, `/account/*`, `/*.html`.
- **`scope.excluded_paths`** — glob patterns that always win over the allow
  list. Use this for `/logout`, payment endpoints, or destructive paths.
  Examples: `/api/v1/payments/*`, `/admin/production/*`.
- **`scope.follow_redirects`** — whether to follow 3xx redirects. When true,
  each hop in the redirect chain is re-validated against the scope.
- **`scope.max_redirects`** — maximum redirect depth before the chain is
  rejected. Defaults to 5.

The scope controller also carries destructive-path heuristics. By default,
mutating methods (`POST`, `PUT`, `DELETE`, `PATCH`) to paths matching
patterns like `/delete/*`, `/wipe/*`, or `/admin/production/*` are rejected
unless explicitly allowed. `GET`, `HEAD`, and `OPTIONS` are always safe.

### 4.2 Safety profiles

The three profiles and what they permit:

| Profile      | Allowed behavior                                                                                                  |
| ------------ | ----------------------------------------------------------------------------------------------------------------- |
| PASSIVE      | Only observation. No payload injection. Reads headers, response bodies, source maps, and cookies.                 |
| LOW_IMPACT   | Safe probes. CORS preflights, HTTP method enumeration, benign header reflection tests, OPTIONS requests.          |
| ACTIVE       | Authenticated IDOR across multiple principals, time-based blind SQLi, OOB SSRF, time-based command injection. Requires `authorization.active_testing=true` and `authorization.acknowledged_safety_terms=true`. |

Each check declares its required profile. The runtime refuses to execute any
check that exceeds the operator's chosen profile for the current run, and it
logs the rejection. The `--profile` flag sets the ceiling for the entire scan —
there is no per-check override.

### 4.3 Authentication

redveil supports five authentication strategies, configured under
`auth.method`:

- **Anonymous (default).** No credentials are sent. Use for unauthenticated
  surface mapping and unauthenticated bug bounty submissions.
- **Cookie.** Pass one or more `{name, value}` entries. Useful for session
  cookies harvested from a browser session. Alternative: `cookie_jar_path`
  pointing at a Netscape-format cookie file.
- **Bearer token.** Pass `token`. The framework adds an `Authorization:
  Bearer <token>` header to every request.
- **Basic auth.** Pass `username` and `password`. The framework adds the
  `Authorization: Basic <base64>` header.
- **Custom header.** Pass `header_name` and `header_value`. The framework
  adds the header verbatim to every request. Use this for API keys,
  signature headers, or non-standard auth schemes.

For multi-principal testing (BOLA / IDOR), populate `auth.principals` with a
list of `PrincipalConfig` entries. Each principal carries its own cookies,
bearer token, or basic credentials, plus optional extra headers. The
`bola-idor` check will replay the same request as each principal in turn and
diff the responses.

The Evidence sanitizer redacts `Authorization`, `Cookie`, and custom header
values in reports by default. Set `reporting.redact_secrets=false` to disable
redaction — only do this when sharing reports within a trusted boundary.

### 4.4 Rate limiting

The HTTP client enforces both a token-bucket rate and a hard request cap:

- **`limits.requests_per_second`** — token-bucket rate. Defaults to 2 RPS.
  Set this to a value appropriate for the target — bug bounty programs often
  publish a rate limit in their rules of engagement.
- **`limits.max_requests`** — hard cap on total outbound requests per scan.
  Defaults to 500. Once reached, further `send()` calls raise an error.
- **`limits.timeout_seconds`** — request timeout. Defaults to 10 seconds.
- **`limits.max_concurrent_requests`** — semaphore cap on parallel in-flight
  requests. Defaults to 5. Lower this for fragile targets.
- **`limits.max_response_size_bytes`** — hard cap on response body size.
  Defaults to 5 MB. Bodies larger than this are truncated and the
  `body_truncated` flag is set on the response.
- **`limits.connection_pool_size`** — httpx connection pool size. Defaults
  to 10.

These limits apply globally across all plugins — there is no per-plugin rate
budget.

### 4.5 Reports

Reports are generated under `reports/<target-name>/` where `<target-name>`
is the target's `name` field, or the URL hostname if not set. The output
directory is sanitized for filesystem use (slashes and colons are
replaced).

Each scan produces:

- **`summary.md`** — overview with severity breakdown and a one-line
  summary per finding.
- **`findings.json`** — machine-readable, all findings in a single JSON
  document. Suitable for ingestion into Jira, DefectDojo, or a SIEM.
- **`findings/<WPOC-id>.md`** — one markdown file per finding, with full
  reproduction steps, evidence references, attack scenarios, code examples,
  remediation guidance, and CWE / OWASP tags.
- **`report.html`** — self-contained HTML report. Inline CSS, no external
  assets, ready to email or archive.

Finding IDs are issued as `WPOC-<6 hex>` and are stable within a scan. The
`fingerprint` field provides a stable identifier across scans for
deduplication.

### 4.6 Plugins

Every check in redveil is a plugin. The framework ships 17 built-in checks
covering headers, CORS, HTTP methods, disclosure, source maps, redirects,
subdomain enumeration, XSS, SQLi, SSRF, command injection, path traversal,
BOLA / IDOR, BFLA, GraphQL, mass assignment, and session cookies. Each is
discoverable through the entry-point group `redveil.checks`.

Adding a new check means subclassing `redveil.plugins.base.Check` and
declaring a `CheckMeta` with the check's id, name, category, and required
safety profile. Register it via an entry point in `pyproject.toml`:

```toml
[project.entry-points."redveil.checks"]
my-check = "my_pkg.checks.my_check:MyCheck"
```

The orchestrator wires each plugin with the wired HTTP client, scope
controller, and configuration. Plugins cannot instantiate their own HTTP
client — `bind()` validates that the supplied `HttpClient` is bound to the
orchestrator's `ScopeController`.

## 5. CLI reference

Every command supports `--help`. The commands are intentionally thin —
heavy lifting lives in the orchestrator and core modules.

- **`redveil scan <url>`** — run a full scan against the target. Builds a
  minimal single-host scope unless `--scope` is passed. Honors `--profile`,
  `--max-requests`, `--rps`, `--active`, `--output`, `--scope`.
- **`redveil scan <url> --scope scope.yaml`** — use a scope file. The file's
  `target.base_url` may differ from the URL argument; the file wins.
- **`redveil scan <url> --profile active`** — set the safety profile ceiling.
  `--profile active` alone does not enable ACTIVE checks; you must also pass
  `--active` to set the authorization flags.
- **`redveil check <plugin-id> <url>`** — run a single check plugin against
  a target. Useful for triage or for re-validating a single finding.
- **`redveil list-checks`** — list all registered check plugins with their
  IDs and safety profiles.
- **`redveil findings <report-dir>`** — print a one-line summary per finding
  from a prior report. Reads `findings.json`.
- **`redveil report <report-dir>`** — re-render Markdown from
  `findings.json`. Useful after editing the JSON or after upgrading the
  reporting layer.
- **`webpoc --help`** — show help. (This is the project's internal alias for
  the same Typer app.)

## 6. Scope configuration examples

Four runnable scope files ship in `examples/`. Each is complete and ready to
adapt.

### Staging environment (no auth, passive)

A minimal staging scope — no auth, only the staging host, low request rate,
passive profile only. See `examples/scope.staging.yaml`.

### Authenticated single-principal (cookie auth)

An in-session assessment — operator is logged in as a regular user, cookies
configured, low_impact profile. See `examples/scope.authenticated.yaml`.

### Multi-principal (for BOLA testing)

Two test accounts, one labeled as the attacker and one as the victim. The
`bola-idor` check replays requests with each principal and compares
responses. See `examples/scope.multi-principal.yaml`.

### Production with OOB (for SSRF)

A production scope with the operator's OOB callback domain declared. The
`ssrf` check will issue probes to the callback domain and watch for
inbound DNS or HTTP hits to confirm blind SSRF. See
`examples/scope.oob.yaml`.

Each file is heavily commented. Read them as templates for your own scope
files.

## 7. Output interpretation

A finding carries the following fields:

- **`id`** — `WPOC-<6 hex>`. Stable within a scan; the `fingerprint` field
  is stable across scans.
- **`check`** — the check that produced the finding, with id, name, version,
  and category.
- **`title`** — short human-readable summary.
- **`severity`** — CVSS-inspired: `critical`, `high`, `medium`, `low`, `info`.
- **`confidence`** — independent of severity: `confirmed`, `high`, `medium`,
  `low`, `tentative`.
- **`status`** — pipeline state: `discovered`, `suspected`, `validating`,
  `confirmed`, `likely`, `inconclusive`, `false_positive`, `reported`.
- **`target`** — the host, port, scheme, endpoint, method, and parameter
  affected.
- **`summary`** — one-paragraph description.
- **`technical_explanation`** — root cause, why the check fired.
- **`impact`** — what an attacker can do.
- **`attack_scenario`** — numbered reproduction steps from the knowledge base.
- **`code_examples`** — per-framework remediation snippets.
- **`reproduction`** — concrete steps with cURL commands and response
  excerpts.
- **`evidence_ids`** — references to the captured request/response pairs in
  the report directory.
- **`remediation`** — ordered guidance.
- **`cwe`** / **`owasp`** — taxonomy tags.
- **`testing_principal`** — the principal that issued the request (for
  multi-principal tests).
- **`discovered_at`** / **`confirmed_at`** — UTC timestamps.

The severity scale is inspired by CVSS v3 but simplified:

- **`critical`** — direct, unauthenticated, with no user interaction needed
  (RCE, authentication bypass, SSRF to internal metadata).
- **`high`** — authenticated or low-privilege, with meaningful data or
  privilege impact (SQLi, stored XSS, IDOR over sensitive data).
- **`medium`** — limited impact, requires specific conditions (reflected
  XSS, missing security headers, permissive CORS).
- **`low`** — informational hardening (missing `X-Content-Type-Options`,
  weak cookie flags).
- **`info`** — observation only (server version disclosure, framework
  fingerprinting).

Confidence is independent of severity. A `medium` severity finding with
`confirmed` confidence has been proven by a successful exploitation of the
PoC; a `critical` severity finding with `tentative` confidence is a
heuristic that needs manual validation. Trust the confidence.

## 8. Safety and authorization

This section is non-negotiable. Read it before running redveil against any
system.

**Only use redveil against systems you own or have explicit written
authorization to test.** The framework includes guards — empty host
allowlists that reject everything, case-insensitive host matching,
subdomain-strict matching, opt-in path globs, exclude-list-beats-allow-list
semantics, destructive-path heuristics for mutating methods, per-hop
redirect re-validation, hard request caps, response-size truncation, TLS
verification on by default, secret redaction in reports — but these guards
do not replace your responsibility as an operator.

**ACTIVE checks should only be used against test environments unless
explicitly authorized for production.** Active checks include authenticated
IDOR testing across multiple test accounts, time-based blind SQL injection,
OOB SSRF via the operator's callback domain, and time-based command
injection detection. Each is designed to be non-destructive: SQLi and CMDi
checks measure timing only and never extract data; SSRF checks target only
the operator's callback domain and never internal IP ranges; BOLA checks
re-issue the same request as multiple test principals and compare outcomes.

**The framework includes guards and will not include destructive
primitives.** Specifically, redveil does not include and will never include:

- Reverse shells or remote code execution payloads.
- Persistence mechanisms (web shells, cron jobs, scheduled tasks, startup
  scripts).
- Data exfiltration routines (SQL dumping, file reading, database listing).
- Credential extraction (hash dumping, token theft).
- Denial-of-service primitives (slow-loris, amplification, resource
  exhaustion, request flooding).
- Data destruction (file deletion, database truncation, ransomware
  patterns).

**ACTIVE profile requires explicit acknowledgement.** Setting
`active_testing=true` without `acknowledged_safety_terms=true` is rejected at
config-load time by a pydantic cross-field validator. The CLI's `--active`
flag sets both flags together so the acknowledgement is unambiguous.

**You are responsible for authorization.** A scope file with a wide
allowlist, a high `max_requests`, and `active_testing=true` is a powerful
configuration. The framework will happily run with those settings against
the host you point it at. The authorization is yours to verify, document,
and retain records of.

The authors disclaim responsibility for unauthorized or unlawful use.
Always obtain explicit, written authorization before testing any system you
do not own.

## 9. Troubleshooting

**"no plugins registered yet"**

The entry-point cache is stale. Reinstall the package:

```bash
pip install -e ".[dev]"
```

If the issue persists, check that the `redveil.checks` entry-point group
is declared in your `pyproject.toml` and that the targets are importable
classes that subclass `redveil.plugins.base.Check`.

**"out-of-scope request blocked"**

The scope controller rejected the request. Check:

- `scope.allowed_hosts` contains the host the request was sent to
  (case-insensitive, subdomain-strict).
- The path matches a glob in `scope.allowed_paths`, or
  `scope.allowed_paths` is empty (which means "allow all paths on the
  allowed hosts").
- The path is not in `scope.excluded_paths` — exclude beats allow.
- For mutating methods (`POST`, `PUT`, `DELETE`, `PATCH`) to paths matching
  destructive patterns, the path must not match the default destructive
  patterns. Override only when you have explicit authorization for those
  endpoints.

**Lab setup for testing**

The project ships an intentionally vulnerable Flask app under `tests/lab/`
for end-to-end testing. Run it with:

```bash
.venv/bin/pip install flask
./tests/lab/run.sh
```

The lab binds to `127.0.0.1:5000` by default. A matching scope file at
`tests/lab/scope.yaml` configures the framework to scan it. See the lab
README for endpoint documentation.

**Rate limiting / 429 responses**

If the target returns 429 (Too Many Requests), lower
`limits.requests_per_second` and `limits.max_concurrent_requests`. Bug
bounty programs often publish a rate limit in their policy — respect it.

**Auth not being applied**

Verify `auth.method` is set correctly and the corresponding field
(`cookies`, `token`, `username` / `password`, or
`header_name` / `header_value`) is populated. The Evidence sanitizer
redacts auth values in reports — this is expected, not a bug.

**Run interrupted mid-scan**

Reports are written at the end of a scan, not incrementally. An interrupted
scan produces no report. Re-run the scan with the same scope file to
regenerate. The `redveil report <dir>` command re-renders Markdown from an
existing `findings.json`.

## 10. Comparison with other tools

A brief comparison with other widely-used security tools. The goal is not
to declare a winner — redveil targets a specific niche.

| Tool             | Strengths                                                    | Differences from redveil                                                |
| --------------- | ------------------------------------------------------------ | --------------------------------------------------------------------- |
| OWASP ZAP       | Mature proxy, active scanner, large addon ecosystem, free.   | ZAP includes proxy UI and intrusive scans by default. redveil is CLI-only, evidence-first, no exploit payloads. |
| Burp Suite      | Industry standard for manual testing, deep request editor, extensions. | Burp is GUI-first, commercial, and operator-driven. redveil automates the report generation and produces reproducible PoC artifacts. |
| Nuclei          | Fast template-based scanner, large community template library. | Nuclei scans are signature-based with optional exploit templates. redveil's checks are code-driven and produce richer evidence per finding. |

What makes redveil distinct:

- **Evidence-first.** Every finding ships with a sanitized cURL command and
  response excerpt that reproduce the finding on demand. No
  "vulnerability found" without reproduction steps.
- **No exploit payloads.** redveil will never include exploit payloads,
  even for confirmed vulnerabilities. The framework stops at
  non-destructive confirmation.
- **Multi-format reports.** Markdown for reading, JSON for automation,
  self-contained HTML for archiving. One scan produces all three.
- **Pluggable architecture.** Adding a check is a 50-line subclass of
  `Check`. No fork required, no upstream patch, no review cycle.

redveil is not a replacement for any of the above tools. It is an
adjacent tool for operators who specifically need reproducible,
non-destructive, evidence-rich reports.

---

For architecture and internals, see [docs/architecture.md](docs/architecture.md).
For changes between versions, see [CHANGELOG.md](CHANGELOG.md). For the
project's own self-description, see [README.md](README.md).