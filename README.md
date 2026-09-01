# redveil

web vulnerability scanner. find vulns, validate safely, get a report you can actually send to a dev team.

<!-- Badges -->
[![PyPI version](https://img.shields.io/pypi/v/redveil.svg)](https://pypi.org/project/redveil/)
[![Python versions](https://img.shields.io/pypi/pyversions/redveil.svg)](https://pypi.org/project/redveil/#files)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/FitzyPrjkt/Redveil/blob/main/LICENSE)
[![Tests](https://img.shields.io/badge/tests-1101%20passing-brightgreen.svg)](https://github.com/FitzyPrjkt/Redveil/actions)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: tiered gate](https://img.shields.io/badge/destructive%20ops-tiered%20confirm-orange.svg)](SECURITY.md)
[![Negative testing](https://img.shields.io/badge/FP%20testing-secure%20fixture-green.svg)](tests/test_negative_testing.py)
[![Audit log](https://img.shields.io/badge/audit%20log-per%20action%20decision-blue.svg)](src/redveil/validation/gate.py)

```
$ pip install redveil
$ redveil scan https://target.example --scope scope.yaml
$ redveil list-checks
```

## install

```bash
pip install redveil
```

or from source:

```bash
git clone https://github.com/FitzyPrjkt/Redveil
cd redveil
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

requires python 3.12+.

## quick start

```bash
# 1. write a scope file
cat > scope.yaml <<'EOF'
target:
  base_url: https://staging.example.com
scope:
  allowed_hosts:
    - staging.example.com
  allowed_paths:
    - /api/*
    - /account/*
limits:
  requests_per_second: 2
  max_requests: 500
authorization:
  active_testing: false
  acknowledged_safety_terms: false
profile: passive
EOF

# 2. scan
redveil scan https://staging.example.com --scope scope.yaml

# 3. results
ls reports/staging.example.com/
cat reports/staging.example.com/summary.md
open reports/staging.example.com/report.html
```

## what you get

- **17 built-in checks** — security headers, CORS, info disclosure, HTTP methods, open redirect indicators, source map exposure, XSS (canary reflection), SQLi (time-based), SSRF (OOB), command injection (time-based), path traversal (canary), BOLA/IDOR, BFLA, GraphQL, mass assignment, session/cookie config, subdomain discovery
- **multi-format reports** — markdown per finding, JSON for tooling, self-contained HTML
- **strict scope enforcement** — host + path allowlist, redirect chain validation, destructive path heuristic. plugins cannot bypass it
- **multi-principal auth** for BOLA testing — define Account A + Account B in scope, redveil compares what each can see
- **evidence sanitization** — JWTs, AWS keys, GitHub tokens, credit cards, cookies, emails all redacted before report
- **local lab** at `tests/lab/` — a Flask app with 17 deliberately vulnerable endpoints for testing without hitting the internet

## safety

redveil is a defensive tool. the active checks (XSS, SQLi, SSRF, command injection, path traversal) use **bounded non-destructive payloads**:

- XSS: alphanumeric canary strings. no `<script>`, no execution
- SQLi/command injection: time-based delay only (`sleep 3`). no data extraction
- SSRF: OOB callback to operator's own domain. no internal IP probing
- path traversal: unique canary filenames. no real file reads

runtime assertions in each check verify these constraints on every import. the test suite has explicit safety tests for every check.

**you are responsible for authorization.** redveil includes guards but they only matter if you actually have permission to test the target.

see [SECURITY.md](SECURITY.md) for the full safety model and how to report issues.

## CLI

```
$ redveil --help                # show all commands
$ redveil scan --help            # scan command flags
$ redveil check --help           # single-check flags
$ redveil list-checks            # list 17 registered check plugins
$ redveil findings <dir>         # show summary of a saved report
$ redveil report <dir>           # re-render a report
```

### `redveil scan <url>`

Run a full scan against a target. Flags:

| Flag | Description |
|---|---|
| `<url>` | **Required.** Target base URL, e.g. `https://staging.example.com` |
| `-s`, `--scope FILE` | Path to a scope YAML file. If omitted, a minimal single-host scope is built. |
| `-p`, `--profile PROFILE` | Safety profile: `passive` (default), `low_impact`, or `active` |
| `--max-requests N` | Hard cap on total requests (default 500) |
| `--rps N` | Requests per second (default 2.0) |
| `--active` | Enable ACTIVE checks. Requires `acknowledged_safety_terms: true` in scope. |
| `-g`, `--gate-mode MODE` | ActionGate mode: `interactive`, `non_interactive` (default), `strict` |
| `--allow-destructive` | Explicit opt-in to unlock destructive actions (each still needs per-action typed confirm) |
| `--max-destructive-level L` | Operator's ceiling. Short form `L1`-`L6` or integer. Default `2` (data_modification). |
| `-o`, `--output DIR` | Output directory for reports (default `reports/`) |

### `redveil check <plugin-id> <url>`

Run a single check plugin. Useful for targeted testing.

```bash
redveil check cors-policy https://staging.example.com
redveil check xss-reflected https://target.com --scope scope.yaml
```

### `redveil list-checks`

List all 17 registered check plugins with their safety profile:

```
bfla                BFLA / Function-Level Authorization Check
bola-idor           BOLA / IDOR Check
command-injection    Command Injection Check (Time-Based)
cors-policy         CORS Policy Check
graphql             GraphQL Check
http-methods        HTTP Methods Check
information-disclosure  Information Disclosure Check
mass-assignment     Mass Assignment Check
open-redirect-indicator  Open Redirect Indicator
path-traversal      Path Traversal Check
security-headers    Security Headers Check
session-cookie      Session and Cookie Configuration Check
source-map-exposure Source Map Exposure Check
sqli-time-based     Time-Based Blind SQL Injection Check
ssrf                Server-Side Request Forgery Check
subdomain-finder    Subdomain Finder
xss-reflected       Reflected XSS Check
```

### `redveil findings <report-dir>`

Print a summary of a previously-saved report.

```bash
redveil findings reports/staging.example.com/
# Output:
#   12 findings
#   - [HIGH    ] Missing X-Frame-Options Header
#   - [MEDIUM  ] Missing Content-Security-Policy Header
#   ...
```

### `redveil report <report-dir>`

Re-render a report from existing `findings.json` (in case you want to
regenerate the markdown/HTML after editing the JSON).

### Safety profiles

- `passive` (default) — only observation, no payload injection
- `low_impact` — safe probes (CORS preflight, method check, harmless reflection)
- `active` — requires `active_testing: true` in scope. Issues canary
  payloads, time-based delays, OOB callbacks, etc.

## writing checks

a check is a `Check` subclass:

```python
from redveil.plugins.base import Check, CheckCategory, CheckMeta, ...

class MyCheck(Check):
    meta = CheckMeta(
        id="my-check",
        name="My Check",
        category=CheckCategory.HEADERS,
        safety_profile=SafetyProfile.PASSIVE,
    )
    async def discover(self, ctx): ...
    async def validate(self, ctx, candidate): ...
    async def collect_evidence(self, candidate): ...
    async def assess(self, candidate): ...
```

register in `pyproject.toml`:

```toml
[project.entry-points."redveil.checks"]
my-check = "my_pkg.checks:MyCheck"
```

see [CONTRIBUTING.md](CONTRIBUTING.md) for the full plugin spec.

## files

- `USER_GUIDE.md` — installation, configuration, CLI reference, output interpretation
- `CONTRIBUTING.md` — how to add checks
- `PUBLISH.md` — how to publish a new release
- `SECURITY.md` — safety model, how to report issues
- `CHANGELOG.md` — release notes
- `docs/architecture.md` — internal design
- `examples/` — scope files for common scenarios
- `tests/lab/` — vulnerable Flask app for local testing

## status

17 checks, ~1090 tests passing, 0 known safety violations. actively used against staging environments. the framework ships with curated, tested-safe payloads; destructive actions require per-action typed confirmation (no batch approval) and an explicit `allow_destructive: true` unlock in config.

## what makes redveil different from sqlmap / nikto / burp scanner

| Aspect | traditional scanner | redveil |
|---|---|---|
| Payload | signature match (e.g. `' OR 1=1 --`) | time-based delay, OOB callback, canary reflection |
| Action | match pattern → flag | model target → hypothesis → controlled test → multi-signal correlation → confidence-scored finding |
| Confidence | hardcoded HIGH or LOW | computed: `oracle × (1 + log2(distinct_dims)) × weight − env_penalty − uncertainty` |
| Reproducibility | not verified | `ReplayRecipe` + `ReplayEngine` runs N samples |
| FP reduction | none | negative testing, flakiness detection, env awareness, uncertainty propagation |
| Root cause | one finding per endpoint | clustered across endpoints with same root cause |
| Destructive | implicit (run anyway) | blocked by default. tiered confirmation L1-L6. no Y-to-all. |

see [USER_GUIDE.md](USER_GUIDE.md) and [docs/architecture.md](docs/architecture.md) for details.

## license

MIT. see [LICENSE](LICENSE).
