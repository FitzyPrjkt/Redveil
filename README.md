# redveil

web vulnerability scanner. find vulns, validate safely, get a report you can actually send to a dev team.

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
$ redveil scan <url> [--scope FILE] [--profile PROFILE] [--output DIR]
$ redveil check <plugin-id> <url>
$ redveil list-checks
$ redveil findings <report-dir>
$ redveil report <report-dir>
```

profiles: `passive` (default, observation only), `low_impact` (safe probes), `active` (requires explicit `active_testing: true` in scope).

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

17 checks, 920 tests passing, 0 known safety violations. actively used against staging environments. not yet battle-tested at scale — feedback and bug reports welcome.

## license

MIT. see [LICENSE](LICENSE).
