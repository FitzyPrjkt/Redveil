# Changelog

## 1.9.5 — 2026-09-01

### changed
- **CLI: comprehensive manpage-style `--help` output** (nmap-like).
  - Sections: TARGET SPECIFICATION, SCAN OPTIONS, AUTHORIZATION &
    ACTION GATE, REPORT COMMANDS, SAFETY PROFILES, DESTRUCTIVE LEVELS,
    EXAMPLES, EXIT CODES, SAFETY, DOCS.
  - Centered section headers (yellow) for visual clarity.
  - Tables for SAFETY PROFILES, DESTRUCTIVE LEVELS, EXIT CODES.
  - Triggered by `redveil --help` or `redveil -h` (no subcommand needed).
- `--version` / `-V` flag added (was missing).
- All `.md` cross-references in README use absolute GitHub URLs so
  they don't 404 on PyPI (which only hosts `README.md`).
- Bumped `__version__` to 1.9.5 (was stuck at 1.9.3).

## 1.9.3 — 2026-09-01

### added
- **DWYOR (Do With Your Own Risk) disclaimer** at the top of README as
  a `## ⚠️ DANGER ZONE` callout. New `DWYOR.md` with the full statement:
  authorized security testing only, system ownership or explicit
  written permission required, operator bears all legal/ethical
  liability, authors not responsible for misuse.
- **PEP 668 install warning** at the top of README: modern Linux distros
  (Debian 12+, Ubuntu 23.04+, Fedora 38+, etc.) block system-wide
  `pip install` with `externally-managed-environment`. Recommends
  `pipx` or `python -m venv`. Includes distro-specific commands
  (apt/dnf/pacman/zypper/brew).
- **Per-vuln destructive mapping** (`redveil/knowledge/destructive_levels.py`):
  - Each active check declares `max_destructive_level` and
    `recommended_max_level` + typical_actions.
  - Examples: `sqli-time-based` max=TAKEOVER, recommended=DATA_EXFILTRATION.
- 11 new tests for the per-vuln destructive mapping.

## 1.9.0 — 2026-09-01

### added
- **DestructiveLevel 1-6 scale** (replaces boolean `destructive`):
  - L1 data_exfiltration · L2 data_modification · L3 data_destruction
  - L4 persistence · L5 lateral_movement · L6 takeover
- **Tiered confirmation** for destructive actions:
  - L1-2: simple Y/N
  - L3+: user must **type the exact word** (`CONFIRM`, `CONFIRM-LEVEL-4`, etc.)
    or the plan's `confirm_word` (e.g. `rm-rf`, `drop-table`)
- **`max_destructive_level` config field** (accepts short form `L1`..`L6`):
  - operator's ceiling. Plans above are denied even with `allow_destructive: true`
  - default `2` (data_modification allowed, destruction blocked)
- **Per-check `destructive_level` + `confirm_word` fields** in `ActionPlan`:
  - XSS, SQLi, CMDi, SSRF, path-traversal, BOLA, BFLA wired
- **ActionGate.audit_log()**: JSON-serializable decision history for
  audit reports
- **ActionGate tiered prompts** in interactive mode:
  - level 1-2: standard Y/N
  - level 3+: prominent warning + "Type CONFIRM[-LEVEL-N]"
- 19 new tests for DestructiveLevel + tiered confirmation
- 11 new tests for per-vuln destructive mapping

## 1.8.0 — 2026-09-01

### added
- `redveil/validation/environment.py`: Environment enum + profile
- `redveil/validation/replay.py`: ReplayRecipe + ReplayEngine (Wave 3)
- `redveil/validation/flakiness.py`: FlakinessDetector (Wave 4)
- `redveil/validation/oracle.py`: Oracle enum + Signal (Wave 2)
- `redveil/validation/confidence.py`: ConfidenceScorer with multi-signal (Wave 2)
- `redveil/validation/risk.py`: Risk enum + ActionPlan (Wave 7)
- `redveil/validation/gate.py`: ActionGate with 3 modes (Wave 7-8)
- `redveil/attack_surface/`: ApplicationModel + BehaviorModel (Phase 2)
- `redveil/behavior/`: State + Transitions + Hypotheses + Planner (Phase 2)
- Wave 5: root-cause clustering (`Finding.root_cause`, `cluster_size`,
  `affected_endpoints`)
- Wave 6: environment awareness + uncertainty propagation
- 1070 → 1089 tests passing

## 1.0.0 — 2026-09-01

first public release. 17 check plugins, 920 tests.

### safety
- no destructive payloads. runtime assertions in every active check
- no data extraction payloads (SQLi is time-based only)
- no internal IP targeting (SSRF uses operator-configured OOB domain only)
- ACTIVE profile requires `authorization.acknowledged_safety_terms=true`
- evidence sanitizer redacts cookies, JWTs, AWS keys, GitHub tokens, Stripe keys, credit cards, emails

see [SECURITY.md](SECURITY.md) for the full model.
