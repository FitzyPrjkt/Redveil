# Changelog

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
- **Per-vuln destructive mapping** in `redveil/knowledge/destructive_levels.py`:
  - each active check declares the maximum destructive level it COULD enable
  - e.g. `sqli-time-based` max = TAKEOVER (xp_cmdshell RCE), but
    `recommended_max_level` = `DATA_EXFILTRATION` (we only do time-based probes)
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
