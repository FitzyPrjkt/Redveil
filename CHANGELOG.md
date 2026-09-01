# Changelog

## 1.0.0 — 2026-09-01

first public release.

### added

- 17 check plugins:
  - **passive** (safe by default): `security-headers`, `information-disclosure`, `cors-policy`, `http-methods`, `open-redirect-indicator`, `source-map-exposure`, `session-cookie`, `subdomain-finder`
  - **active** (require `active_testing: true`): `xss-reflected`, `sqli-time-based`, `ssrf`, `command-injection`, `path-traversal`
  - **authz** (require multi-principal config): `bola-idor`, `bfla`, `mass-assignment`, `graphql`
- plugin system with entry-point discovery (`[project.entry-points."redveil.checks"]`)
- scope controller with host + path allowlist, redirect chain validation, destructive-path heuristic. plugins cannot bypass
- async HTTP client (`httpx`) with rate limiting, request IDs, response timing, max response size
- auth providers: anonymous, cookie, bearer, basic, custom header, multi-principal
- event bus with rich console renderer
- finding + evidence model with sanitizer (JWT, AWS, GitHub, Stripe, Slack, credit card, email, cookies)
- deduplicator (per-fingerprint)
- markdown, JSON, and self-contained HTML reports
- vulnerability knowledge base: 50+ entries with summary, technical explanation, attack scenario, impact, remediation, and code examples for 4+ frameworks per entry
- local vulnerable Flask lab (`tests/lab/`) with 17 endpoints covering every check category
- subdomain discovery via web crawler
- 920 tests

### safety

- no destructive payloads. runtime assertions in every active check
- no data extraction payloads (SQLi is time-based only)
- no internal IP targeting (SSRF uses operator-configured OOB domain only)
- ACTIVE profile requires `authorization.acknowledged_safety_terms=true`
- evidence sanitizer redacts cookies, JWTs, AWS keys, GitHub tokens, Stripe keys, credit cards, emails

see [SECURITY.md](SECURITY.md) for the full model.
