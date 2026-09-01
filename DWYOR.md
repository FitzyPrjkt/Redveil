# DWYOR — Do With Your Own Risk

⚠️ **DWYOR — Do With Your Own Risk.**

Redveil is intended for **authorized security testing only**.

Only use it against systems you **own** or have **explicit written permission** to test.

The authors are not responsible for misuse, damage, data loss, or unauthorized activity resulting from the use of this software.

## What this means in practice

You are responsible for:

- **Authorization** — having explicit, written permission from the system owner
  before running redveil against any target
- **Scope** — staying within the agreed-upon scope (hosts, paths, time window)
- **Impact** — any state changes, alerts, or side effects caused by redveil
  or any exploit built on findings it produces
- **Cleanup** — restoring any test data, accounts, or configuration changes
  made during authorized testing
- **Legal compliance** — following all applicable laws (CFAA, GDPR, computer
  misuse laws, etc.) in your jurisdiction

## What redveil does to help

Redveil includes technical safeguards, not legal ones:

- **Scope controller** — refuses out-of-scope hosts, paths, redirects
- **DestructiveLevel 1-6 + tiered confirmation** — requires typed
  per-action approval for level 3+ actions (rm -rf, DROP TABLE, etc.)
- **No destructive payloads by default** — all built-in checks use
  canary strings, time-based delays, OOB callbacks, or observation only
- **Evidence sanitization** — secrets are redacted from reports
- **Audit log** — every gate decision is logged

These are **engineering controls**. They make accidental damage less
likely. They do not constitute authorization to test any system you
don't have permission to test.

## No "explore freely" mode

Redveil intentionally does not provide:

- A "scan the internet" mode
- A "find targets for me" feature
- Anonymous OOB callback servers
- Pre-configured targets for popular bug bounty programs

If you want those, use a different tool. redveil assumes the operator
has already chosen a target and has authorization to test it.

## Violation of this policy

If you use redveil to scan systems without authorization:

- The authors offer no support
- The authors do not condone the activity
- You assume all legal and ethical liability
- You may be subject to criminal prosecution under applicable laws

The "DWYOR" principle means: **you own the consequences of your use
of this tool, including any unauthorized use.**
