# Security

## Found a bug in redveil itself?

if you find a vulnerability in the framework code — bypass in the scope controller, ACTIVE check producing a destructive payload, sanitizer not redacting something, hardcoded credential, that kind of thing — please report it privately.

**don't open a public GitHub issue.** public disclosure before a fix gives attackers a head start.

report via GitHub Security Advisories (preferred): https://github.com/FitzyPrjkt/Redveil/security/advisories/new — supports private disclosure thread.

include:
- what's vulnerable
- how to reproduce (proof of concept if you have one)
- which version
- your read on impact

we'll ack within a few days. no formal SLA on fix timeline — this is a small project, not a vendor with a security team.

## Out of scope

these are user output, not redveil bugs — file them in the right place:

- findings produced by redveil on a target you scanned. if the finding is wrong, that's a check bug — file a GitHub issue. if the finding is right but you don't like the wording, that's a doc issue.
- vulnerabilities in third-party plugins or deps. report upstream.
- general "redveil should also do X" requests. open a feature request issue.

## what redveil is and isn't

redveil is a defensive security assessment tool. it is not an exploit framework. the active checks use bounded non-destructive payloads:

- XSS — alphanumeric canary only
- SQLi — time-based delay only
- SSRF — OOB callback to operator's configured domain only
- command injection — `sleep` only
- path traversal — unique canary filename only

runtime assertions in each check verify these on import. the test suite has safety tests for every check.

if you find a code path that does anything destructive, that IS a vulnerability and you should report it.

## destructive action handling (DestructiveLevel 1-6)

redveil classifies potential destruction on a 6-level scale:

| Level | Label | Example |
|---|---|---|
| 1 | data_exfiltration | read `/etc/passwd`, dump DB |
| 2 | data_modification | `UPDATE`, `chmod` |
| 3 | data_destruction | `rm -rf`, `DROP TABLE` |
| 4 | persistence | `crontab`, webshell |
| 5 | lateral_movement | SSH keys, network scan |
| 6 | takeover | full account takeover, complete RCE |

**Default behavior**:
- Destructive actions (`destructive=True`) are **denied by default**
- `max_destructive_level` defaults to `2` (data_modification allowed)
- Even with `allow_destructive: true`, each destructive action requires
  per-action typed confirmation: level 3+ requires typing `CONFIRM`,
  `CONFIRM-LEVEL-4`, etc. or the plan's `confirm_word` (e.g. `rm-rf`).
  **No Y-to-all.**
- In non-interactive mode (CI), destructive actions are denied even
  with `allow_destructive: true`. Use `--interactive` to enable prompts.

this protects against accidental destructive actions, including in
shared/CI environments where a prompt would be auto-skipped.

## authorized use only

operators are responsible for ensuring they have permission before scanning a target. redveil includes guards, but the guards only matter if you actually have authorization.

legitimate use cases: bug bounty (with the program's scope), VDP, pentest under a written RoE, owned apps, local labs (use `tests/lab/`).

not legitimate: scanning systems you don't own or aren't authorized to test. "just probing" is not a defense.

## the safety contract

this is what redveil will never do, by design:

- reverse shells, bind shells, /dev/tcp, anything that gives the operator a shell
- persistence: cron, systemd, registry, scheduled tasks
- credential extraction: mimikatz-style, /etc/shadow reads
- data destruction: rm -rf, dd, mkfs, fdisk, chmod 777 on /
- denial of service: slowloris, http flood, resource exhaustion
- exploit payloads that execute arbitrary code
- internal network probing: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16, ::1
- brute force: no credential spraying, no token guessing, no session fixation via forced login
- large-scale scraping: rate-limited by default (2 RPS)

if any of these start happening, file a bug.

## disclosure timeline

rough guideline, not a hard commitment:

| day | what |
|---|---|
| 0 | report received |
| 3 | ack, start triage |
| 14 | fix proposed or status update |
| 90 | fix shipped, or disclosure coordinated with reporter |

if you need a faster turnaround, mention it in the report and we'll do what we can.
