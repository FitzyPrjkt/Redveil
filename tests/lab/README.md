# redveil Vulnerable Lab

An **intentionally vulnerable** Flask application used as a fixture for testing
the redveil security framework (Phase 3 passive checks and Phase 4 active checks).

> **Authorized security testing only.** This lab binds to `127.0.0.1` only.
> Do **not** expose it to a network. No real exploits, no destructive
> functionality. The "vulnerabilities" produce strong, testable evidence
> (timing, response differences, header presence/absence).

## Running

```bash
# From the project root
.venv/bin/pip install flask      # one-time
./tests/lab/run.sh               # or: .venv/bin/python tests/lab/app.py
```

The server listens on `http://127.0.0.1:5000` with Flask debug mode enabled.

Override host/port with environment variables if needed:

```bash
LAB_HOST=127.0.0.1 LAB_PORT=5050 python tests/lab/app.py
```

## Endpoints and what each simulates

Each row documents: the route, the simulated vulnerability category, the
evidence a scanner should collect, and any safety notes.

| # | Route | Vuln class | Evidence |
|---|---|---|---|
| 1 | `GET /` | Missing security headers | No `Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`, `X-Content-Type-Options` |
| 2 | `GET /api/profile?user_id=N` | IDOR | Different `user_id` returns different user records without authn check. CORS misconfig (`ACAO: *` + `ACAC: true`) |
| 3 | `GET /api/profile/me` | Weak cookie config | Cookie set without `HttpOnly`, `Secure`, or `SameSite` |
| 4 | `GET /search?q=` | Reflected XSS | `q` value is rendered verbatim into HTML; `<script>` payloads will appear in the response body |
| 5 | `POST /login` | SQL injection simulation | `username=admin' OR '1'='1` returns `auth_ok=true` and sets a session cookie. No real SQL executed - a Python dict lookup mimics the bypass |
| 6 | `GET /file?path=` | Path traversal | `..` or absolute paths return 404 with `blocked: true` evidence. Real traversal is *not* allowed |
| 7 | `GET /api/data` | CORS misconfig | `Access-Control-Allow-Origin: *` plus `Access-Control-Allow-Credentials: true` (contradictory). OPTIONS preflight echoes the Origin |
| 8 | `GET /redirect?to=` | Open redirect | No validation - 302 to any URL |
| 9 | `GET /debug` | Info disclosure | Leaks Python version, Flask version, hostname, full route map, env vars, fake config secret. Sets `X-Powered-By: Flask` |
| 10 | `GET /server-status` | Exposed management panel | Static "Apache Server Status" output. Discovery check should flag |
| 11 | `POST /api/echo` | Permissive HTTP methods | Allows GET/POST/PUT/DELETE/PATCH/OPTIONS. Method check should flag |
| 12 | `GET /api/ping?host=` | Command injection (SAFE) | Echoes input. If shell metachars are present, returns blocked payload and sleeps 0.5s (time-based evidence, capped). **No commands are executed** |
| 13 | `GET /api/version` | API versioning | Sets `X-API-Version: 1.0` header |
| 14 | `POST /webhook` | Webhook auth | Accepts token via query or `X-Webhook-Token` header. Correct token returns 200, otherwise 401 |
| 15 | `GET /api/source-map` | Source map disclosure | Returns a fake `.js.map` JSON with `Content-Type: application/json` and `X-SourceMap` header |
| 16 | `GET|POST /api/graphql` | GraphQL introspection enabled | `{"query": "{ __schema { types { name } } }"}` returns the type list |
| 17 | `GET /robots.txt`, `GET /sitemap.xml` | Discovery | Static content listing disallowed paths and a basic sitemap |
| 18 | `GET /login-insecure` | Weak session cookie (multiple flags missing) | Sets `session=insecure_session_token_abc123` with no `HttpOnly`, no `Secure`, no `SameSite` |
| 19 | `GET /login-https-only` | Cookie over HTTP without `Secure` flag | Sets a long random session cookie with `HttpOnly` and `SameSite=Strict` but no `Secure` |
| 20 | `GET /login-weak-token` | Low-entropy session token | Sets `session=abc123` (predictable 6-char token) despite correct flags |
| 21 | `GET /login-vulnerable` | Hardening gap (no `HttpOnly`) | Sets a strong token with `Secure` and `SameSite=Strict` but no `HttpOnly` — XSS-chainable |
| 22 | `GET /xss-vulnerable?q=` | Reflected XSS sink | `q` value is rendered verbatim into HTML; chains with `/login-vulnerable` to demonstrate a CRITICAL XSS-to-cookie-theft attack |

> **Note:** Endpoints 18–22 exist so redveil's `session-cookie` check (vector-based)
> has real cookie data to test against. Each endpoint exercises a different
> aspect of cookie hardening (missing flags, weak tokens, XSS chain) so the
> framework can produce a differentiated finding for each class.

## Sample data

- `data/users.json` — three user records (Alice, Bob, Admin) used for IDOR.
- `data/notes.txt` — sample note used for the path traversal demo.
- `data/config.ini` — fake config with `password = FAKE_PASSWORD_FOR_TESTING_ONLY_NOT_REAL`
  (the "secret" leaked by `/debug` is intentionally fake).

## Cookie behavior

`/login` and `/api/profile/me` set cookies with `Path=/`, `HttpOnly=False`,
`Secure=False`, and `SameSite=None`. This is intentional - the framework's
cookie-config check should flag the missing security flags.

## Safety guarantees

- No real SQL is executed. The login endpoint uses a Python dict lookup.
- No real shell commands run. The ping endpoint only echoes input and may
  sleep up to 0.5s as time-based evidence.
- No real path traversal succeeds. The `/file` endpoint serves files from
  an allowlist only; traversal attempts are detected and blocked with 404.
- Bound to `127.0.0.1` by default. `LAB_HOST` env var exists but should
  never be set to anything other than `127.0.0.1`.

## Verification

A quick smoke test:

```bash
.venv/bin/python -c "
import httpx
r = httpx.get('http://127.0.0.1:5000/')
print('GET /:', r.status_code)
r = httpx.get('http://127.0.0.1:5000/api/profile?user_id=1')
print('GET /api/profile:', r.status_code, r.json().get('name'))
r = httpx.get('http://127.0.0.1:5000/search?q=test')
print('GET /search:', r.status_code, 'reflected:', 'test' in r.text)
r = httpx.get('http://127.0.0.1:5000/debug')
print('GET /debug:', r.status_code, 'disclosure:', 'Python' in r.text)
r = httpx.get('http://127.0.0.1:5000/api/data')
print('GET /api/data cors:', r.headers.get('access-control-allow-origin'))
print('OK')
"
```