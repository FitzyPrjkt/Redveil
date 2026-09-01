"""redveil vulnerable lab Flask application.

INTENTIONALLY VULNERABLE - for AUTHORIZED security testing of the redveil
framework only. Binds to 127.0.0.1 only. No real exploits, no destructive
functionality. All "vulnerabilities" produce strong, testable evidence.

WARNING: Do not expose this application to a network.
"""
from __future__ import annotations

import json
import os
import platform
import re
import socket
import sys
import time
from pathlib import Path

import flask

# ----------------------------------------------------------------------------
# App setup
# ----------------------------------------------------------------------------

LAB_DIR = Path(__file__).resolve().parent
DATA_DIR = LAB_DIR / "data"

app = flask.Flask("redveil-lab")
app.config["JSON_SORT_KEYS"] = False
app.config["PROPAGATE_EXCEPTIONS"] = True
app.debug = True  # so X-Powered-By: Flask leaks and Werkzeug debug is on

# Allowlist of files for the /file endpoint - safe but vulnerable-looking
FILE_ALLOWLIST = {
    "notes.txt": DATA_DIR / "notes.txt",
    "config.ini": DATA_DIR / "config.ini",
    "users.json": DATA_DIR / "users.json",
}


def _fake_query_builder(table: str, where_clause: str) -> dict:
    """Mimic a naive SQL query builder without actually executing SQL.

    Real apps do: f"SELECT * FROM {table} WHERE {where_clause}". We mimic the
    *effect* of injection by parsing the WHERE clause for SQLi tautologies so
    the framework can detect the bypass.
    """
    sql = f"SELECT * FROM {table} WHERE {where_clause}"
    # Normalize for tautology detection: admin' OR '1'='1
    # We treat any clause containing `OR '1'='1` (or 1=1) as a SQLi bypass.
    lowered = where_clause.lower().replace(" ", "")
    sqli_bypass = bool(
        re.search(r"or['\"]?1['\"]?=['\"]?1", lowered)
        or "or1=1" in lowered
        or "'or'" in lowered
        or '"or"1"="1' in lowered
    )
    # Naive credential lookup table (simulated DB rows)
    rows = {
        ("admin", "admin"): {"id": 3, "name": "Admin", "role": "admin"},
        ("alice", "wonderland"): {"id": 1, "name": "Alice", "role": "user"},
        ("bob", "builder"): {"id": 2, "name": "Bob", "role": "user"},
    }
    if sqli_bypass:
        # SQLi bypass returns the first row regardless of credentials.
        return {"sql": sql, "auth_ok": True, "row": list(rows.values())[0], "sqli": True}
    # Try to extract username/password from "username='X' AND password='Y'"
    m = re.match(
        r"^\s*username\s*=\s*['\"](?P<u>[^'\"]*)['\"]\s*AND\s*password\s*=\s*['\"](?P<p>[^'\"]*)['\"]\s*$",
        where_clause,
    )
    if m:
        row = rows.get((m.group("u"), m.group("p")))
        return {
            "sql": sql,
            "auth_ok": row is not None,
            "row": row,
            "sqli": False,
        }
    return {"sql": sql, "auth_ok": False, "row": None, "sqli": sqli_bypass}


# ----------------------------------------------------------------------------
# 1. GET / — Home
# ----------------------------------------------------------------------------

@app.route("/")
def home():
    resp = flask.Response(
        """<!doctype html>
<html><head><title>redveil lab</title></head><body>
<h1>redveil vulnerable lab</h1>
<p>Authorized security testing only. Binds to 127.0.0.1.</p>
<ul>
<li><a href="/api/profile?user_id=1">/api/profile?user_id=1</a> (IDOR)</li>
<li><a href="/api/profile/me">/api/profile/me</a> (cookie auth)</li>
<li><a href="/search?q=hello">/search?q=hello</a> (reflected XSS)</li>
<li><a href="/login">/login</a> (SQLi simulation, GET form preview)</li>
<li><a href="/file?path=notes.txt">/file?path=notes.txt</a> (path traversal)</li>
<li><a href="/api/data">/api/data</a> (CORS misconfig)</li>
<li><a href="/redirect?to=https://example.com">/redirect?to=...</a></li>
<li><a href="/debug">/debug</a> (info disclosure)</li>
<li><a href="/server-status">/server-status</a></li>
<li><a href="/api/version">/api/version</a></li>
<li><a href="/api/source-map">/api/source-map</a></li>
<li><a href="/robots.txt">/robots.txt</a> / <a href="/sitemap.xml">/sitemap.xml</a></li>
</ul>
</body></html>
""",
        mimetype="text/html",
    )
    # Intentional: NO security headers (CSP, X-Frame-Options, etc.)
    return resp


# ----------------------------------------------------------------------------
# 2. GET /api/profile?user_id=N — IDOR
# ----------------------------------------------------------------------------

@app.route("/api/profile")
def api_profile():
    user_id = flask.request.args.get("user_id", "")
    # No auth check. Vulnerable: any caller can read any user.
    with (DATA_DIR / "users.json").open() as f:
        users = json.load(f)
    user = users.get(str(user_id))
    if user is None:
        return flask.jsonify({"error": "not found", "user_id": user_id}), 404
    resp = flask.make_response(flask.jsonify(user))
    # CORS misconfig: wildcard origin + credentials (contradictory).
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


# ----------------------------------------------------------------------------
# 3. GET /api/profile/me — Cookie-based auth
# ----------------------------------------------------------------------------

@app.route("/api/profile/me")
def api_profile_me():
    # Vulnerable cookie handling: no HttpOnly, no Secure, no SameSite.
    # Supports BOTH session=1|2|3 (multi-principal test cookie) AND the
    # legacy session_user=1 cookie. The session cookie is what the BOLA
    # check uses to authenticate as different principals for cross-account
    # testing.
    #   session=1 → Account A (Alice)
    #   session=2 → Account B (Bob)
    #   session=3 → Account C (Admin)
    session = flask.request.cookies.get("session")
    session_user = flask.request.cookies.get("session_user", "1")
    principal_id = session or session_user
    with (DATA_DIR / "users.json").open() as f:
        users = json.load(f)
    user = users.get(str(principal_id))
    resp = flask.make_response(
        flask.jsonify({
            "authenticated_as": user,
            "principal_id": principal_id,
            "cookie_used": "session" if session else "session_user",
            "cookie_flags": "missing HttpOnly, Secure, SameSite",
        })
    )
    # Intentional weak cookie: set if not present, no security flags.
    if not flask.request.cookies.get("session_user") and not session:
        resp.set_cookie("session_user", "1", path="/", httponly=False, secure=False, samesite=None)
    return resp


# ----------------------------------------------------------------------------
# 4. GET /search?q=... — Reflected XSS
# ----------------------------------------------------------------------------

@app.route("/search")
def search():
    q = flask.request.args.get("q", "")
    # Vulnerable: no sanitization, direct reflection into HTML.
    body = f"""<!doctype html>
<html><head><title>search</title></head><body>
<h1>Search results for: {q}</h1>
<p>You searched for: {q}</p>
</body></html>"""
    return flask.Response(body, mimetype="text/html")


# ----------------------------------------------------------------------------
# 5. POST /login — SQL injection simulation
# ----------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if flask.request.method == "GET":
        return flask.Response(
            """<!doctype html><html><body>
<form method="POST" action="/login">
<input name="username" placeholder="username">
<input name="password" type="password">
<button>login</button>
</form>
</body></html>""",
            mimetype="text/html",
        )
    username = flask.request.form.get("username", "")
    password = flask.request.form.get("password", "")
    # Vulnerable: f-string interpolation into the "query" (simulated).
    where = f"username='{username}' AND password='{password}'"
    result = _fake_query_builder("users", where)
    resp = flask.make_response(
        flask.jsonify(
            {
                "query": result["sql"],
                "authenticated": result["auth_ok"],
                "row": result["row"],
                "sqli_bypass": result["sqli"],
            }
        )
    )
    if result["auth_ok"]:
        # Weak cookie: no HttpOnly, no Secure, no SameSite.
        resp.set_cookie(
            "session",
            str(result["row"]["id"]),
            path="/",
            httponly=False,
            secure=False,
            samesite=None,
        )
    return resp


# ----------------------------------------------------------------------------
# 6. GET /file?path=... — Path traversal (simulated)
# ----------------------------------------------------------------------------

@app.route("/file")
def file_endpoint():
    requested = flask.request.args.get("path", "")
    # The vulnerability is the naive os.path.join below.
    # SAFETY: we then constrain to the allowlist to avoid real traversal.
    naive_join = os.path.join(str(DATA_DIR), requested)
    resolved = os.path.normpath(naive_join)
    # Only serve files in the allowlist (real traversal blocked).
    name = os.path.basename(requested)
    safe_path = FILE_ALLOWLIST.get(name)
    # Detect traversal attempt for evidence.
    traversal_attempt = (
        ".." in requested
        or requested.startswith("/")
        or (resolved and not resolved.startswith(str(DATA_DIR)))
    )
    if safe_path is None or traversal_attempt:
        return (
            flask.jsonify(
                {
                    "requested": requested,
                    "blocked": True,
                    "reason": "traversal attempt detected" if traversal_attempt else "not in allowlist",
                    "hint": "this endpoint is vulnerable to path traversal if implemented naively",
                }
            ),
            404,
        )
    try:
        content = safe_path.read_text()
    except OSError as exc:
        return flask.jsonify({"error": str(exc)}), 500
    return flask.Response(content, mimetype="text/plain")


# ----------------------------------------------------------------------------
# 7. GET /api/data — CORS misconfig
# ----------------------------------------------------------------------------

@app.route("/api/data", methods=["GET", "OPTIONS"])
def api_data():
    if flask.request.method == "OPTIONS":
        # Echo the origin in ACAO for preflight; allow any header & method.
        origin = flask.request.headers.get("Origin", "*")
        resp = flask.make_response()
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Methods"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "*"
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Access-Control-Max-Age"] = "86400"
        return resp
    resp = flask.make_response(
        flask.jsonify({"items": [1, 2, 3], "secret": "demo-data", "ok": True})
    )
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


# ----------------------------------------------------------------------------
# 8. GET /redirect?to=... — Open redirect
# ----------------------------------------------------------------------------

@app.route("/redirect")
def open_redirect():
    target = flask.request.args.get("to", "/")
    # Vulnerable: no validation of the redirect target.
    return flask.redirect(target)


# ----------------------------------------------------------------------------
# 9. GET /debug — Information disclosure
# ----------------------------------------------------------------------------

@app.route("/debug")
def debug():
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append(
            {
                "rule": rule.rule,
                "endpoint": rule.endpoint,
                "methods": sorted(m for m in rule.methods if m not in {"HEAD", "OPTIONS"}),
            }
        )
    # Read the fake config "secret" (still fake).
    secret = "UNKNOWN"
    try:
        for line in (DATA_DIR / "config.ini").read_text().splitlines():
            if line.startswith("password"):
                secret = line.split("=", 1)[1].strip()
    except OSError:
        pass
    body = {
        "python_version": sys.version,
        "platform": platform.platform(),
        "flask_version": flask.__version__,
        "hostname": socket.gethostname(),
        "routes": routes,
        "config_secret": secret,
        "environment": dict(os.environ),
    }
    resp = flask.make_response(flask.jsonify(body))
    resp.headers["X-Powered-By"] = "Flask"
    resp.headers["Server"] = "redveil-lab/1.0"
    return resp


# ----------------------------------------------------------------------------
# 10. GET /server-status — Exposed management endpoint
# ----------------------------------------------------------------------------

@app.route("/server-status")
def server_status():
    # Static, fake Apache server-status output. The discovery check should
    # flag this as an exposed management panel.
    body = """Apache Server Status for 127.0.0.1 (127.0.0.1)

Server Version: Apache/2.4.51 (Lab simulation)
Server MPM: event
Server Built: 2024-01-15
Current Time: Monday, 01-Jan-2024 00:00:00 UTC
Restart Time: Monday, 01-Jan-2024 00:00:00 UTC
Parent Server Config. Generation: 1
Parent Server MPM Generation: 1

Server uptime: 1 day 0 hours 0 minutes 0 seconds
Requests/sec (avg): 0.1234
Bytes/sec (avg):  142B
Bytes/request (avg): 1152B

Srv    PID    Acc    M    CPU   SS    Req   Conn    Child    Slot    Client    VHost    Request
0-0    1234   0/42/42 W     0.00 124   0     0.0     0.00     142.11   127.0.0.1  redveil   GET / HTTP/1.1
"""
    return flask.Response(body, mimetype="text/plain")


# ----------------------------------------------------------------------------
# 11. POST /api/echo — Method confusion / overly permissive methods
# ----------------------------------------------------------------------------

@app.route("/api/echo", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def api_echo():
    body = flask.request.get_data(as_text=True) or ""
    return flask.jsonify(
        {
            "method": flask.request.method,
            "path": flask.request.path,
            "body": body,
            "headers": {k: v for k, v in flask.request.headers.items()},
        }
    )


# ----------------------------------------------------------------------------
# 12. GET /api/ping?host=... — Command injection (SAFE simulation)
# ----------------------------------------------------------------------------

SHELL_METACHARS = (";", "&", "|", "`", "$", "(", ")", "<", ">", "\n")


@app.route("/api/ping")
def api_ping():
    host = flask.request.args.get("host", "")
    # Vulnerable-looking: echo input verbatim. Do NOT execute commands.
    metachar_used = any(c in host for c in SHELL_METACHARS)
    if metachar_used:
        # SAFE time-based evidence (0.5s cap) so framework timing checks can
        # detect the attempt without real command execution.
        time.sleep(0.5)
        return flask.jsonify(
            {
                "echo": host,
                "executed": False,
                "blocked": True,
                "reason": "shell metacharacters detected - command execution disabled in lab",
                "note": "would be vulnerable to command injection if implemented naively",
            }
        )
    return flask.jsonify(
        {
            "echo": host,
            "executed": False,
            "fake_ping": f"PING {host} 56(84) bytes of data.\n64 bytes from {host}: icmp_seq=1 ttl=64 time=0.042 ms",
        }
    )


# ----------------------------------------------------------------------------
# 13. GET /api/version — API version disclosure
# ----------------------------------------------------------------------------

@app.route("/api/version")
def api_version():
    resp = flask.make_response(
        flask.jsonify({"api_version": "1.0", "deprecated": False, "endpoints": 17})
    )
    resp.headers["X-API-Version"] = "1.0"
    return resp


# ----------------------------------------------------------------------------
# 14. GET|POST /webhook — Webhook with token
# ----------------------------------------------------------------------------

WEBHOOK_TOKEN = "lab-test-token-12345"


@app.route("/webhook", methods=["GET", "POST"])
def webhook():
    token_q = flask.request.args.get("token", "")
    token_h = flask.request.headers.get("X-Webhook-Token", "")
    if token_q == WEBHOOK_TOKEN or token_h == WEBHOOK_TOKEN:
        return flask.jsonify({"ok": True, "token_match": True})
    return flask.jsonify({"ok": False, "token_match": False}), 401


# ----------------------------------------------------------------------------
# 15. GET /api/source-map — Exposed source map (fake)
# ----------------------------------------------------------------------------

@app.route("/api/source-map")
def api_source_map():
    fake_map = {
        "version": 3,
        "file": "app.bundle.js",
        "sourceRoot": "",
        "sources": ["webpack:///./src/app.ts", "webpack:///./src/api.ts"],
        "names": ["App", "fetch"],
        "mappings": "AAAA,SAAS,GAAG,CAAC;",
        "sourcesContent": [
            "export function App() { return 'redveil-lab'; }",
            "export async function fetch(url) { return globalThis.fetch(url); }",
        ],
        "note": "This is a fake source map used for the disclosure check.",
    }
    resp = flask.make_response(flask.jsonify(fake_map))
    resp.headers["Content-Type"] = "application/json"
    resp.headers["X-SourceMap"] = "app.bundle.js.map"
    return resp


# ----------------------------------------------------------------------------
# 16. GET|POST /api/graphql — GraphQL with introspection enabled
# ----------------------------------------------------------------------------

@app.route("/api/graphql", methods=["GET", "POST", "OPTIONS"])
def api_graphql():
    if flask.request.method == "GET":
        return flask.jsonify(
            {
                "graphql": True,
                "introspection_enabled": True,
                "schema_hint": "POST {\"query\":\"{ __schema { types { name } } }\"}",
            }
        )
    try:
        body = flask.request.get_json(force=True, silent=True) or {}
    except Exception:
        body = {}
    query = (body.get("query") or "").strip()
    if "__schema" in query and "types" in query:
        # Introspection response (truncated, real-looking).
        return flask.jsonify(
            {
                "data": {
                    "__schema": {
                        "types": [
                            {"name": "Query"},
                            {"name": "Mutation"},
                            {"name": "User"},
                            {"name": "Note"},
                            {"name": "Secret"},
                            {"name": "AdminSecret"},
                        ]
                    }
                }
            }
        )
    return flask.jsonify(
        {
            "data": {
                "users": [
                    {"id": 1, "name": "Alice"},
                    {"id": 2, "name": "Bob"},
                    {"id": 3, "name": "Admin"},
                ]
            }
        }
    )


# ----------------------------------------------------------------------------
# 17. Standard discovery endpoints
# ----------------------------------------------------------------------------

# ----------------------------------------------------------------------------
# 17. GET /login-insecure — Session cookie with multiple missing flags
# ----------------------------------------------------------------------------

@app.route("/login-insecure")
def login_insecure():
    resp = flask.make_response('<html><body>Logged in (insecurely)</body></html>')
    # No HttpOnly, no Secure, no SameSite — multiple issues
    resp.set_cookie('session', 'insecure_session_token_abc123', path='/')
    return resp


# ----------------------------------------------------------------------------
# 18. GET /login-https-only — Session cookie over HTTP (no Secure flag)
# ----------------------------------------------------------------------------

@app.route("/login-https-only")
def login_https_only():
    resp = flask.make_response('<html><body>Logged in (cookie without Secure)</body></html>')
    resp.set_cookie('session', 'Yk7_q2vN3xMzP9bL4cVwR8jT6sH1dF0gA', path='/', httponly=True, samesite='Strict')
    return resp


# ----------------------------------------------------------------------------
# 19. GET /login-weak-token — Session cookie with low-entropy token
# ----------------------------------------------------------------------------

@app.route("/login-weak-token")
def login_weak_token():
    resp = flask.make_response('<html><body>Logged in (weak token)</body></html>')
    # Predictable token — should trigger weak_token finding
    resp.set_cookie('session', 'abc123', path='/', httponly=True, secure=True, samesite='Strict')
    return resp


# ----------------------------------------------------------------------------
# 20. GET /login-vulnerable — Session cookie without HttpOnly (hardening gap)
# ----------------------------------------------------------------------------

@app.route("/login-vulnerable")
def login_vulnerable():
    resp = flask.make_response('<html><body>Logged in (vulnerable to XSS chain)</body></html>')
    # Cookie WITHOUT HttpOnly (so XSS could steal it) — but no XSS in this app
    # This tests the "hardening gap" finding
    resp.set_cookie('session', 'Yk7_q2vN3xMzP9bL4cVwR8jT6sH1dF0gA', path='/', secure=True, samesite='Strict')
    return resp


# ----------------------------------------------------------------------------
# 21. GET /xss-vulnerable?q=... — XSS reflection sink (chain with /login-vulnerable)
# ----------------------------------------------------------------------------

@app.route("/xss-vulnerable")
def xss_vulnerable():
    q = flask.request.args.get('q', '')
    # Reflects unescaped — simulates a real XSS sink
    return f'<html><body>You searched for: {q}</body></html>'


# ----------------------------------------------------------------------------
# 22. Standard discovery endpoints
# ----------------------------------------------------------------------------

@app.route("/robots.txt")
def robots():
    body = """User-agent: *
Disallow: /admin
Disallow: /debug
Disallow: /server-status
Disallow: /api/source-map
Allow: /
"""
    return flask.Response(body, mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap():
    body = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://127.0.0.1:5000/</loc></url>
  <url><loc>http://127.0.0.1:5000/api/profile</loc></url>
  <url><loc>http://127.0.0.1:5000/search</loc></url>
  <url><loc>http://127.0.0.1:5000/api/data</loc></url>
  <url><loc>http://127.0.0.1:5000/api/version</loc></url>
</urlset>
"""
    return flask.Response(body, mimetype="application/xml")


# ----------------------------------------------------------------------------
# Error handlers
# ----------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(_):
    return flask.jsonify({"error": "not found", "path": flask.request.path}), 404


@app.errorhandler(500)
def server_error(exc):
    # In debug mode Flask renders its own traceback, but we provide a hint
    # in JSON for non-debug contexts.
    return flask.jsonify({"error": "server error", "type": type(exc).__name__}), 500


# ----------------------------------------------------------------------------
# Entrypoint
# ----------------------------------------------------------------------------

if __name__ == "__main__":
    # Bind ONLY to loopback. Do NOT change this.
    host = os.environ.get("LAB_HOST", "127.0.0.1")
    port = int(os.environ.get("LAB_PORT", "5000"))
    # LAB_FAST=1 disables debug mode + threaded server — used by the E2E
    # tests to keep the scan quick. Debug=False still leaks X-Powered-By
    # (we set it manually on the /debug route anyway).
    fast = os.environ.get("LAB_FAST", "") == "1"
    debug = not fast
    app.debug = debug
    threaded = fast  # serve concurrent requests when not in debug mode
    print(
        f"[redveil-lab] starting on http://{host}:{port} (debug={debug}, threaded={threaded})",
        flush=True,
    )
    app.run(host=host, port=port, debug=debug, use_reloader=False, threaded=threaded)
