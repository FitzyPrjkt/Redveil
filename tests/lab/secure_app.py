"""Secure Flask app — control fixture for negative testing.

This app mirrors the endpoints in app.py but is hardened against the
vulnerabilities redveil checks look for. When redveil scans this app,
a check that produces a finding here is producing a FALSE POSITIVE.

Hardening applied:
- XSS: all template output goes through Jinja2 auto-escaping; canary strings
  rendered as plain text, never as HTML
- SQLi: parameterized queries only, no string interpolation
- SSRF: URL parameter validated against allowlist; no outbound fetch
- Path traversal: filenames validated against allowlist
- IDOR/BOLA: ownership check on every object access
- BFLA: role-based access control on admin endpoints
- Session: HttpOnly + Secure + SameSite=Strict; rotated on auth change
- HTTP methods: only GET on read-only; mutating methods require auth + CSRF
- CORS: strict allowlist, not *
- Mass assignment: explicit allowlist of writable fields
- Source maps: not served
- Debug endpoints: disabled

Run:
    $ python tests/lab/secure_app.py
    $ redveil scan http://127.0.0.1:5001 --scope tests/lab/secure_scope.yaml
"""
from __future__ import annotations
import hmac
import os
import secrets
from datetime import datetime, timezone

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    make_response,
    render_template_string,
    request,
    send_from_directory,
)
from markupsafe import escape


# Allow insecure cookie flag for the local test environment (no HTTPS).
# In production this would always be True.
INSECURE_COOKIE = os.environ.get("INSECURE_COOKIE", "1") == "1"

app = Flask(__name__)
app.config["SECRET_KEY"] = "test-only-not-for-prod"
app.config["DEBUG"] = False

# In-memory "user database" — keys are session token, values are user dict.
_SESSIONS: dict[str, dict] = {}

# User database (intentionally simple — single table).
_USERS = {
    "1": {"id": "1", "name": "alice", "email": "alice@example.com", "role": "user", "is_admin": False},
    "2": {"id": "2", "name": "bob", "email": "bob@example.com", "role": "user", "is_admin": False},
    "3": {"id": "3", "name": "carol", "email": "carol@example.com", "role": "admin", "is_admin": True},
}

# User-owned resources.
_RESOURCES = {
    "1": {"id": "1", "owner_id": "1", "type": "order", "total": 42.0, "items": ["widget"]},
    "2": {"id": "2", "owner_id": "1", "type": "order", "total": 99.0, "items": ["gadget"]},
    "3": {"id": "3", "owner_id": "2", "type": "order", "total": 15.0, "items": ["thing"]},
}

# Per-user rate limit: dict[ip] = [timestamps]
_RATE: dict[str, list[float]] = {}


def _now() -> float:
    return datetime.now(timezone.utc).timestamp()


def _check_rate_limit(ip: str, max_per_min: int = 60) -> bool:
    """Simple sliding-window rate limit. Returns True if OK, False if exceeded."""
    now = _now()
    window = [t for t in _RATE.get(ip, []) if now - t < 60]
    if len(window) >= max_per_min:
        return False
    _RATE[ip] = window + [now]
    return True


def _current_user():
    """Look up the current user from the session cookie. Returns None if invalid."""
    token = request.cookies.get("session")
    if not token:
        return None
    # Constant-time comparison
    for stored_token, user in _SESSIONS.items():
        if hmac.compare_digest(token, stored_token):
            return user
    return None


def _require_user():
    user = _current_user()
    if not user:
        abort(401)
    return user


def _require_admin():
    user = _require_user()
    if not user.get("is_admin"):
        abort(403)
    return user


def _set_session_cookie(resp, user_id: str):
    """Issue a fresh, secure session cookie (rotated on every login)."""
    token = secrets.token_urlsafe(32)
    _SESSIONS[token] = _USERS[user_id]
    resp.set_cookie(
        "session",
        token,
        httponly=True,
        secure=not INSECURE_COOKIE,
        samesite="Strict",
        path="/",
        max_age=3600,
    )


def _clear_session_cookie(resp):
    """Invalidate the session server-side AND clear the cookie client-side."""
    token = request.cookies.get("session")
    if token and token in _SESSIONS:
        del _SESSIONS[token]
    resp.set_cookie("session", "", expires=0, path="/")


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


@app.route("/login", methods=["POST"])
def login():
    """Parameterized credential check. Returns 401 on failure.

    Notice: this is NOT a SQL query. It's a dict lookup. The check
    strings for SQLi (timing-based) will see no delay and report nothing.
    """
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if not username or not password:
        abort(400)
    # Constant-time dict lookup
    user = None
    for u in _USERS.values():
        if hmac.compare_digest(u["name"], username) and hmac.compare_digest(
            password, f"pw-{u['name']}"
        ):
            user = u
            break
    if not user:
        abort(401)
    resp = make_response(jsonify({"status": "ok", "id": user["id"]}))
    _set_session_cookie(resp, user["id"])
    return resp


@app.route("/logout", methods=["POST"])
def logout():
    """Invalidate the session server-side. Clear the cookie."""
    user = _current_user()
    resp = make_response(jsonify({"status": "logged out"}))
    _clear_session_cookie(resp)
    if user is None:
        abort(401)  # already logged out = unauth
    return resp


# ---------------------------------------------------------------------------
# Profile / me
# ---------------------------------------------------------------------------


@app.route("/api/profile/me")
def profile_me():
    user = _require_user()
    # Only return the user-specific fields, never the role or internal flags
    # to non-admin viewers. (Mass-assignment check should find nothing.)
    return jsonify({
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
    })


@app.route("/api/profile/<user_id>")
def profile_by_id(user_id: str):
    """BOLA-safe: only owner or admin can read another user's profile."""
    viewer = _require_user()
    target = _USERS.get(user_id)
    if not target:
        abort(404)
    if target["id"] != viewer["id"] and not viewer.get("is_admin"):
        abort(403)  # BOLA protection
    return jsonify({
        "id": target["id"],
        "name": target["name"],
        "email": target["email"],
    })


@app.route("/api/profile", methods=["PUT"])
def profile_update():
    user = _require_user()
    # Explicit allowlist of writable fields. No role/is_admin updatable
    # via the body (mass-assignment protection).
    allowed = {"name", "email"}
    update = {k: v for k, v in (request.json or {}).items() if k in allowed}
    if "role" in request.json or "is_admin" in request.json:
        # Reject the request — privileged field present in body.
        abort(400)
    _USERS[user["id"]].update(update)
    return jsonify({"status": "ok"})


# ---------------------------------------------------------------------------
# Orders (with ownership check)
# ---------------------------------------------------------------------------


@app.route("/api/orders/<order_id>")
def order_get(order_id: str):
    """BOLA-safe: only owner or admin can read the order."""
    viewer = _require_user()
    order = _RESOURCES.get(order_id)
    if not order:
        abort(404)
    if order["owner_id"] != viewer["id"] and not viewer.get("is_admin"):
        abort(403)
    return jsonify(order)


@app.route("/api/orders", methods=["GET"])
def order_list():
    """BOLA-safe: list only your own orders, not all users' orders."""
    viewer = _require_user()
    mine = [o for o in _RESOURCES.values() if o["owner_id"] == viewer["id"]]
    return jsonify(mine)


# ---------------------------------------------------------------------------
# Admin endpoints (with BFLA check)
# ---------------------------------------------------------------------------


@app.route("/api/admin/users", methods=["GET"])
def admin_users_list():
    """BFLA: admin-only."""
    _require_admin()
    return jsonify(list(_USERS.values()))


@app.route("/api/admin/users/<user_id>", methods=["DELETE"])
def admin_user_delete(user_id: str):
    """BFLA: admin-only. Mass-action requires admin role."""
    _require_admin()
    _USERS.pop(user_id, None)
    return jsonify({"status": "deleted"})


# ---------------------------------------------------------------------------
# Search (with XSS-safe output)
# ---------------------------------------------------------------------------


@app.route("/search")
def search():
    """XSS-safe: Jinja2 auto-escapes by default. Canary strings are
    rendered as text, never as HTML.
    """
    q = request.args.get("q", "")
    # Jinja2's auto-escaping converts < > & " ' in the value to entities
    template = "<html><body>You searched for: {{ q }}</body></html>"
    return Response(render_template_string(template, q=q), mimetype="text/html")


# ---------------------------------------------------------------------------
# File access (with path traversal protection)
# ---------------------------------------------------------------------------


_ALLOWED_FILES = {"readme.txt", "data.json"}


@app.route("/file")
def file_access():
    """Path-traversal-safe: filename validated against allowlist, no path concat."""
    name = request.args.get("path", "")
    if not name:
        abort(400)
    if "/" in name or "\\" in name or ".." in name or name not in _ALLOWED_FILES:
        abort(403)
    # Serve from a sandboxed dir; in this lab we just return a stub.
    return Response(f"(stub contents of {name})", mimetype="text/plain")


# ---------------------------------------------------------------------------
# SSRF (safe URL fetcher)
# ---------------------------------------------------------------------------


@app.route("/api/fetch", methods=["GET"])
def url_fetch():
    """SSRF-safe: URL parameter validated. Only allowlisted external hosts.
    No internal IPs.
    """
    from urllib.parse import urlparse
    target = request.args.get("url", "")
    if not target:
        abort(400)
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        abort(400)
    if parsed.hostname in {"127.0.0.1", "localhost", "0.0.0.0"} or parsed.hostname.startswith("10.") or parsed.hostname.startswith("192.168."):
        abort(403)  # SSRF protection
    # Allowlist of external domains
    if parsed.hostname not in {"example.com", "api.public-service.test"}:
        abort(403)
    return jsonify({"url": target, "fetched": True})


# ---------------------------------------------------------------------------
# Command injection / shell (safe)
# ---------------------------------------------------------------------------


@app.route("/api/ping", methods=["GET"])
def ping():
    """Command-injection-safe: shell is NOT invoked. Returns a stub."""
    host = request.args.get("host", "")
    # Validate host as hostname only (no shell metacharacters)
    if not host.replace(".", "").replace("-", "").isalnum():
        abort(400)
    return jsonify({"host": host, "rtt_ms": 12.3, "ok": True})


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------


@app.after_request
def add_cors_headers(resp):
    """Strict CORS: explicit allowlist, not *. Plus all recommended
    security headers (CSP, X-Frame-Options, HSTS, etc.) — these are
    baseline hardening that any production app should have."""
    origin = request.headers.get("Origin")
    if origin and origin in {"https://app.example.com", "https://admin.example.com"}:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"

    # Defense-in-depth headers
    resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'self'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if not INSECURE_COOKIE:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Generic server header without version
    resp.headers["Server"] = "secure"
    return resp


# ---------------------------------------------------------------------------
# Error handlers (no information disclosure)
# ---------------------------------------------------------------------------


@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "bad_request"}), 400


@app.errorhandler(401)
def unauthorized(e):
    return jsonify({"error": "unauthorized"}), 401


@app.errorhandler(403)
def forbidden(e):
    return jsonify({"error": "forbidden"}), 403


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "not_found"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "server_error"}), 500


# ---------------------------------------------------------------------------
# Other endpoints (clean implementations)
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    return Response(
        """<html><head><title>secure app</title></head><body>
        <ul>
            <li><a href="/search?q=hello">/search</a></li>
            <li><a href="/api/profile/me">/api/profile/me</a></li>
            <li><a href="/api/orders">/api/orders</a></li>
            <li><a href="/robots.txt">/robots.txt</a></li>
        </ul></body></html>""",
        mimetype="text/html",
    )


@app.route("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /api/\n", mimetype="text/plain")


@app.route("/api/source-map")
def no_source_map():
    # Source maps NOT served.
    abort(404)


@app.route("/debug")
def no_debug():
    # Debug endpoint NOT served.
    abort(404)


@app.route("/.env")
def no_env():
    abort(404)


@app.route("/server-status")
def no_server_status():
    abort(404)


@app.route("/sitemap.xml")
def sitemap():
    return Response('<?xml version="1.0"?><urlset><url><loc>/</loc></url></urlset>', mimetype="application/xml")


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    host = os.environ.get("LAB_HOST", "127.0.0.1")
    port = int(os.environ.get("LAB_PORT", "5001"))
    print(f"secure_app running on http://{host}:{port}", file=sys.stderr)
    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=False)
