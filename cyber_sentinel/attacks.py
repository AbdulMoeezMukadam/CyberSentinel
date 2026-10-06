"""Vulnerability detection checks for CyberSentinel.

Each public ``*_attack`` function takes no arguments and returns a list of
*check callables*. A check callable has the signature ``check(page, client,
log)`` and records any findings on ``log``.

Design notes
------------
These checks are detection-oriented and deliberately conservative. They use
unique, harmless marker strings and single probe requests per parameter so
the tool behaves like a scanner (confirming whether an input is handled
safely) rather than an exploitation framework. Run it only against systems
you are authorized to test.
"""
from __future__ import unicode_literals

import re
import uuid

from .client import NotAPage, RedirectedToExternal
from .utils import set_query_param, add_duplicate_param

# A unique, inert marker so reflections are unambiguous and traceable.
MARKER = "czs" + uuid.uuid4().hex[:8]

# Signatures of database error messages (indicates unsanitised input).
SQL_ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",
    r"warning:\s+mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg::syntaxerror",
    r"sqlite3::",
    r"ora-\d{5}",
    r"odbc sql server driver",
    r"supplied argument is not a valid mysql",
]
SQL_ERROR_RE = re.compile("|".join(SQL_ERROR_SIGNATURES), re.I)

# Markers a directory listing page typically contains.
DIR_LISTING_RE = re.compile(r"<title>\s*index of /|directory listing for", re.I)

# File-inclusion signatures (content that indicates a server file was read).
LFI_SIGNATURES = re.compile(r"root:.*:0:0:|\[extensions\]|[a-z]+:x:\d+:\d+:", re.I)


def _iter_param_targets(page):
    """Yield (url, param_name) pairs worth probing on this page.

    Covers both the page's own query-string params and GET-form inputs.
    """
    for name in page.query_params:
        yield page.url, name
    for form in page.forms:
        if form.method == "get":
            for name in form.input_names:
                # Probe the form action with the input as a query param.
                yield form.action, name


def _safe_get(client, url):
    try:
        return client.raw_get(url)
    except (NotAPage, RedirectedToExternal, Exception):
        return None


# --------------------------------------------------------------------------- #
# Individual checks
# --------------------------------------------------------------------------- #
def check_xss(page, client, log):
    """Reflected-XSS indicator: does a unique marker come back un-encoded?"""
    probe = "<{}>".format(MARKER)
    for url, name in _iter_param_targets(page):
        test_url = set_query_param(url, name, probe)
        resp = _safe_get(client, test_url)
        if resp and probe in (resp.text or ""):
            log.high(
                "Possible Reflected XSS",
                test_url,
                detail="Parameter '{}' reflected an un-encoded marker in the "
                "response body.".format(name),
                evidence=probe,
                recommendation="Context-aware output encoding, a strict "
                "Content-Security-Policy, and input validation.",
            )


def check_sql_error(page, client, log):
    """SQL error-based indicator: a lone quote surfacing a DB error."""
    for url, name in _iter_param_targets(page):
        test_url = set_query_param(url, name, "'")
        resp = _safe_get(client, test_url)
        if resp and SQL_ERROR_RE.search(resp.text or ""):
            m = SQL_ERROR_RE.search(resp.text)
            log.high(
                "Possible SQL Injection (error-based)",
                test_url,
                detail="Parameter '{}' produced a database error message.".format(name),
                evidence=m.group(0) if m else None,
                recommendation="Use parameterized queries / prepared "
                "statements and suppress verbose DB errors.",
            )


def check_hpp(page, client, log):
    """HTTP Parameter Pollution: does a duplicated param change the response?"""
    for url, name in _iter_param_targets(page):
        base = _safe_get(client, set_query_param(url, name, MARKER + "a"))
        dup = _safe_get(client, add_duplicate_param(url, name, MARKER + "b"))
        if base is None or dup is None:
            continue
        if (MARKER + "b") in (dup.text or "") and (MARKER + "a") not in (dup.text or ""):
            log.low(
                "Possible HTTP Parameter Pollution",
                dup.url,
                detail="Duplicated parameter '{}' appears to override the "
                "first occurrence.".format(name),
                recommendation="Normalize/validate duplicate parameters "
                "server-side and reject unexpected repeats.",
            )


def check_crlf(page, client, log):
    """CRLF-injection indicator via a response-splitting marker in a param."""
    payload = "%0d%0aX-Czs-Test:{}".format(MARKER)
    for url, name in _iter_param_targets(page):
        test_url = set_query_param(url, name, payload)
        resp = _safe_get(client, test_url)
        if resp and resp.headers.get("X-Czs-Test") == MARKER:
            log.medium(
                "Possible CRLF / HTTP Response Splitting",
                test_url,
                detail="Parameter '{}' allowed injection of a response "
                "header.".format(name),
                recommendation="Strip CR/LF from user input used in headers; "
                "use framework APIs that encode header values.",
            )


def check_lfi(page, client, log):
    """Local File Inclusion indicator using a benign traversal probe."""
    probe = "../../../../etc/passwd"
    for url, name in _iter_param_targets(page):
        test_url = set_query_param(url, name, probe)
        resp = _safe_get(client, test_url)
        if resp and LFI_SIGNATURES.search(resp.text or ""):
            log.high(
                "Possible Local File Inclusion / Path Traversal",
                test_url,
                detail="Parameter '{}' returned content resembling a system "
                "file.".format(name),
                recommendation="Never pass user input to file paths; use "
                "allow-lists and canonicalize/validate paths.",
            )


def check_csrf(page, client, log):
    """CSRF indicator: state-changing forms without an anti-CSRF token."""
    token_hint = re.compile(r"csrf|token|nonce|authenticity", re.I)
    for form in page.forms:
        if form.method != "post":
            continue
        has_token = any(token_hint.search(n or "") for n in form.input_names)
        if not has_token:
            log.medium(
                "Form without anti-CSRF token",
                form.action,
                detail="A POST form has no field that looks like a CSRF "
                "token (fields: {}).".format(", ".join(form.input_names) or "none"),
                recommendation="Add per-session CSRF tokens and set cookies "
                "with SameSite=Lax/Strict.",
            )


def check_directory_listing(page, client, log):
    """Directory listing indicator on the page and common parent paths."""
    if DIR_LISTING_RE.search(page.text or ""):
        log.medium(
            "Directory listing enabled",
            page.url,
            detail="The server returned an auto-generated directory index.",
            recommendation="Disable automatic directory indexing "
            "(e.g. 'Options -Indexes' / autoindex off).",
        )


def check_breach(page, client, log):
    """Missing transport / hardening headers that aid data exposure."""
    headers = {k.lower(): v for k, v in page.headers.items()}
    if page.url.startswith("https://") and "strict-transport-security" not in headers:
        log.low(
            "Missing HSTS header",
            page.url,
            detail="No Strict-Transport-Security header on an HTTPS response.",
            recommendation="Send Strict-Transport-Security with a long "
            "max-age (and includeSubDomains where appropriate).",
        )
    if "x-content-type-options" not in headers:
        log.low(
            "Missing X-Content-Type-Options",
            page.url,
            detail="Responses may be MIME-sniffed by browsers.",
            recommendation="Send 'X-Content-Type-Options: nosniff'.",
        )
    if "content-security-policy" not in headers:
        log.low(
            "Missing Content-Security-Policy",
            page.url,
            detail="No CSP header, reducing defense-in-depth against "
            "injection.",
            recommendation="Define a restrictive Content-Security-Policy.",
        )


def check_clickjack(page, client, log):
    """Clickjacking indicator: no framing protection."""
    headers = {k.lower(): v for k, v in page.headers.items()}
    xfo = headers.get("x-frame-options")
    csp = headers.get("content-security-policy", "")
    if not xfo and "frame-ancestors" not in csp.lower():
        log.medium(
            "Clickjacking: no framing protection",
            page.url,
            detail="Neither X-Frame-Options nor CSP frame-ancestors is set.",
            recommendation="Set 'X-Frame-Options: DENY' (or SAMEORIGIN) and/or "
            "CSP 'frame-ancestors'.",
        )


def check_cookies(page, client, log):
    """Cookie hardening: Secure / HttpOnly / SameSite flags."""
    for cookie in page.cookies:
        issues = []
        if not cookie.secure:
            issues.append("Secure")
        rest = getattr(cookie, "_rest", {}) or {}
        rest_lower = {k.lower(): v for k, v in rest.items()}
        if "httponly" not in rest_lower:
            issues.append("HttpOnly")
        if "samesite" not in rest_lower:
            issues.append("SameSite")
        if issues:
            log.low(
                "Cookie missing security flags",
                page.url,
                detail="Cookie '{}' is missing: {}.".format(
                    cookie.name, ", ".join(issues)
                ),
                recommendation="Set Secure, HttpOnly, and SameSite on "
                "session cookies.",
            )


# --------------------------------------------------------------------------- #
# Attack "groups" referenced by main.py's menu
# --------------------------------------------------------------------------- #
def xss_attack():
    return [check_xss]


def hpp_attack():
    return [check_hpp]


def sql_error_attack():
    return [check_sql_error]


def csrf_attack():
    return [check_csrf]


def crlf_attack():
    return [check_crlf]


def lfi_attack():
    return [check_lfi]


def directory_listing_attack():
    return [check_directory_listing]


def breach_attack():
    return [check_breach]


def clickjack_attack():
    return [check_clickjack]


def cookiescan_attack():
    return [check_cookies]


def all_attacks():
    return [
        check_xss,
        check_sql_error,
        check_hpp,
        check_csrf,
        check_crlf,
        check_lfi,
        check_directory_listing,
        check_breach,
        check_clickjack,
        check_cookies,
    ]


__all__ = [
    "all_attacks", "xss_attack", "hpp_attack", "sql_error_attack",
    "csrf_attack", "crlf_attack", "lfi_attack", "directory_listing_attack",
    "breach_attack", "clickjack_attack", "cookiescan_attack",
]
