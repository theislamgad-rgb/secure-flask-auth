"""Cross-cutting security controls: CSRF protection and response headers."""
import hmac
import secrets

from flask import abort, request, session

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# Content-Security-Policy: only same-origin resources, no inline script/style,
# no framing, no plugins, forms may only submit back to this origin.
CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'self'"
)


def csrf_token():
    """Return the per-session CSRF token, creating it on first use."""
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


def _check_csrf():
    if request.method in SAFE_METHODS:
        return
    sent = request.form.get("csrf_token", "")
    expected = session.get("_csrf", "")
    # Constant-time comparison; reject if the session has no token at all.
    if not expected or not hmac.compare_digest(sent, expected):
        abort(400, description="Invalid or missing CSRF token.")


def _add_headers(response):
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # Pages can contain account data; keep them out of shared/browser caches.
    response.headers["Cache-Control"] = "no-store"
    return response


def init_app(app):
    app.before_request(_check_csrf)
    app.after_request(_add_headers)
    app.jinja_env.globals["csrf_token"] = csrf_token
