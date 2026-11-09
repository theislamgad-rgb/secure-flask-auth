"""Secure Flask authentication demo: application factory."""
import os
import secrets
from datetime import timedelta

from flask import Flask

from . import auth, db, security


def create_app(test_config=None):
    app = Flask(__name__)

    app.config.update(
        # In production set SECRET_KEY in the environment. The random fallback
        # keeps local dev working but invalidates sessions on every restart.
        SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        DATABASE=os.environ.get("DATABASE", os.path.join(app.instance_path, "app.sqlite")),
        # Cookie hardening
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        # Set SECURE_COOKIES=0 only for local http:// development.
        SESSION_COOKIE_SECURE=os.environ.get("SECURE_COOKIES", "1") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        # Brute-force protection
        MAX_FAILED_LOGINS=5,
        LOCKOUT_MINUTES=5,
        MIN_PASSWORD_LENGTH=12,
        # Reject oversized request bodies
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if test_config:
        app.config.update(test_config)

    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)
    security.init_app(app)
    app.register_blueprint(auth.bp)
    return app
