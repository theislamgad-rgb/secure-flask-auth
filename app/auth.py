"""Registration, login, logout and a protected dashboard."""
import functools
import re
from datetime import datetime, timedelta, timezone

from flask import (Blueprint, current_app, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from .db import get_db

bp = Blueprint("auth", __name__)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")

# Hash checked when the username does not exist, so "unknown user" and
# "wrong password" take similar time and give the same answer.
_DUMMY_HASH = generate_password_hash("not-a-real-password")


def _now():
    return datetime.now(timezone.utc)


def _audit(event, username=None):
    get_db().execute(
        "INSERT INTO audit_log (event, username, ip) VALUES (?, ?, ?)",
        (event, username, request.remote_addr),
    )
    get_db().commit()


def validate_password(password, username=""):
    """Return a list of problems (empty list means acceptable)."""
    problems = []
    if len(password) < current_app.config["MIN_PASSWORD_LENGTH"]:
        problems.append(
            f"Password must be at least {current_app.config['MIN_PASSWORD_LENGTH']} characters."
        )
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        problems.append("Password must contain letters and digits.")
    if username and username.lower() in password.lower():
        problems.append("Password must not contain the username.")
    return problems


def login_required(view):
    @functools.wraps(view)
    def wrapped(**kwargs):
        if g.user is None:
            return redirect(url_for("auth.login"))
        return view(**kwargs)

    return wrapped


@bp.before_app_request
def load_user():
    user_id = session.get("user_id")
    g.user = (
        None
        if user_id is None
        else get_db().execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()
    )


@bp.route("/register", methods=("GET", "POST"))
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        errors = []
        if not USERNAME_RE.match(username):
            errors.append("Username must be 3-32 characters: letters, digits, _ . -")
        errors += validate_password(password, username)

        if not errors:
            try:
                get_db().execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password)),  # salted scrypt
                )
                get_db().commit()
            except Exception:  # sqlite3.IntegrityError: username taken
                errors.append("That username is not available.")
            else:
                _audit("register", username)
                flash("Account created. Please sign in.")
                return redirect(url_for("auth.login"))
        for e in errors:
            flash(e)
    return render_template("register.html")


@bp.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        # 1. Account lockout check (applies even if the password is right).
        if user and user["locked_until"]:
            if datetime.fromisoformat(user["locked_until"]) > _now():
                _audit("login_blocked_locked", username)
                flash("Too many failed attempts. Try again later.")
                return render_template("login.html"), 429

        # 2. Verify password; same work and same message for unknown users.
        ok = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password)

        if user and ok:
            db.execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?",
                       (user["id"],))
            db.commit()
            session.clear()  # new session on login: prevents session fixation
            session["user_id"] = user["id"]
            session.permanent = True
            _audit("login_success", username)
            return redirect(url_for("auth.dashboard"))

        if user:
            failures = user["failed_logins"] + 1
            locked_until = None
            if failures >= current_app.config["MAX_FAILED_LOGINS"]:
                locked_until = (_now() + timedelta(minutes=current_app.config["LOCKOUT_MINUTES"])).isoformat()
                failures = 0
            db.execute("UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?",
                       (failures, locked_until, user["id"]))
            db.commit()
        _audit("login_failed", username)
        flash("Invalid username or password.")  # deliberately generic
        return render_template("login.html"), 401
    return render_template("login.html")


@bp.route("/logout", methods=("POST",))  # POST + CSRF token: logout cannot be forced by a link
def logout():
    session.clear()
    return redirect(url_for("auth.login"))


@bp.route("/")
@bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")
