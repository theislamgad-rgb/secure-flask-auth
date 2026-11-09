import sqlite3

from app import create_app
from conftest import get_token, login, register


def test_dashboard_requires_login(client):
    r = client.get("/dashboard")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_register_and_login_flow(client):
    assert register(client).status_code == 302
    r = login(client)
    assert r.status_code == 302 and r.headers["Location"].endswith("/dashboard")
    assert b"Welcome, alice" in client.get("/dashboard").data


def test_password_is_hashed_not_stored_plaintext(app, client):
    register(client, password="correct-horse-42")
    row = sqlite3.connect(app.config["DATABASE"]).execute(
        "SELECT password_hash FROM users WHERE username='alice'").fetchone()
    assert "correct-horse-42" not in row[0]
    assert row[0].startswith(("scrypt:", "pbkdf2:"))


def test_weak_passwords_rejected(client):
    for pw in ("short1", "alllettersnodigits", "123456789012345"):
        r = register(client, username="bob", password=pw)
        assert r.status_code == 200  # form re-rendered, no redirect
    r = register(client, username="bob", password="bobbobbob12345")  # contains username
    assert r.status_code == 200


def test_duplicate_username_rejected(client):
    register(client)
    assert register(client).status_code == 200


def test_wrong_password_and_unknown_user_look_identical(client):
    register(client)
    a = login(client, "alice", "wrong-password-1")
    b = login(client, "nobody", "wrong-password-1")
    # Same status and same message, so an attacker can't enumerate valid usernames.
    assert a.status_code == b.status_code == 401
    assert b"Invalid username or password." in a.data
    assert b"Invalid username or password." in b.data


def test_account_lockout_after_repeated_failures(app, client):
    register(client)
    for _ in range(app.config["MAX_FAILED_LOGINS"]):
        login(client, "alice", "wrong-password-1")
    # Even the correct password is refused while locked.
    r = login(client, "alice", "correct-horse-42")
    assert r.status_code == 429


def test_csrf_required_on_post(client):
    r = client.post("/login", data={"username": "alice", "password": "x"})
    assert r.status_code == 400
    r = client.post("/login", data={"username": "alice", "password": "x", "csrf_token": "forged"})
    assert r.status_code == 400


def test_logout_is_post_only_and_clears_session(client):
    register(client)
    login(client)
    assert client.get("/logout").status_code == 405
    client.post("/logout", data={"csrf_token": get_token(client, "/dashboard")})
    assert client.get("/dashboard").status_code == 302


def test_security_headers_present(client):
    h = client.get("/login").headers
    assert "default-src 'self'" in h["Content-Security-Policy"]
    assert h["X-Content-Type-Options"] == "nosniff"
    assert h["X-Frame-Options"] == "DENY"
    assert h["Cache-Control"] == "no-store"


def test_session_cookie_flags(app):
    secure_app = create_app({"TESTING": True, "SECRET_KEY": "k",
                             "DATABASE": app.config["DATABASE"],
                             "SESSION_COOKIE_SECURE": True})
    c = secure_app.test_client()
    cookie = c.get("/login", base_url="https://localhost").headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=Lax" in cookie


def test_sql_injection_in_login_does_not_bypass_auth(client):
    register(client)
    r = login(client, "alice' OR '1'='1' --", "anything-at-all-1")
    assert r.status_code == 401


def test_xss_in_username_is_escaped_on_dashboard(client):
    # Usernames are validated, so the payload can't register at all.
    r = register(client, username="<script>alert(1)</script>", password="correct-horse-42")
    assert r.status_code == 200
    assert b"<script>alert(1)</script>" not in r.data
