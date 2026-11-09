"""SQL injection: vulnerable query vs. parameterised query.

Self-contained teaching demo. It uses an in-memory SQLite database, so there is
no server to attack and nothing to deploy. Run:  python demos/sqli_demo.py
"""
import hashlib
import sqlite3


def _hash(password: str) -> str:
    # Demo only. The real app uses salted scrypt via werkzeug (see app/auth.py).
    return hashlib.sha256(password.encode()).hexdigest()


def make_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (username TEXT, password_hash TEXT, role TEXT)")
    conn.executemany(
        "INSERT INTO users VALUES (?, ?, ?)",
        [("admin", _hash("S3cret-admin-pw"), "admin"), ("alice", _hash("alice-pw-123"), "user")],
    )
    return conn


def login_vulnerable(conn, username: str, password: str):
    """VULNERABLE: user input is concatenated into the SQL string."""
    query = (
        f"SELECT username, role FROM users "
        f"WHERE username = '{username}' AND password_hash = '{_hash(password)}'"
    )
    return conn.execute(query).fetchone()


def login_fixed(conn, username: str, password: str):
    """FIXED: bound parameters keep data separate from SQL code."""
    return conn.execute(
        "SELECT username, role FROM users WHERE username = ? AND password_hash = ?",
        (username, _hash(password)),
    ).fetchone()


if __name__ == "__main__":
    conn = make_db()
    payload = "admin' --"  # closes the string and comments out the password check
    print("Legitimate login (alice):       ", login_vulnerable(conn, "alice", "alice-pw-123"))
    print("Injection against VULNERABLE:   ", login_vulnerable(conn, payload, "wrong-password"))
    print("Injection against FIXED:        ", login_fixed(conn, payload, "wrong-password"))
