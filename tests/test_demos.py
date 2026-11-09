import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "demos"))

import sqli_demo  # noqa: E402
import xss_demo  # noqa: E402


def test_sqli_vulnerable_version_is_bypassed():
    conn = sqli_demo.make_db()
    assert sqli_demo.login_vulnerable(conn, "admin' --", "wrong") == ("admin", "admin")


def test_sqli_fixed_version_rejects_payload():
    conn = sqli_demo.make_db()
    assert sqli_demo.login_fixed(conn, "admin' --", "wrong") is None


def test_both_versions_accept_legitimate_login():
    conn = sqli_demo.make_db()
    expected = ("alice", "user")
    assert sqli_demo.login_vulnerable(conn, "alice", "alice-pw-123") == expected
    assert sqli_demo.login_fixed(conn, "alice", "alice-pw-123") == expected


def test_xss_vulnerable_template_emits_raw_markup():
    out = xss_demo.render_vulnerable('<img src=x onerror="alert(1)">')
    assert '<img src=x onerror="alert(1)">' in out


def test_xss_fixed_template_escapes_markup():
    out = xss_demo.render_fixed('<img src=x onerror="alert(1)">')
    assert "<img" not in out and "&lt;img" in out
