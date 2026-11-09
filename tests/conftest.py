import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app  # noqa: E402


@pytest.fixture()
def app(tmp_path):
    return create_app({
        "TESTING": True,
        "DATABASE": str(tmp_path / "test.sqlite"),
        "SECRET_KEY": "test-key",
        "SESSION_COOKIE_SECURE": False,  # test client uses http://
    })


@pytest.fixture()
def client(app):
    return app.test_client()


def get_token(client, path="/login"):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def register(client, username="alice", password="correct-horse-42"):
    return client.post("/register", data={
        "username": username, "password": password,
        "csrf_token": get_token(client, "/register")})


def login(client, username="alice", password="correct-horse-42"):
    return client.post("/login", data={
        "username": username, "password": password,
        "csrf_token": get_token(client, "/login")})
