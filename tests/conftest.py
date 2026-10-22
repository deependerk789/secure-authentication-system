"""Shared pytest fixtures."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

# Keep the real environment out of the way: the tests must never send mail or
# read a developer's .env file.
os.environ["SECRET_KEY"] = "test-secret-key-" + ("a" * 40)
os.environ.pop("PRODUCTION", None)
os.environ.pop("MAIL_SERVER", None)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import create_app  # noqa: E402
from app import routes  # noqa: E402

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
SECRET_RE = re.compile(r'id="totp-secret">([A-Z2-7]+)<')
TOKEN_RE = re.compile(r"/verify-email\?token=([A-Za-z0-9_\-]+)")


def csrf_token(client, url: str) -> str:
    """Read a CSRF token out of a rendered form."""
    html = client.get(url).get_data(as_text=True)
    match = CSRF_RE.search(html)
    assert match, f"no CSRF token found on {url}"
    return match.group(1)


@pytest.fixture()
def app(tmp_path):
    application = create_app(
        {
            "TESTING": True,
            "DATABASE": str(tmp_path / "test.sqlite3"),
            "SECRET_KEY": "test-secret-key-" + ("a" * 40),
            "PRODUCTION": False,
            "MAIL_SERVER": "",
            "WTF_CSRF_ENABLED": True,
            "OUTBOX_DIR": str(tmp_path / "outbox"),
        }
    )
    yield application
    routes._ip_failures.clear()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def registered(client):
    """Register an account and return its e-mail address."""
    email = "person@example.com"
    password = "Str0ng!Passw0rd#2026"
    token = csrf_token(client, "/register")
    response = client.post(
        "/register",
        data={
            "email": email,
            "password": password,
            "confirm_password": password,
            "csrf_token": token,
        },
    )
    assert response.status_code == 200  # development mode shows the confirm link
    body = response.get_data(as_text=True)
    match = TOKEN_RE.search(body)
    return {
        "email": email,
        "password": password,
        "token": match.group(1) if match else "",
    }
