"""End-to-end tests for the authentication flows."""

from __future__ import annotations

import re
import time

from app.security import (
    hash_password,
    new_totp_secret,
    password_needs_rehash,
    password_problems,
    password_strength_score,
    totp_code,
    verify_password,
    verify_totp,
)

from conftest import csrf_token

SECRET_RE = re.compile(r'id="totp-secret">\s*([A-Z2-7]+)')


def sign_in(client, email: str, password: str):
    token = csrf_token(client, "/login")
    return client.post(
        "/login",
        data={"email": email, "password": password, "csrf_token": token},
    )


# --------------------------------------------------------------------- units
def test_password_hash_is_salted_and_verifies():
    first = hash_password("Str0ng!Passw0rd#2026")
    second = hash_password("Str0ng!Passw0rd#2026")
    assert first != second, "each hash must use a fresh salt"
    assert verify_password(first, "Str0ng!Passw0rd#2026")
    assert not verify_password(first, "wrong-password")
    assert not password_needs_rehash(first)


def test_password_policy_rejects_weak_passwords():
    assert password_problems("short")
    assert password_problems("alllettersonly")
    assert password_problems("NoDigitsAtAllHere")
    assert password_problems("password123")
    assert password_problems("A" * 200)
    assert password_problems("Str0ng!Passw0rd#2026") == []


def test_strength_score_is_bounded():
    assert password_strength_score("") == 0
    assert password_strength_score("aaaa") <= 25
    assert password_strength_score("Str0ng!Passw0rd#2026") == 100
    assert 0 <= password_strength_score("abcdefghij12") <= 100


def test_totp_roundtrip():
    secret = new_totp_secret()
    code = totp_code(secret, int(time.time()) // 30)
    assert verify_totp(secret, code)
    assert not verify_totp(secret, "000000" if code != "000000" else "111111")
    assert not verify_totp(secret, "abc")


# ------------------------------------------------------------------ register
def test_register_creates_the_account(client):
    token = csrf_token(client, "/register")
    response = client.post(
        "/register",
        data={
            "email": "New.User@Example.com",
            "password": "Str0ng!Passw0rd#2026",
            "confirm_password": "Str0ng!Passw0rd#2026",
            "csrf_token": token,
        },
    )
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "confirm" in body.lower()


def test_register_rejects_a_weak_password(client):
    token = csrf_token(client, "/register")
    response = client.post(
        "/register",
        data={
            "email": "weak@example.com",
            "password": "short",
            "confirm_password": "short",
            "csrf_token": token,
        },
    )
    assert response.status_code == 200
    assert "at least 10 characters" in response.get_data(as_text=True).lower()


def test_register_does_not_leak_duplicate_addresses(client, registered):
    token = csrf_token(client, "/register")
    response = client.post(
        "/register",
        data={
            "email": registered["email"],
            "password": "An0ther!Passw0rd#2026",
            "confirm_password": "An0ther!Passw0rd#2026",
            "csrf_token": token,
        },
    )
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_csrf_token_is_required(client):
    response = client.post(
        "/login", data={"email": "a@example.com", "password": "Str0ng!Passw0rd#2026"}
    )
    assert response.status_code == 400


# --------------------------------------------------------------------- login
def test_login_succeeds_and_opens_the_dashboard(client, registered):
    response = sign_in(client, registered["email"], registered["password"])
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard")
    assert client.get("/dashboard").status_code == 200


def test_login_with_a_wrong_password_is_generic(client, registered):
    response = sign_in(client, registered["email"], "Wrong!Passw0rd#2026")
    assert response.status_code == 401
    assert "incorrect" in response.get_data(as_text=True).lower()


def test_unknown_account_gets_the_same_message(client, registered):
    known = sign_in(client, registered["email"], "Wrong!Passw0rd#2026")
    unknown = sign_in(client, "nobody@example.com", "Wrong!Passw0rd#2026")
    assert known.status_code == unknown.status_code == 401
    assert "incorrect" in unknown.get_data(as_text=True).lower()


def test_repeated_failures_lock_the_account(client, registered):
    for _ in range(5):
        assert sign_in(client, registered["email"], "Wrong!Passw0rd#2026").status_code == 401
    locked = sign_in(client, registered["email"], "Wrong!Passw0rd#2026")
    assert locked.status_code == 429
    # The correct password is refused while the lock is in place.
    assert sign_in(client, registered["email"], registered["password"]).status_code == 429


def test_dashboard_requires_a_session(client):
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_logout_clears_the_session(client, registered):
    sign_in(client, registered["email"], registered["password"])
    token = csrf_token(client, "/dashboard")
    response = client.post("/logout", data={"csrf_token": token})
    assert response.status_code == 302
    assert client.get("/dashboard").status_code == 302


# --------------------------------------------------------- email verification
def test_email_verification_marks_the_address_verified(client, registered):
    assert registered["token"], "expected a verification token in the development mode page"

    token = csrf_token(client, "/login")
    client.post(
        "/login",
        data={"email": registered["email"], "password": registered["password"], "csrf_token": token},
    )
    body = client.get("/dashboard").get_data(as_text=True)
    assert "Not verified" in body

    result = client.get(f"/verify-email?token={registered['token']}")
    assert result.status_code == 302
    assert "Verified" in client.get("/dashboard").get_data(as_text=True)


# ------------------------------------------------------------------ two factor
def test_two_factor_setup_and_challenge(client, registered):
    sign_in(client, registered["email"], registered["password"])
    page = client.get("/two-factor/setup").get_data(as_text=True)
    match = SECRET_RE.search(page)
    assert match, "expected the setup key on the page"
    secret = match.group(1)

    code = totp_code(secret, int(time.time()) // 30)
    token = csrf_token(client, "/two-factor/setup")
    response = client.post(
        "/two-factor/setup", data={"code": code, "csrf_token": token}
    )
    assert response.status_code == 302
    assert "Enabled" in client.get("/dashboard").get_data(as_text=True)

    # A new sign-in now needs the second factor.
    response = sign_in(client, registered["email"], registered["password"])
    assert response.headers["Location"].endswith("/two-factor")

    token = csrf_token(client, "/two-factor")
    response = client.post(
        "/two-factor", data={"code": totp_code(secret, int(time.time()) // 30), "csrf_token": token}
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard")


def test_wrong_two_factor_code_is_rejected(client, registered):
    sign_in(client, registered["email"], registered["password"])
    page = client.get("/two-factor/setup").get_data(as_text=True)
    secret = SECRET_RE.search(page).group(1)
    token = csrf_token(client, "/two-factor/setup")
    client.post(
        "/two-factor/setup",
        data={"code": totp_code(secret, int(time.time()) // 30), "csrf_token": token},
    )
    sign_in(client, registered["email"], registered["password"])
    token = csrf_token(client, "/two-factor")
    wrong = totp_code(secret, 0)  # a code from counter zero, far outside the window
    response = client.post("/two-factor", data={"code": wrong, "csrf_token": token})
    assert response.status_code == 200
    assert "not correct" in response.get_data(as_text=True).lower()


# ------------------------------------------------------------ password change
def test_change_password_signs_the_user_out(client, registered):
    sign_in(client, registered["email"], registered["password"])
    token = csrf_token(client, "/change-password")
    response = client.post(
        "/change-password",
        data={
            "current_password": registered["password"],
            "new_password": "N3w!StrongerPassw0rd#2026",
            "confirm_password": "N3w!StrongerPassw0rd#2026",
            "csrf_token": token,
        },
    )
    assert response.status_code == 302
    assert client.get("/dashboard").status_code == 302
    assert sign_in(client, registered["email"], "N3w!StrongerPassw0rd#2026").status_code == 302


def test_change_password_needs_the_current_password(client, registered):
    sign_in(client, registered["email"], registered["password"])
    token = csrf_token(client, "/change-password")
    response = client.post(
        "/change-password",
        data={
            "current_password": "not-my-password",
            "new_password": "N3w!StrongerPassw0rd#2026",
            "confirm_password": "N3w!StrongerPassw0rd#2026",
            "csrf_token": token,
        },
    )
    assert response.status_code == 401


# ------------------------------------------------------------- account removal
def test_account_deletion_removes_the_user(client, registered):
    sign_in(client, registered["email"], registered["password"])
    token = csrf_token(client, "/account")
    response = client.post(
        "/account", data={"action": "delete", "password": registered["password"], "csrf_token": token}
    )
    assert response.status_code == 302
    assert sign_in(client, registered["email"], registered["password"]).status_code == 401


# ------------------------------------------------------------------- headers
def test_security_headers_are_present(client):
    response = client.get("/login")
    headers = response.headers
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert "unsafe-inline" not in headers["Content-Security-Policy"]
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "same-origin"


def test_pages_do_not_use_inline_styles(client, registered):
    """Inline style attributes are blocked by the CSP, so there must be none."""
    sign_in(client, registered["email"], registered["password"])
    for path in ("/dashboard", "/account", "/change-password"):
        body = client.get(path).get_data(as_text=True)
        assert "style=" not in body, f"{path} contains an inline style attribute"


def test_healthz(client):
    assert client.get("/healthz").status_code == 200
