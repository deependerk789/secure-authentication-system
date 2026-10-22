"""Password hashing, password policy, tokens and TOTP.

Nothing here trusts the client.  The browser-side strength meter is only a
convenience; the checks below are the ones that actually decide whether a
password is accepted.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import struct
import time

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# Tuned for a normal workstation: 64 MiB, three passes, four lanes.
_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)

# A hash of a value nobody will guess.  Verifying against it makes a login for
# an unknown address cost the same as a login for a known one, so response time
# does not reveal whether an account exists.
DUMMY_HASH = _hasher.hash("secureauth-timing-equaliser")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")
MIN_PASSWORD_LENGTH = 10
MAX_PASSWORD_LENGTH = 128

# Passwords that are famous enough to be tried first.
COMMON_PASSWORDS = {
    "password123",
    "qwerty12345",
    "1234567890",
    "letmein1234",
    "administrator",
}


# --------------------------------------------------------------------------- #
# Hashing
# --------------------------------------------------------------------------- #
def hash_password(password: str) -> str:
    """Return an Argon2id hash of ``password``."""
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Return True when ``password`` matches ``password_hash``."""
    try:
        return bool(_hasher.verify(password_hash, password))
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    """True when the stored hash uses outdated parameters."""
    try:
        return bool(_hasher.check_needs_rehash(password_hash))
    except InvalidHashError:
        return False


def burn_equivalent_time(password: str) -> None:
    """Run a verification against the dummy hash to equalise timing."""
    try:
        _hasher.verify(DUMMY_HASH, password)
    except Exception:  # noqa: BLE001 - the result is irrelevant by design
        pass


# --------------------------------------------------------------------------- #
# Password policy
# --------------------------------------------------------------------------- #
def password_problems(password: str) -> list[str]:
    """Return a list of human readable reasons the password is rejected."""
    problems: list[str] = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"Use at least {MIN_PASSWORD_LENGTH} characters.")
    if len(password) > MAX_PASSWORD_LENGTH:
        problems.append(f"Use {MAX_PASSWORD_LENGTH} characters or fewer.")
    if not re.search(r"[A-Za-z]", password):
        problems.append("Include at least one letter.")
    if not re.search(r"\d", password):
        problems.append("Include at least one number.")
    if password.lower() in COMMON_PASSWORDS:
        problems.append("That password is too common. Choose something less predictable.")
    return problems


def password_strength_score(password: str) -> int:
    """Return a 0-100 strength indicator.

    This is guidance for the user, not a security guarantee.  The same rules
    are mirrored in ``static/app.js`` so the live meter matches the server.
    """
    if not password:
        return 0
    score = 0
    length = len(password)
    if length >= 10:
        score += 35
    if length >= 14:
        score += 15
    if length >= 20:
        score += 10
    if re.search(r"[a-z]", password):
        score += 10
    if re.search(r"[A-Z]", password):
        score += 10
    if re.search(r"\d", password):
        score += 10
    if re.search(r"[^A-Za-z0-9]", password):
        score += 10
    if len(set(password)) <= 3 or password.lower() in COMMON_PASSWORDS:
        score = min(score, 25)
    return min(score, 100)


def strength_label(score: int) -> str:
    """Map a strength score to a word."""
    if score >= 80:
        return "Strong"
    if score >= 55:
        return "Good"
    if score >= 30:
        return "Fair"
    return "Weak"


# --------------------------------------------------------------------------- #
# Tokens
# --------------------------------------------------------------------------- #
def new_token() -> str:
    """Return a URL-safe random token for email verification / recovery."""
    return secrets.token_urlsafe(32)


def constant_time_equals(left: str, right: str) -> bool:
    """Compare two strings without leaking their contents through timing."""
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


# --------------------------------------------------------------------------- #
# TOTP (RFC 6238) - implemented locally to avoid an extra dependency
# --------------------------------------------------------------------------- #
def new_totp_secret() -> str:
    """Return a new base32 encoded TOTP secret."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _decode_base32(secret: str) -> bytes:
    padded = secret.strip().replace(" ", "").upper()
    padded += "=" * ((8 - len(padded) % 8) % 8)
    return base64.b32decode(padded, casefold=True)


def totp_code(secret: str, counter: int) -> str:
    """Return the six digit TOTP code for ``secret`` at ``counter``."""
    key = _decode_base32(secret)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{truncated % 1_000_000:06d}"


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    """Return True when ``code`` is a valid TOTP for ``secret``."""
    candidate = (code or "").strip().replace(" ", "")
    if not candidate.isdigit() or len(candidate) != 6:
        return False
    counter = int(time.time()) // 30
    for drift in range(-window, window + 1):
        if constant_time_equals(totp_code(secret, counter + drift), candidate):
            return True
    return False


def totp_uri(secret: str, email: str, issuer: str = "SecureAuth") -> str:
    """Return the ``otpauth://`` URI an authenticator app expects."""
    label = f"{issuer}:{email}"
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    )
