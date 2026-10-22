"""Application configuration.

Every setting is read from the environment (optionally seeded by a local
``.env`` file).  Real environment variables always win over the file, so a
deployment can override anything without touching the source tree.

Nothing secret is committed to the repository:

* ``SECRET_KEY`` must be supplied by the environment in production.
* In development a random key is generated once and cached in
  ``data/dev_secret_key`` so sessions survive a restart.
"""

from __future__ import annotations

import os
import secrets
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"


def read_env_file(path: Path) -> dict[str, str]:
    """Parse a simple ``KEY=VALUE`` file. A missing file is not an error."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def load_env() -> dict[str, str]:
    """Return the merged environment, with real env vars taking priority."""
    merged = read_env_file(BASE_DIR / ".env")
    merged.update(os.environ)
    return merged


def resolve_secret_key(env: dict[str, str], production: bool) -> str:
    """Return the session signing key or fail loudly in production."""
    key = env.get("SECRET_KEY", "").strip()
    if key:
        if production and len(key) < 32:
            raise RuntimeError("SECRET_KEY must be at least 32 characters when PRODUCTION=1.")
        return key
    if production:
        raise RuntimeError("SECRET_KEY environment variable is required when PRODUCTION=1.")

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    key_file = DATA_DIR / "dev_secret_key"
    if key_file.is_file():
        stored = key_file.read_text(encoding="utf-8").strip()
        if stored:
            return stored

    key = secrets.token_hex(32)
    key_file.write_text(key, encoding="utf-8")
    try:
        os.chmod(key_file, 0o600)
    except OSError:  # pragma: no cover - Windows ACLs are managed elsewhere
        pass
    return key


def build_config(env: dict[str, str] | None = None) -> dict:
    """Build the Flask config mapping used by :func:`create_app`."""
    env = load_env() if env is None else env
    production = env.get("PRODUCTION", "").strip().lower() in {
        "1", "true", "yes", "on"
    }

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    database = env.get("DATABASE_PATH", "").strip()
    database_path = Path(database) if database else DATA_DIR / "secureauth.sqlite3"

    return {
        "SECRET_KEY": resolve_secret_key(env, production),
        "DATABASE": str(database_path),
        "PRODUCTION": production,
        "DEBUG": env.get("FLASK_DEBUG", "").strip().lower() in {
            "1", "true", "yes", "on"
        },

        # Public website URL used in email verification links
        "PUBLIC_BASE_URL": env.get("PUBLIC_BASE_URL", "").strip().rstrip("/"),

        "MAX_LOGIN_ATTEMPTS": int(env.get("MAX_LOGIN_ATTEMPTS", "5")),
        "LOCKOUT_MINUTES": int(env.get("LOCKOUT_MINUTES", "15")),
        "SESSION_LIFETIME_MINUTES": int(env.get("SESSION_LIFETIME_MINUTES", "30")),
        "IDLE_TIMEOUT_MINUTES": int(env.get("IDLE_TIMEOUT_MINUTES", "15")),
        "TWO_FACTOR_WINDOW": int(env.get("TWO_FACTOR_WINDOW", "1")),

        "MAIL_SERVER": env.get("MAIL_SERVER", "").strip(),
        "MAIL_PORT": int(env.get("MAIL_PORT", "587")),
        "MAIL_USERNAME": env.get("MAIL_USERNAME", "").strip(),
        "MAIL_PASSWORD": env.get("MAIL_PASSWORD", "").strip(),
        "MAIL_USE_TLS": env.get("MAIL_USE_TLS", "1").strip().lower()
        not in {"0", "false", "no"},
        "MAIL_FROM": env.get("MAIL_FROM", "no-reply@secureauth.local").strip(),

        "OUTBOX_DIR": str(DATA_DIR / "outbox"),

        # Cookie hardening
        "SESSION_COOKIE_NAME": (
            "__Host-secureauth_session" if production else "secureauth_session"
        ),
        "SESSION_COOKIE_SECURE": production,
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Lax",
        "PERMANENT_SESSION_LIFETIME": timedelta(
            minutes=int(env.get("SESSION_LIFETIME_MINUTES", "30"))
        ),
    }
