
"""SQLite access layer.

The database is a single file. Connections are opened lazily per request
and closed automatically when the request context tears down.
"""

from __future__ import annotations

import sqlite3

from flask import current_app, g


USERS_COLUMNS: dict[str, str] = {
    "password_strength": "INTEGER NOT NULL DEFAULT 0",
    "email_verified": "INTEGER NOT NULL DEFAULT 0",
    "email_verification_token": "TEXT",
    "email_verification_sent_at": "TEXT",
    "two_factor_enabled": "INTEGER NOT NULL DEFAULT 0",
    "two_factor_secret": "TEXT",
    "two_factor_confirmed_at": "TEXT",
    "session_version": "INTEGER NOT NULL DEFAULT 1",
    "password_changed_at": "TEXT",
    "updated_at": "TEXT",
}

CREATE_USERS = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL,
    password_strength INTEGER NOT NULL DEFAULT 0
)
"""

CREATE_LOGIN_EVENTS = """
CREATE TABLE IF NOT EXISTS login_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    email_attempted TEXT NOT NULL,
    event TEXT NOT NULL CHECK (
        event IN (
            'success',
            'failure',
            'locked',
            'logout',
            'two_factor_failure',
            'email_otp_sent'
        )
    ),
    ip_address TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)
"""

CREATE_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_login_events_user_time "
    "ON login_events(user_id, created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_users_verification_token "
    "ON users(email_verification_token)",
)


def get_db() -> sqlite3.Connection:
    """Return the request-scoped database connection."""
    if "db" not in g:
        connection = sqlite3.connect(
            current_app.config["DATABASE"],
            detect_types=sqlite3.PARSE_DECLTYPES,
            timeout=15,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA busy_timeout = 15000")
        g.db = connection
    return g.db


def close_db(_exc: BaseException | None = None) -> None:
    """Close the request-scoped database connection."""
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def _table_sql(db: sqlite3.Connection, table: str) -> str | None:
    row = db.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    return row["sql"] if row else None


def _migrate_login_events(db: sqlite3.Connection) -> None:
    """Upgrade outdated login event constraints and missing columns."""
    sql = _table_sql(db, "login_events")
    if not sql:
        return

    required_events = (
        "success",
        "failure",
        "locked",
        "logout",
        "two_factor_failure",
        "email_otp_sent",
    )

    old_columns = {
        row["name"]
        for row in db.execute("PRAGMA table_info(login_events)")
    }

    required_columns = {
        "id",
        "user_id",
        "email_attempted",
        "event",
        "ip_address",
        "user_agent",
        "created_at",
    }

    outdated_events = any(
        f"'{event}'" not in sql for event in required_events
    )
    missing_columns = not required_columns.issubset(old_columns)

    if not outdated_events and not missing_columns:
        return

    db.execute("DROP TABLE IF EXISTS login_events_legacy")
    db.execute("ALTER TABLE login_events RENAME TO login_events_legacy")
    db.execute(CREATE_LOGIN_EVENTS)

    columns_to_copy = [
        column
        for column in (
            "id",
            "user_id",
            "email_attempted",
            "event",
            "ip_address",
            "user_agent",
            "created_at",
        )
        if column in old_columns
    ]

    columns_sql = ", ".join(columns_to_copy)

    db.execute(
        f"""
        INSERT INTO login_events ({columns_sql})
        SELECT {columns_sql}
        FROM login_events_legacy
        """
    )

    db.execute("DROP TABLE login_events_legacy")


def _migrate_users(db: sqlite3.Connection) -> None:
    """Add any column that the current application expects."""
    existing = {
        row["name"] for row in db.execute("PRAGMA table_info(users)")
    }
    for column, declaration in USERS_COLUMNS.items():
        if column not in existing:
            db.execute(
                f"ALTER TABLE users ADD COLUMN {column} {declaration}"
            )


def init_db(app) -> None:
    """Create or upgrade the schema without deleting user records."""
    with app.app_context():
        db = get_db()
        try:
            db.execute(CREATE_USERS)
            _migrate_users(db)
            db.execute(CREATE_LOGIN_EVENTS)
            _migrate_login_events(db)
            for statement in CREATE_INDEXES:
                db.execute(statement)
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            close_db()
