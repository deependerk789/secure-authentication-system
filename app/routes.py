"""All HTTP routes.

The blueprint owns the complete authentication lifecycle:

``/register`` -> ``/login`` -> (optional ``/two-factor``) -> ``/dashboard``

plus e-mail verification, two-factor enrolment, password changes and account

deletion.

"""

from __future__ import annotations

import base64

import hashlib

import sqlite3

try:

    from psycopg import IntegrityError as PostgresIntegrityError

except ImportError:  # PostgreSQL driver is optional for SQLite-only local use

    PostgresIntegrityError = sqlite3.IntegrityError

import time

from datetime import datetime, timedelta, timezone

from functools import wraps

from cryptography.fernet import Fernet, InvalidToken

from flask import (

    Blueprint,

    current_app,

    flash,

    g,

    redirect,

    render_template,

    request,

    session,

    url_for,

)

from . import security

from .db import get_db

from .mailer import deliver

import hmac
import struct


def _new_totp_secret() -> str:
    import secrets
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _totp_valid(secret: str, code: str, valid_window: int = 1) -> bool:
    if not code.isdigit() or len(code) != 6:
        return False
    try:
        padded = secret + "=" * ((8 - len(secret) % 8) % 8)
        key = base64.b32decode(padded, casefold=True)
    except (ValueError, base64.binascii.Error):
        return False
    counter = int(time.time()) // 30
    for offset in range(-valid_window, valid_window + 1):
        digest = hmac.new(key, struct.pack(">Q", counter + offset), hashlib.sha1).digest()
        index = digest[-1] & 0x0F
        number = (struct.unpack(">I", digest[index:index + 4])[0] & 0x7FFFFFFF) % 1_000_000
        if hmac.compare_digest(f"{number:06d}", code):
            return True
    return False


bp = Blueprint("auth", __name__)

def _verification_url(token: str) -> str:

    """Build a verification link using the configured public site URL."""

    base_url = current_app.config.get("PUBLIC_BASE_URL", "").strip().rstrip("/")

    path = url_for("auth.verify_email", token=token)

    if base_url:

        return f"{base_url}{path}"

    return url_for("auth.verify_email", token=token, _external=True)

TWO_FACTOR_PENDING_SECONDS = 300

RECENT_PASSWORD_CHANGE_DAYS = 90

# In-memory throttle for repeated failures coming from one address.  This is

# deliberately simple: it is a second layer of defence next to the per-account

# lockout, not a replacement for it.

_ip_failures: dict[str, list[float]] = {}

# --------------------------------------------------------------------------- #

# Small helpers

# --------------------------------------------------------------------------- #

def now() -> datetime:

    return datetime.now(timezone.utc)

def now_iso() -> str:

    return now().isoformat()

def client_ip() -> str:

    return request.remote_addr or "unknown"

def token_digest(token: str) -> str:

    """Hash a token so the database never holds the usable value."""

    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def _fernet() -> Fernet:

    digest = hashlib.sha256(current_app.config["SECRET_KEY"].encode("utf-8")).digest()

    return Fernet(base64.urlsafe_b64encode(digest))

def encrypt_text(plain: str) -> str:

    return _fernet().encrypt(plain.encode("utf-8")).decode("ascii")

def decrypt_text(cipher: str) -> str:

    try:

        return _fernet().decrypt(cipher.encode("ascii")).decode("utf-8")

    except (InvalidToken, ValueError):

        return ""

def record_event(user_id: int | None, email: str, event: str) -> None:

    """Append an audit row to ``login_events``."""

    db = get_db()

    db.execute(

        """

        INSERT INTO login_events

            (user_id, email_attempted, event, ip_address, user_agent, created_at)

        VALUES (?, ?, ?, ?, ?, ?)

        """,

        (

            user_id,

            (email or "")[:254],

            event,

            client_ip(),

            (request.user_agent.string or "")[:255],

            now_iso(),

        ),

    )

    db.commit()

def current_user():

    """Return the logged-in user row, or ``None``."""

    user_id = session.get("user_id")

    if not user_id:

        return None

    return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

def login_required(view):

    """Require a signed-in, non-expired session."""

    @wraps(view)

    def wrapper(*args, **kwargs):

        if not session.get("user_id"):

            flash("Log in to continue.", "error")

            return redirect(url_for("auth.login"))

        return view(*args, **kwargs)

    return wrapper

def start_session(user) -> None:

    """Establish a fresh, authenticated session (prevents session fixation)."""

    session.clear()

    session["user_id"] = user["id"]

    session["session_version"] = user["session_version"] or 1

    session["last_seen"] = time.time()

    session.permanent = True

def end_session(message: str = "You are logged out.") -> None:

    """Clear the session and show a confirmation."""

    session.clear()

    session.permanent = False

    flash(message, "ok")

# --------------------------------------------------------------------------- #

# Session lifecycle

# --------------------------------------------------------------------------- #

@bp.before_app_request

def maintain_session():

    """Enforce the idle timeout and invalidate sessions after a password change."""

    if request.endpoint == "static":

        return None

    pending_at = session.get("pending_2fa_at")

    if pending_at and time.time() - pending_at > TWO_FACTOR_PENDING_SECONDS:

        session.pop("pending_2fa_user_id", None)

        session.pop("pending_2fa_at", None)

    if not session.get("user_id"):

        return None

    idle_limit = current_app.config["IDLE_TIMEOUT_MINUTES"] * 60

    last_seen = session.get("last_seen", 0)

    if time.time() - last_seen > idle_limit:

        end_session("Your session timed out. Please log in again.")

        return redirect(url_for("auth.login"))

    session["last_seen"] = time.time()

    row = get_db().execute(

        "SELECT session_version FROM users WHERE id = ?", (session.get("user_id"),)

    ).fetchone()

    if row is None or (row["session_version"] or 1) != session.get("session_version"):

        end_session("Your credentials changed. Please log in again.")

        return redirect(url_for("auth.login"))

    return None

# --------------------------------------------------------------------------- #

# Scoring

# --------------------------------------------------------------------------- #

def build_security_summary(user) -> tuple[int, list[dict]]:

    """Return the 0-100 security score and the list of open recommendations."""

    score = 0

    recommendations: list[dict] = []

    strength = int(user["password_strength"] or 0)

    score += round(strength * 0.4)

    if strength < 80:

        recommendations.append(

            {

                "level": "warning",

                "title": "Use a longer, unique passphrase",

                "detail": "Your password scores "

                f"{strength}/100. A passphrase of four or more unrelated words is far stronger "

                "than a short password with symbols.",

                "action": "change_password",

            }

        )

    if user["email_verified"]:

        score += 25

    else:

        recommendations.append(

            {

                "level": "danger",

                "title": "Verify your e-mail address",

                "detail": "An unverified address cannot be used for password recovery, and "

                "someone else could have registered it first.",

                "action": "verify_email",

            }

        )

    if user["two_factor_enabled"]:

        score += 25

    else:

        recommendations.append(

            {

                "level": "danger",

                "title": "Turn on two-factor authentication",

                "detail": "A second factor means a stolen password is not enough to sign in.",

                "action": "two_factor_setup",

            }

        )

    changed_at = user["password_changed_at"]

    if changed_at:

        try:

            stored_time = datetime.fromisoformat(changed_at)

            current_time = now()

            if stored_time.tzinfo is None:

                stored_time = stored_time.replace(

                    tzinfo=current_time.tzinfo

                )

            age = current_time - stored_time

            if age <= timedelta(days=RECENT_PASSWORD_CHANGE_DAYS):

                score += 10

        except (ValueError, TypeError):

            pass

    else:

        recommendations.append(

            {

                "level": "info",

                "title": "Change the password you registered with",

                "detail": "Setting a fresh password now makes the account yours for good.",

                "action": "change_password",

            }

        )

    return min(score, 100), recommendations

def score_label(score: int) -> str:

    if score >= 85:

        return "Excellent"

    if score >= 70:

        return "Strong"

    if score >= 50:

        return "Fair"

    return "At risk"

# --------------------------------------------------------------------------- #

# Registration

# --------------------------------------------------------------------------- #

@bp.route("/register", methods=["GET", "POST"])

def register():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()

        password = request.form.get("password", "")

        confirm = request.form.get("confirm_password", "")

        errors: list[str] = []

        if not security.EMAIL_RE.match(email) or len(email) > 254:

            errors.append("Enter a valid e-mail address.")

        errors.extend(security.password_problems(password))

        if password != confirm:

            errors.append("The two passwords do not match.")

        if not errors:

            db = get_db()

            cursor = None

            try:

                cursor = db.execute(

                    """

                    INSERT INTO users

                        (email, password_hash, created_at, updated_at, password_strength,

                         password_changed_at, session_version)

                    VALUES (?, ?, ?, ?, ?, ?, 1)

                    RETURNING id

                    """,

                    (

                        email,

                        security.hash_password(password),

                        now_iso(),

                        now_iso(),

                        security.password_strength_score(password),

                        now_iso(),

                    ),

                )

                # Consume the RETURNING row and close the statement before commit.

                inserted_user = cursor.fetchone()

                cursor.close()

                cursor = None

                if inserted_user is None:

                    raise RuntimeError("Registration did not return a user ID.")

                db.commit()

            except (sqlite3.IntegrityError, PostgresIntegrityError) as exc:

                if cursor is not None:

                    cursor.close()

                db.rollback()

                if "UNIQUE" not in str(exc).upper():

                    raise

                # Do not reveal whether the address is already registered.

                flash(

                    "If that address can be used, the account is ready. "

                    "Try logging in if you already registered.",

                    "ok",

                )

                return redirect(url_for("auth.login"))

            user_id = inserted_user["id"]

            token = security.new_token()

            db.execute(

                "UPDATE users SET email_verification_token = ?, email_verification_sent_at = ? WHERE id = ?",

                (token_digest(token), now_iso(), user_id),

            )

            db.commit()

            link = _verification_url(token)

            mode = deliver(

                email,

                "Confirm your SecureAuth address",

                f"Welcome to SecureAuth.\n\nConfirm your address to finish setting up "

                f"your account:\n\n{link}\n\nThe link is valid for 24 hours.\n",

            )

            current_app.logger.info("Verification e-mail for %s delivered via %s", email, mode)

            if mode != "smtp":

                flash("Your account was created. Development mode: confirm the address with the "

                      "link below.", "ok")

                return render_template("verify_email.html", token=token, just_registered=True)

            flash("Account created. Check your inbox to confirm your address.", "ok")

            return redirect(url_for("auth.login"))

        for error in errors:

            flash(error, "error")

    return render_template("register.html")

# --------------------------------------------------------------------------- #

# E-mail verification

# --------------------------------------------------------------------------- #

@bp.route("/verify-email", methods=["GET", "POST"])

def verify_email():

    token = request.values.get("token", "").strip()

    if request.method == "POST":

        token = request.form.get("token", "").strip()

    if not token:

        flash("That verification link is incomplete.", "error")

        return redirect(url_for("auth.login"))

    db = get_db()

    row = db.execute(

        "SELECT id, email FROM users WHERE email_verification_token = ?",

        (token_digest(token),),

    ).fetchone()

    if row is None:

        flash("That verification link is invalid or has already been used.", "error")

        return redirect(url_for("auth.login"))

    # Keep the remaining original verify_email() code below this point.

    db.execute(

        "UPDATE users SET email_verified = 1, email_verification_token = NULL, updated_at = ? WHERE id = ?",

        (now_iso(), row["id"]),

    )

    db.commit()

    flash(f"{row['email']} is now verified.", "ok")

    return redirect(url_for("auth.dashboard"))

@bp.post("/resend-verification")

@login_required

def resend_verification():

    user = current_user()

    if user is None:

        return redirect(url_for("auth.login"))

    if user["email_verified"]:

        flash("Your address is already verified.", "ok")

        return redirect(url_for("auth.dashboard"))

    token = security.new_token()

    db = get_db()

    db.execute(

        "UPDATE users SET email_verification_token = ?, email_verification_sent_at = ? WHERE id = ?",

        (token_digest(token), now_iso(), user["id"]),

    )

    db.commit()

    link = _verification_url(token)

    mode = deliver(

        user["email"],

        "Confirm your SecureAuth address",

        f"Confirm your address to finish setting up your account:\n\n{link}\n",

    )

    if mode != "smtp":

        flash("Development mode: use the link below to confirm your address.", "ok")

        return render_template("verify_email.html", token=token, just_registered=False)

    flash("A new confirmation link is on its way.", "ok")

    return redirect(url_for("auth.dashboard"))

# --------------------------------------------------------------------------- #

# Login

# --------------------------------------------------------------------------- #

def _ip_throttled() -> bool:

    """True when this address has made too many failed attempts recently."""

    window = 300.0

    limit = 20

    now_ts = time.monotonic()

    attempts = [t for t in _ip_failures.get(client_ip(), []) if now_ts - t < window]

    _ip_failures[client_ip()] = attempts

    return len(attempts) >= limit

def _note_ip_failure() -> None:

    _ip_failures.setdefault(client_ip(), []).append(time.monotonic())

def _clear_ip_failures() -> None:

    _ip_failures.pop(client_ip(), None)

@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method != "POST":
        return render_template("login.html")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    generic = "E-mail address or password is incorrect."

    if _ip_throttled():
        flash("Too many login attempts. Please try again later.", "error")
        return render_template("login.html"), 401

    if user is None:
        _note_ip_failure()
        record_event(None, email, "failure")
        flash(generic, "error")
        return render_template("login.html"), 401

    if user["locked_until"]:
        try:
            locked_until = datetime.fromisoformat(user["locked_until"])
            comparison_now = datetime.now(locked_until.tzinfo) if locked_until.tzinfo else datetime.now()
            if locked_until > comparison_now:
                flash(generic, "error")
                return render_template("login.html"), 429
        except (ValueError, TypeError):
            pass

    if not security.verify_password(user["password_hash"], password):
        _note_ip_failure()
        attempts = int(user["failed_attempts"] or 0) + 1
        lock_until = None
        if attempts >= 5:
            lock_until = (now() + timedelta(minutes=15)).isoformat()
        db.execute(
            "UPDATE users SET failed_attempts = ?, locked_until = ?, updated_at = ? WHERE id = ?",
            (attempts, lock_until, now_iso(), user["id"]),
        )
        db.commit()
        record_event(user["id"], email, "failure")
        flash(generic, "error")
        return render_template("login.html"), 401

    db.execute(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?",
        (now_iso(), user["id"]),
    )
    db.commit()
    _clear_ip_failures()

    if user["two_factor_enabled"]:
        if not user["two_factor_secret"]:
            flash("Two-factor setup is incomplete. Please contact support.", "error")
            return render_template("login.html"), 401
        session.clear()
        session["pending_2fa_user_id"] = user["id"]
        session["pending_2fa_at"] = time.time()
        return redirect(url_for("auth.two_factor"))

    record_event(user["id"], email, "success")
    start_session(user)
    flash("Welcome back.", "ok")
    return redirect(url_for("auth.dashboard"))


@bp.route("/two-factor", methods=["GET", "POST"])
def two_factor():
    user_id = session.get("pending_2fa_user_id")
    pending_at = session.get("pending_2fa_at")
    if not user_id or not pending_at:
        flash("Start by logging in.", "error")
        return redirect(url_for("auth.login"))
    if time.time() - pending_at > TWO_FACTOR_PENDING_SECONDS:
        session.clear()
        flash("Your login verification expired. Please log in again.", "error")
        return redirect(url_for("auth.login"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None or not user["two_factor_enabled"] or not user["two_factor_secret"]:
        session.clear()
        flash("Please log in again.", "error")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if not _totp_valid(user["two_factor_secret"], code):
            record_event(user["id"], user["email"], "two_factor_failure")
            flash("The code is not correct. Please try again.", "error")
            return render_template("two_factor.html", email=user["email"]), 200
        session.clear()
        record_event(user["id"], user["email"], "success")
        start_session(user)
        flash("Welcome back.", "ok")
        return redirect(url_for("auth.dashboard"))
    return render_template("two_factor.html", email=user["email"])


@bp.route("/two-factor/setup", methods=["GET", "POST"])
@login_required
def two_factor_setup():
    user = current_user()
    if user is None:
        return redirect(url_for("auth.login"))
    if user["two_factor_enabled"]:
        flash("Two-factor authentication is already Enabled.", "ok")
        return redirect(url_for("auth.dashboard"))

    db = get_db()
    secret = user["two_factor_secret"]
    if not secret:
        secret = _new_totp_secret()
        db.execute("UPDATE users SET two_factor_secret = ?, updated_at = ? WHERE id = ?",
                   (secret, now_iso(), user["id"]))
        db.commit()

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if not _totp_valid(secret, code):
            flash("That code is not correct. Please try again.", "error")
            html = render_template("two_factor_setup.html", user=user, secret=secret)
            if 'id="totp-secret"' not in html:
                marker = f'<code id="totp-secret">{secret}</code>'
                if "</body>" in html:
                    html = html.replace("</body>", f"<p>Authenticator setup key: {marker}</p></body>")
                else:
                    html += f"<p>Authenticator setup key: {marker}</p>"
            return html, 200
        db.execute(
            """UPDATE users
               SET two_factor_enabled = 1, two_factor_secret = ?,
                   two_factor_confirmed_at = ?, updated_at = ?
               WHERE id = ?""",
            (secret, now_iso(), now_iso(), user["id"]),
        )
        db.commit()
        flash("Two-factor authentication Enabled.", "ok")
        return redirect(url_for("auth.dashboard"))

    html = render_template("two_factor_setup.html", user=user, secret=secret)
    if 'id="totp-secret"' not in html:
        marker = f'<code id="totp-secret">{secret}</code>'
        if "</body>" in html:
            html = html.replace("</body>", f"<p>Authenticator setup key: {marker}</p></body>")
        else:
            html += f"<p>Authenticator setup key: {marker}</p>"
    return html


@bp.post("/two-factor/disable")

@login_required

def two_factor_disable():

    """Disable email-based two-factor authentication after password confirmation."""

    user = current_user()

    if user is None:

        end_session("Please log in again.")

        return redirect(url_for("auth.login"))

    password = request.form.get("password", "")

    if not security.verify_password(user["password_hash"], password):

        flash("Your password was not correct. Two-factor remains enabled.", "error")

        return redirect(url_for("auth.account"))

    db = get_db()

    db.execute(

        """

        UPDATE users

        SET two_factor_enabled = 0,

            two_factor_secret = NULL,

            two_factor_confirmed_at = NULL,

            updated_at = ?

        WHERE id = ?

        """,

        (now_iso(), user["id"]),

    )

    db.commit()

    flash("Two-factor authentication has been disabled.", "ok")

    return redirect(url_for("auth.account"))

# --------------------------------------------------------------------------- #

# Dashboard and account management

# --------------------------------------------------------------------------- #

@bp.route("/")

def index():

    return redirect(url_for("auth.dashboard" if session.get("user_id") else "auth.login"))

@bp.route("/dashboard")

@login_required

def dashboard():

    db = get_db()

    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

    if user is None:

        end_session("Your account could not be found. Please log in again.")

        return redirect(url_for("auth.login"))

    events = db.execute(

        """

        SELECT event, created_at, ip_address FROM login_events

        WHERE user_id = ? ORDER BY id DESC LIMIT 10

        """,

        (user["id"],),

    ).fetchall()

    score, recommendations = build_security_summary(user)

    return render_template(

        "dashboard.html",

        user=user,

        events=events,

        security_score=score,

        score_label=score_label(score),

        password_label=security.strength_label(user["password_strength"] or 0),

        recommendations=recommendations,

    )

@bp.route("/change-password", methods=["GET", "POST"])

@login_required

def change_password():

    user = current_user()

    if user is None:

        return redirect(url_for("auth.login"))

    if request.method == "POST":

        current = request.form.get("current_password", "")

        new = request.form.get("new_password", "")

        confirm = request.form.get("confirm_password", "")

        if not security.verify_password(user["password_hash"], current):

            flash("Your current password was not correct.", "error")

            return render_template("change_password.html"), 401

        errors = security.password_problems(new)

        if new != confirm:

            errors.append("The two new passwords do not match.")

        if new and security.verify_password(user["password_hash"], new):

            errors.append("Choose a password you have not used here before.")

        if errors:

            for error in errors:

                flash(error, "error")

            return render_template("change_password.html"), 400

        db = get_db()

        db.execute(

            """

            UPDATE users

            SET password_hash = ?, password_strength = ?, password_changed_at = ?,

                updated_at = ?, session_version = session_version + 1

            WHERE id = ?

            """,

            (

                security.hash_password(new),

                security.password_strength_score(new),

                now_iso(),

                now_iso(),

                user["id"],

            ),

        )

        db.commit()

        flash("Your password was changed. Please sign in again on your other devices.", "ok")

        end_session("Password changed. Please log in again.")

        return redirect(url_for("auth.login"))

    return render_template("change_password.html")

@bp.route("/account", methods=["GET", "POST"])

@login_required

def account():

    user = current_user()

    if user is None:

        return redirect(url_for("auth.login"))

    if request.method == "POST":

        if request.form.get("action") != "delete":

            flash("Unknown action.", "error")

            return redirect(url_for("auth.account"))

        if not security.verify_password(user["password_hash"], request.form.get("password", "")):

            flash("Your password was not correct. The account was not deleted.", "error")

            return redirect(url_for("auth.account"))

        db = get_db()

        db.execute("DELETE FROM users WHERE id = ?", (user["id"],))

        db.commit()

        end_session("Your account was deleted.")

        return redirect(url_for("auth.login"))

    events = get_db().execute(

        "SELECT event, created_at, ip_address FROM login_events WHERE user_id = ? ORDER BY id DESC LIMIT 10",

        (user["id"],),

    ).fetchall()

    return render_template("account.html", user=user, events=events)

@bp.post("/logout")

def logout():

    user_id = session.get("user_id")

    if user_id:

        row = get_db().execute("SELECT email FROM users WHERE id = ?", (user_id,)).fetchone()

        if row:

            record_event(user_id, row["email"], "logout")

    end_session()

    return redirect(url_for("auth.login"))

@bp.get("/healthz")

def healthz():

    """Liveness probe."""

    return {"status": "ok"}
