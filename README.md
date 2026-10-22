# SecureAuth

A small, complete authentication service built with Flask and SQLite.

Passwords are hashed with Argon2id, sessions are signed and time limited, every
form is protected with CSRF tokens, sign-in activity is written to an audit
table, and the dashboard tells you exactly what is still missing.

---

## What it does

| Feature | Status |
| --- | --- |
| Registration with e-mail confirmation | Working |
| Argon2id password hashing (64 MiB, 3 passes) | Working |
| Password policy and strength meter | Working |
| Generic error messages (no account enumeration) | Working |
| Per-account lockout after repeated failures | Working |
| Per-address throttle on top of the lockout | Working |
| TOTP two-factor authentication (RFC 6238) | Working |
| E-mail verification with a hashed, single-use token | Working |
| Password change with re-hash on every successful sign-in | Working |
| Account deletion | Working |
| Sign-in audit log with IP and user agent | Working |
| Security score and prioritised recommendations | Working |
| Strict Content-Security-Policy and hardened headers | Working |
| Automated test suite | 23 tests |

The secret for two-factor authentication is encrypted at rest with Fernet
before it is written to the database.

---

## Layout

```
secure_auth/
├── app/
│   ├── __init__.py          application factory, security headers
│   ├── config.py             environment configuration
│   ├── db.py                 SQLite access layer and schema migration
│   ├── mailer.py             SMTP delivery with a development fallback
│   ├── routes.py             every HTTP route
│   ├── security.py           hashing, password policy, tokens, TOTP
│   ├── static/
│   │   ├── app.js            password meter, score bars, copy button
│   │   └── style.css         the whole design system
│   └── templates/            base, login, register, dashboard, ...
├── tests/
│   ├── conftest.py
│   └── test_auth.py
├── data/                     created at runtime, ignored by git
├── run.py                    development entry point
├── requirements.txt
├── requirements-dev.txt
├── .env.example
└── README.md
```

---

## Running it

### Windows PowerShell

```powershell
cd "C:\Users\deepe\Secure Authentication System\secure_auth"

python -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt
pip install -r requirements-dev.txt

python run.py
```

Open <http://127.0.0.1:5000/register>.

### macOS / Linux

```bash
cd secure_auth
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

### Running the tests

```powershell
pytest -q
```

---

## Configuration

Copy `.env.example` to `.env` and edit it. Real environment variables always
override the file.

| Variable | Default | Notes |
| --- | --- | --- |
| `SECRET_KEY` | generated in development | **Required** when `PRODUCTION=1` |
| `PRODUCTION` | `0` | Set to `1` only behind HTTPS |
| `DATABASE_PATH` | `data/secureauth.sqlite3` | SQLite file location |
| `SESSION_LIFETIME_MINUTES` | `30` | Maximum session lifetime |
| `IDLE_TIMEOUT_MINUTES` | `15` | Sign out after this much inactivity |
| `MAX_LOGIN_ATTEMPTS` | `5` | Failures before the account locks |
| `LOCKOUT_MINUTES` | `15` | Length of the lock |
| `TWO_FACTOR_WINDOW` | `1` | TOTP steps accepted either side of now |
| `MAIL_SERVER` | empty | Empty means development mode |

### Development mode e-mail

With no `MAIL_SERVER` configured, outgoing messages are written to
`data/outbox/` and the confirmation link is shown directly in the browser.
That makes the whole verification flow testable without a mail server.

---

## Security notes

* **Passwords** are hashed with Argon2id. The hash is re-generated with
  current parameters whenever the parameters change, so old accounts upgrade
  silently on their next sign-in.
* **Account enumeration** is blocked. An unknown address performs the same
  Argon2 work as a known one and returns the same message.
* **Sessions** are signed, `HttpOnly`, `SameSite=Lax`, `Secure` in production,
  and use the `__Host-` cookie prefix when served over HTTPS. The session id
  is regenerated on sign-in, and the session version in the database
  invalidates every other device after a password change.
* **CSRF** is enforced on every state-changing route, including sign-out and
  account deletion.
* **CSP** is strict: no `unsafe-inline`, no inline scripts and no inline style
  attributes anywhere in the templates. The progress bars are driven by
  `data-score` attributes that `app.js` turns into widths, so the policy stays
  tight instead of being weakened for the sake of a bar.
* **Two-factor secrets** are encrypted with Fernet using a key derived from
  `SECRET_KEY`, and the stored value is never shown again after setup.
* **Verification tokens** are stored as a SHA-256 digest, so the database never
  contains a usable token.

### Before deploying

1. Set a strong random `SECRET_KEY` (at least 32 characters).
2. Serve over HTTPS and set `PRODUCTION=1`.
3. Configure real SMTP so verification e-mails are delivered.
4. Put a real WSGI server in front of `app:create_app()`. The built-in Flask
   server is for development only.
5. Back up the SQLite file. `init_db` upgrades the schema in place and never
   deletes rows, but a backup is still worth having.

---

## API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` `POST` | `/register` | Create an account |
| `GET` `POST` | `/login` | Sign in |
| `GET` `POST` | `/two-factor` | Second factor challenge |
| `GET` `POST` | `/two-factor/setup` | Enrol an authenticator app |
| `POST` | `/two-factor/disable` | Turn two-factor off |
| `GET` `POST` | `/verify-email` | Confirm an address |
| `POST` | `/resend-verification` | Send a new confirmation link |
| `GET` | `/dashboard` | Security overview |
| `GET` `POST` | `/change-password` | Change the password |
| `GET` `POST` | `/account` | Account details and deletion |
| `POST` | `/logout` | Sign out |
| `GET` | `/healthz` | Liveness probe |


## Reviewed updates
- Fixed the login OTP template context and form action.
- Replaced the authenticator-app setup instructions with the existing email-OTP setup flow.
- Integrated the floating holographic Help Agent into the shared base template.

## Local setup
This package excludes `.env`, local databases/outbox, `.venv`, and caches. Create `.env` from `.env.example` and enter your own credentials privately. Run `python run.py`. Test registration, email verification, login OTP, and enabling email-based 2FA. The Help Agent uses built-in local guidance; it is not connected to an external AI API.
