
"""Outgoing e-mail.

When SMTP is configured, the message is delivered for real.
When SMTP is not configured, the message is written to data/outbox.
"""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path

from flask import current_app


def _smtp_is_configured() -> bool:
    return bool(current_app.config.get("MAIL_SERVER"))


def deliver(to: str, subject: str, body: str) -> str | None:
    """Send an e-mail.

    Returns:
        "smtp"   - email sent successfully
        "outbox" - saved locally because SMTP is not configured
        "failed" - SMTP delivery failed
    """
    if not _smtp_is_configured():
        _write_to_outbox(to, subject, body)
        return "outbox"

    try:
        message = EmailMessage()
        message["From"] = current_app.config["MAIL_FROM"]
        message["To"] = to
        message["Subject"] = subject
        message.set_content(body)

        mail_server = current_app.config["MAIL_SERVER"]
        mail_port = int(current_app.config.get("MAIL_PORT", 587))
        username = current_app.config.get("MAIL_USERNAME")
        password = current_app.config.get("MAIL_PASSWORD")
        use_tls = current_app.config.get("MAIL_USE_TLS", True)

        if mail_port == 465:
            # Gmail SSL connection (port 465)
            with smtplib.SMTP_SSL(
                mail_server,
                mail_port,
                timeout=20,
                context=ssl.create_default_context(),
            ) as server:
                if username:
                    server.login(username, password)
                server.send_message(message)

        else:
            # SMTP with STARTTLS (normally port 587)
            with smtplib.SMTP(
                mail_server,
                mail_port,
                timeout=20,
            ) as server:
                server.ehlo()

                if use_tls:
                    server.starttls(context=ssl.create_default_context())
                    server.ehlo()

                if username:
                    server.login(username, password)

                server.send_message(message)

        current_app.logger.info("E-mail sent successfully to %s", to)
        return "smtp"

    except Exception:
        current_app.logger.exception(
            "Could not deliver e-mail to %s", to
        )
        _write_to_outbox(to, subject, body)
        return "failed"


def _write_to_outbox(to: str, subject: str, body: str) -> Path:
    """Store the message on disk and return the file path."""
    outbox = Path(current_app.config["OUTBOX_DIR"])
    outbox.mkdir(parents=True, exist_ok=True)

    from datetime import datetime, timezone

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    safe_recipient = to.replace("@", "_at_").replace("/", "_").replace("\\", "_")
    path = outbox / f"{stamp}-{safe_recipient}.txt"

    path.write_text(
        f"To: {to}\nSubject: {subject}\n\n{body}\n",
        encoding="utf-8",
    )
    return path
