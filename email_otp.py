
import os
import smtplib
from email.message import EmailMessage


def send_otp_email(recipient, otp):
    smtp_server = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    smtp_port = int(os.environ.get("MAIL_PORT", "587"))
    sender = os.environ.get("MAIL_USERNAME")
    app_password = os.environ.get("MAIL_PASSWORD")

    if not sender or not app_password:
        raise RuntimeError(
            "MAIL_USERNAME and MAIL_PASSWORD must be configured."
        )

    message = EmailMessage()
    message["Subject"] = "Your SecureAuth verification code"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        f"""Your SecureAuth verification code is: {otp}

This code expires in 5 minutes.
If you did not request this code, you can ignore this email.
Do not share this code with anyone."""
    )

    with smtplib.SMTP("smtp.gmail.com", 587, timeout=15) as server:
       server.set_debuglevel(1)
    server.starttls()
    server.login(sender, app_password)
    server.send_message(message)