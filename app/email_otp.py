
import os
import smtplib
from email.message import EmailMessage


def send_otp_email(recipient, otp):
    sender = os.getenv("MAIL_USERNAME")
    app_password = os.getenv("MAIL_PASSWORD")

    if not sender or not app_password:
        raise RuntimeError("Email credentials are not configured.")

    message = EmailMessage()
    message["Subject"] = "SecureAuth - Verification Code"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        f"Your SecureAuth verification code is {otp}.\n"
        "It expires in 5 minutes. Do not share this code."
    )

    with smtplib.SMTP("smtp.gmail.com", 587, timeout=15) as server:
        server.starttls()
        server.login(sender, app_password)
        server.send_message(message)
