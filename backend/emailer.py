import os
import smtplib
from email.message import EmailMessage


def send_email(to_email: str, subject: str, body: str) -> None:
    """Send an email using SMTP settings from env vars.

    Required env vars (set in Render dashboard):
      - SMTP_HOST
      - SMTP_PORT (default 587)
      - SMTP_USER (optional)
      - SMTP_PASS (optional)
      - SMTP_FROM (default 'TruthStamp <no-reply@truthstamp.local>')
    """
    host = os.getenv("SMTP_HOST", "").strip()
    if not host:
        # Email not configured; silently no-op for MVP
        return

    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER", "").strip()
    password = os.getenv("SMTP_PASS", "").strip()
    from_addr = os.getenv("SMTP_FROM", "TruthStamp <no-reply@truthstamp.local>").strip()

    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP(host, port, timeout=15) as server:
        server.ehlo()
        if port in (587, 25):
            try:
                server.starttls()
                server.ehlo()
            except Exception:
                # some providers might not support STARTTLS on this port
                pass
        if user and password:
            server.login(user, password)
        server.send_message(msg)
