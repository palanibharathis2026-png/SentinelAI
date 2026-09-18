"""Email for OTP codes and security notices.

Every message is stored in the outbox table so the SOC can see it in the dashboard.
If SMTP is configured in .env (e.g. Gmail with an app password) it is also really sent;
otherwise delivery is "demo" and the outbox is the only copy.
"""
import logging
import os
import smtplib
import threading
from email.message import EmailMessage

from database import SessionLocal
from models import MailMessage
import simulator

log = logging.getLogger("sentinel.mail")

DEMO_DOMAIN = ".demo"  # placeholder addresses such as rahul@staff.demo are never sent


def smtp_config() -> dict | None:
    host, user, password = os.getenv("SMTP_HOST"), os.getenv("SMTP_USER"), os.getenv("SMTP_PASSWORD")
    if not (host and user and password):
        return None
    return {"host": host, "port": int(os.getenv("SMTP_PORT", "587")), "user": user, "password": password,
            "sender": os.getenv("MAIL_FROM") or user}


def _deliver(message_id: int, to: str, subject: str, body: str, cfg: dict) -> None:
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = f"SentinelAI <{cfg['sender']}>", to, subject
    msg.set_content(body)
    delivery, error = "sent", None
    try:
        if cfg["port"] == 465:
            with smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=20) as s:
                s.login(cfg["user"], cfg["password"])
                s.send_message(msg)
        else:
            with smtplib.SMTP(cfg["host"], cfg["port"], timeout=20) as s:
                s.starttls()
                s.login(cfg["user"], cfg["password"])
                s.send_message(msg)
    except (OSError, smtplib.SMTPException) as e:
        delivery, error = "failed", str(e)[:300]
        log.warning("Email to %s failed: %s", to, e)
    with SessionLocal() as db:
        row = db.get(MailMessage, message_id)
        if row:
            row.delivery, row.error = delivery, error
            db.commit()


def send(db, to: str, subject: str, body: str, kind: str, user_id: str | None = None) -> MailMessage:
    """Store the message in the outbox and, when possible, send it in the background."""
    cfg = smtp_config()
    real = cfg is not None and "@" in to and not to.endswith(DEMO_DOMAIN)
    row = MailMessage(created_at=simulator.now_ist(), to=to, subject=subject, body=body, kind=kind,
                      user_id=user_id, delivery="sending" if real else "demo")
    db.add(row)
    db.commit()
    db.refresh(row)
    if real:
        threading.Thread(target=_deliver, args=(row.id, to, subject, body, cfg), daemon=True).start()
    return row
