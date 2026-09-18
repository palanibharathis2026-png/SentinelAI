"""Unlink the admin's authenticator app (e.g. a lost phone). The next admin login shows a new QR code.

Usage (from the backend folder, with the API stopped or running):
    python reset_admin_2fa.py
"""
from database import SessionLocal, init_db
from models import Setting

init_db()
with SessionLocal() as db:
    for key in ("admin_totp_secret", "admin_totp_pending"):
        row = db.get(Setting, key)
        if row:
            db.delete(row)
    db.commit()
print("Admin authenticator unlinked. Sign in as the admin to scan a new QR code.")
