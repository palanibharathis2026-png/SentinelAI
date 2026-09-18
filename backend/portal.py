"""Logins, the staff portal, access control and the mail outbox.

Staff sign in with ID + password + a one-time code sent by email. Every portal session is a
real session scored by SentinelAI. Opening a system you have no permission for locks the
account until an admin unlocks it; the admin is emailed about logins, denials and requests.
"""
import hashlib
import re
import hmac
import os
import secrets
import threading
import time
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

import auth
import mailer
import mode
import simulator
from common import ALERT_TIERS, audit, event_out, get_employee, get_event, latest_time, names
from database import get_db
from feature_engineering import haversine_km
from detection_service import sentinel
from models import AccessRequest, AuditLog, Employee, Event, MailMessage, Setting, StaffAccess, StaffAccount

router = APIRouter()

OTP_REQUIRED = os.getenv("OTP_REQUIRED", "true").lower() == "true"
OTP_SECONDS, OTP_MAX_TRIES = 300, 3
ONLINE_SECONDS = 45
ALL_SYSTEMS = sorted(set(simulator.HIGH_VALUE) | {r for rs in simulator.ROLE_RESOURCES.values() for r in rs})

# In-memory state (fine for a single-process demo server).
failed_logins: dict[str, int] = {}      # wrong passwords/codes per username since the last success
otp_challenges: dict[str, dict] = {}    # challenge id -> pending second factor
presence: dict[str, dict] = {}          # user_id -> signed-in portal session
presence_lock = threading.Lock()
revoked_sessions: set[int] = set()      # portal sessions the SOC force-signed-out
admin_failures: list[float] = []
ADMIN_MAX_FAILURES, ADMIN_LOCK_SECONDS = 5, 120
admin_challenges: dict[str, dict] = {}   # password accepted, waiting for the app or email code
ADMIN_EMAIL_RESEND_SECONDS = 30
STAFF_MAX_FAILURES = 5                   # wrong passwords in a row before a staff account is locked


# ------------------------------------------------------------------ helpers
def _access(db: Session, user_id: str) -> StaffAccess:
    """Access settings for a staff member, created with their role's usual systems on first use."""
    acc = db.get(StaffAccess, user_id)
    if acc is None:
        acc = StaffAccess(user_id=user_id, email=None, permissions=list(simulator.PROFILES[user_id]["resources"]),
                          known_emails=[], known_devices=[])
        db.add(acc)
        db.commit()
    for device in acc.known_devices or []:  # keep the engine in sync after a restart
        sentinel.enroll_device(user_id, device)
    return acc


def _staff_email(acc: StaffAccess) -> str:
    return acc.email or f"{auth.staff_usernames().get(acc.user_id, acc.user_id.lower())}@staff.demo"


def _admin_email(db: Session) -> str:
    row = db.get(Setting, "admin_email")
    return (row.value if row and row.value else None) or os.getenv("ADMIN_EMAIL") or "toby@soc.demo"


def _is_usual_email(acc: StaffAccess, email: str) -> bool:
    email = email.strip().lower()
    return email == _staff_email(acc).lower() or email in (acc.known_emails or [])


def _valid_email(email: str) -> bool:
    local, _, domain = email.partition("@")
    return bool(local) and "." in domain and " " not in email


def _resolve_location(lat: float | None, lon: float | None, home_city: str) -> tuple[str, str, float, float, str]:
    """(city, country, lat, lon, source) from the device's own location (GPS / mobile network / Wi-Fi).

    Snaps to the nearest known office city within 150 km; otherwise keeps the raw coordinates.
    Without a device location, falls back to the employee's usual office.
    """
    if lat is None or lon is None or not (-90 <= lat <= 90 and -180 <= lon <= 180):
        country, hlat, hlon = simulator.LOCATIONS[home_city]
        return home_city, country, hlat, hlon, "office (no device location)"
    city, (country, clat, clon) = min(simulator.LOCATIONS.items(),
                                      key=lambda kv: haversine_km(lat, lon, kv[1][1], kv[1][2]))
    if haversine_km(lat, lon, clat, clon) <= 150:
        return city, country, round(lat, 4), round(lon, 4), "device"
    in_india = 6 <= lat <= 37.5 and 68 <= lon <= 97.5
    return (f"GPS {lat:.2f}, {lon:.2f}", "India" if in_india else "Unknown country",
            round(lat, 4), round(lon, 4), "device")


def _mask(email: str) -> str:
    local, _, domain = email.partition("@")
    return f"{local[:2]}{'*' * max(1, len(local) - 2)}@{domain}"


def _real_delivery(email: str) -> bool:
    return mailer.smtp_config() is not None and not email.endswith(mailer.DEMO_DOMAIN)


def _notify_admin(db: Session, subject: str, body: str, kind: str, user_id: str | None = None) -> None:
    mailer.send(db, _admin_email(db), f"[SentinelAI] {subject}", body, kind, user_id)


def _lock(db: Session, user_id: str, reason: str) -> None:
    emp = get_employee(db, user_id)
    emp.status, emp.status_reason, emp.status_changed_at = "blocked", reason, simulator.now_ist()
    db.commit()


def _claims(request: Request, role: str = "staff") -> dict:
    claims = request.state.user
    if claims["role"] != role:
        raise HTTPException(403, "Staff only" if role == "staff" else "Admins only")
    if claims.get("event_id") in revoked_sessions:
        raise HTTPException(401, "You were signed out by the security team.")
    return claims


def _staff_view(db: Session, user_id: str, event_id: int) -> dict:
    """What a staff member sees about their own session: no scores, just the outcome."""
    emp = get_employee(db, user_id)
    row = get_event(db, event_id)
    acc = _access(db, user_id)
    twin = sentinel.twin(user_id)
    check = "locked" if emp.status == "blocked" else "mfa" if row.tier == "MFA" else "verified"
    pending = db.scalars(select(AccessRequest.resource).where(AccessRequest.user_id == user_id,
                                                              AccessRequest.status == "pending")).all()
    return {
        "employee": {"id": emp.id, "name": emp.name, "role": emp.role, "department": emp.department,
                     "home_city": emp.home_city, "status": emp.status, "status_reason": emp.status_reason},
        "session": {"id": row.id, "login_at": row.timestamp, "city": row.city, "country": row.country,
                    "device": f"{row.os} / {row.browser}", "files_downloaded": row.files_downloaded,
                    "resources": row.resources or [], "actions": row.actions or []},
        "security_check": check,
        "email": _mask(_staff_email(acc)),
        "email_full": _staff_email(acc),
        "permissions": acc.permissions or [],
        "familiar": [r for r in twin.get("familiar_resources", [])] + list(row.resources or []),
        "pending_requests": list(pending),
        "all_systems": ALL_SYSTEMS,
        "usual_systems": [r for r in simulator.PROFILES[user_id]["resources"] if r in (acc.permissions or [])],
        "shared_files": simulator.HONEYTOKENS,
    }


# ------------------------------------------------------------------ admin login
class LoginRequest(BaseModel):
    username: str
    password: str


def _setting(db: Session, key: str) -> str | None:
    row = db.get(Setting, key)
    return row.value if row else None


def _set_setting(db: Session, key: str, value: str | None) -> None:
    db.merge(Setting(key=key, value=value))
    db.commit()


def _admin_throttle() -> None:
    now = time.time()
    admin_failures[:] = [t for t in admin_failures if now - t < ADMIN_LOCK_SECONDS]
    if len(admin_failures) >= ADMIN_MAX_FAILURES:
        wait = int(ADMIN_LOCK_SECONDS - (now - admin_failures[0])) + 1
        raise HTTPException(429, f"Too many wrong attempts. Admin login is paused for {wait} seconds.")


def _admin_token(db: Session, request: Request) -> dict:
    name = auth.ADMIN_USERNAME
    audit(db, request, "admin_login", name, "password + authenticator code" if auth.ADMIN_2FA else "password", actor=name)
    return {"token": auth.issue("admin", name, name), "role": "admin", "name": name}


@router.post("/api/auth/login")
def admin_login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """Step 1: admin password. Step 2 (/api/auth/admin-2fa): code from an authenticator app."""
    _admin_throttle()
    if not auth.check_admin(body.username, body.password):
        admin_failures.append(time.time())
        audit(db, request, "admin_login_failed", body.username[:40], "wrong username or password", actor="anonymous")
        raise HTTPException(401, "Wrong username or password")
    if not auth.ADMIN_2FA:
        admin_failures.clear()
        return _admin_token(db, request)
    cid = secrets.token_urlsafe(16)
    admin_challenges[cid] = {"expires": time.time() + OTP_SECONDS, "email_code": None, "tries": 0, "sent_at": 0.0}
    email = _admin_email(db)
    extra = {"email_available": _real_delivery(email), "email": _mask(email)}
    if extra["email_available"]:  # email is set up: send the code straight away (the app code works too)
        _send_admin_code(db, cid)
        extra["email_sent"] = True
    if _setting(db, "admin_totp_secret"):
        return {"mfa_required": True, "challenge_id": cid, "enrolled": True, **extra}
    # First sign-in: set up the authenticator app. The secret only becomes active once a code is confirmed.
    pending = _setting(db, "admin_totp_pending") or auth.new_totp_secret()
    _set_setting(db, "admin_totp_pending", pending)
    return {"mfa_required": True, "challenge_id": cid, "enrolled": False, "secret": pending,
            "otpauth_uri": auth.totp_uri(pending, auth.ADMIN_USERNAME), **extra}


def _send_admin_code(db: Session, cid: str) -> None:
    ch = admin_challenges[cid]
    code = f"{secrets.randbelow(1_000_000):06d}"
    ch.update(email_code=hashlib.sha256(code.encode()).hexdigest(), tries=0, sent_at=time.time(),
              expires=time.time() + OTP_SECONDS)
    mailer.send(db, _admin_email(db), f"SentinelAI admin sign-in code: {code}",
                f"Your SentinelAI admin sign-in code is {code}. It expires in {OTP_SECONDS // 60} minutes.\n\n"
                "Someone entered the correct admin password. If this wasn't you, change the admin password now.",
                "otp")


class AdminEmailCode(BaseModel):
    challenge_id: str


@router.post("/api/auth/admin-email-code")
def admin_email_code(body: AdminEmailCode, db: Session = Depends(get_db)):
    """Send (or re-send) the admin sign-in code to the admin's email address."""
    ch = admin_challenges.get(body.challenge_id)
    if not ch or ch["expires"] < time.time():
        raise HTTPException(401, "This sign-in expired. Enter your password again.")
    email = _admin_email(db)
    if not _real_delivery(email):
        raise HTTPException(400, "Email sending isn't set up yet (SMTP settings and ADMIN_EMAIL in .env). "
                                 "Use the authenticator app for now.")
    wait = ADMIN_EMAIL_RESEND_SECONDS - (time.time() - ch["sent_at"])
    if wait > 0:
        raise HTTPException(429, f"A code was just sent. Wait {int(wait) + 1} seconds before asking again.")
    _send_admin_code(db, body.challenge_id)
    return {"sent_to": _mask(email)}


class AdminCode(BaseModel):
    challenge_id: str
    code: str


@router.post("/api/auth/admin-2fa")
def admin_second_factor(body: AdminCode, request: Request, db: Session = Depends(get_db)):
    _admin_throttle()
    ch = admin_challenges.get(body.challenge_id)
    if not ch or ch["expires"] < time.time():
        admin_challenges.pop(body.challenge_id, None)
        raise HTTPException(401, "This sign-in expired. Enter your password again.")
    secret = _setting(db, "admin_totp_secret")
    enrolling = secret is None
    secret = secret or _setting(db, "admin_totp_pending")
    by_app = bool(secret) and auth.verify_totp(secret, body.code)
    by_email = bool(ch["email_code"]) and ch["tries"] < OTP_MAX_TRIES and hmac.compare_digest(
        ch["email_code"], hashlib.sha256(body.code.encode()).hexdigest())
    if not (by_app or by_email):
        ch["tries"] += 1
        admin_failures.append(time.time())
        audit(db, request, "admin_2fa_failed", auth.ADMIN_USERNAME, "wrong verification code", actor="anonymous")
        raise HTTPException(401, "Wrong or expired code. Use the code from your email or your authenticator app.")
    admin_challenges.pop(body.challenge_id, None)
    admin_failures.clear()
    if by_email and not by_app:
        audit(db, request, "admin_2fa_email", auth.ADMIN_USERNAME, "verified with an emailed code", actor=auth.ADMIN_USERNAME)
        return _admin_token(db, request)
    if enrolling:
        _set_setting(db, "admin_totp_secret", secret)
        _set_setting(db, "admin_totp_pending", None)
        audit(db, request, "admin_2fa_enrolled", auth.ADMIN_USERNAME, "authenticator app linked", actor=auth.ADMIN_USERNAME)
    return _admin_token(db, request)


# ------------------------------------------------------------------ staff login (password + OTP)
class StaffLoginRequest(LoginRequest):
    lat: float | None = None  # from the browser's geolocation (GPS / mobile network / Wi-Fi)
    lon: float | None = None
    email: str | None = None  # "send my code to": blank = the registered address


class OtpRequest(BaseModel):
    challenge_id: str
    code: str


def _start_session(db: Session, username: str, user_id: str, where: tuple, ua: str, ip: str,
                   new_email: str | None = None, enroll: bool = False) -> dict:
    emp = get_employee(db, user_id)
    city, country, lat, lon, loc_source = where
    os_name, browser = auth.device_from_user_agent(ua)
    if enroll:
        # The one-time code reached this person's usual inbox, so this device is now trusted for them.
        acc = _access(db, user_id)
        device = f"{os_name} / {browser}"
        if device not in (acc.known_devices or []):
            acc.known_devices = sorted(set(acc.known_devices or []) | {device})
            db.commit()
        sentinel.enroll_device(user_id, device)
    event = {
        "user_id": user_id, "timestamp": simulator.now_ist(), "city": city, "country": country,
        "lat": lat, "lon": lon, "ip": ip, "os": os_name, "browser": browser,
        "failed_attempts": failed_logins.pop(username, 0), "files_downloaded": 0, "mb_downloaded": 0.0,
        "api_calls": 5, "sensitive_access": 0, "session_minutes": 1, "resources": [],
        "actions": [f"new_email:{new_email}"] if new_email else [], "scenario": None,
    }
    row = sentinel.ingest(db, event, "portal")
    with presence_lock:
        presence[user_id] = {"event_id": row.id, "login_at": row.timestamp, "last_seen": time.time()}
    _notify_admin(
        db, f"{emp.name} signed in ({row.tier}, risk {row.risk})",
        f"{emp.name} ({emp.role}) signed in to the staff portal.\n\n"
        f"Time: {row.timestamp:%d %b %Y %H:%M}\nLocation: {row.city}, {row.country} (from {loc_source})\n"
        f"Device: {row.os} / {row.browser}\n"
        f"Failed attempts before success: {row.failed_attempts}\nVerdict: {row.tier} (risk {row.risk}/100)\n"
        + (f"WARNING: the sign-in code went to an unfamiliar email ({new_email})\n" if new_email else "")
        + (f"Likely threat: {row.threat}\n" if row.threat else "")
        + "\nOpen the SentinelAI dashboard to review or lock the session.",
        "login", user_id)
    audit(db, None, "staff_login", user_id, f"{row.city} · {row.os} / {row.browser} · {row.tier} {row.risk}", actor=username)
    token = auth.issue("staff", user_id, emp.name, event_id=row.id)
    return {"token": token, "role": "staff", "name": emp.name}


@router.post("/api/auth/staff-login")
def staff_login(body: StaffLoginRequest, request: Request, db: Session = Depends(get_db)):
    """Step 1: staff ID + password. With OTP on, this emails a 6-digit code instead of signing in."""
    if mode.CERT:
        raise HTTPException(403, "The staff portal is off while SentinelAI runs on the real CERT data. " + mode.DEMO_ONLY)
    username = body.username.strip().lower()
    account = auth.staff_account(username)
    if account and get_employee(db, account[1]).status == "blocked":
        raise HTTPException(403, "This account is locked. Ask your security admin to unlock it.")
    if not account or not auth.verify_password(body.password, account[0]):
        if account:
            failed_logins[username] = failed_logins.get(username, 0) + 1
            audit(db, request, "staff_login_failed", account[1], f"wrong password ({failed_logins[username]} in a row)",
                  actor="anonymous")
            if failed_logins[username] >= STAFF_MAX_FAILURES:
                emp = get_employee(db, account[1])
                _lock(db, account[1], f"Locked after {STAFF_MAX_FAILURES} wrong passwords in a row (possible password guessing)")
                _notify_admin(db, f"Account locked: {STAFF_MAX_FAILURES} wrong passwords for {emp.name}",
                              f"Someone entered a wrong password for {emp.name} {STAFF_MAX_FAILURES} times in a row. "
                              "The account is locked until you unlock it in SentinelAI > Access Control.", "alert", account[1])
                raise HTTPException(403, "Too many wrong passwords. This account is now locked; ask your security admin.")
        raise HTTPException(401, "Wrong staff ID or password")
    user_id = account[1]
    ua, ip = request.headers.get("user-agent", ""), request.client.host if request.client else "0.0.0.0"
    where = _resolve_location(body.lat, body.lon, simulator.PROFILES[user_id]["home_city"])
    acc = _access(db, user_id)
    emp = get_employee(db, user_id)
    registered = _staff_email(acc)
    target = (body.email or "").strip().lower() or registered
    if not _valid_email(target):
        raise HTTPException(400, "That does not look like an email address")
    unusual = not _is_usual_email(acc, target)
    if unusual:
        # Classic takeover move: the attacker has the password and redirects the code to their own inbox.
        mailer.send(db, registered, "Security alert: someone asked for your code at a different email",
                    f"Hi {emp.name.split()[0]},\n\nSomeone signed in with your password and asked for the sign-in code "
                    f"to be sent to {target}, which is not your usual email. If this was not you, change your password "
                    "and tell your security team now.", "alert", user_id)
        _notify_admin(db, f"Unfamiliar email used for {emp.name}",
                      f"{emp.name}'s sign-in code was requested at {target} instead of their usual address "
                      f"{registered}. SentinelAI will score this session with an 'Unfamiliar email' signal.",
                      "alert", user_id)
    if not OTP_REQUIRED:
        return _start_session(db, username, user_id, where, ua, ip, target if unusual else None)

    now = time.time()
    for cid in [c for c, v in otp_challenges.items() if v["expires"] < now]:
        otp_challenges.pop(cid)
    code = f"{secrets.randbelow(10**6):06d}"
    cid = secrets.token_urlsafe(16)
    otp_challenges[cid] = {"username": username, "user_id": user_id, "where": where, "ua": ua, "ip": ip,
                           "new_email": target if unusual else None,
                           "code_hash": hashlib.sha256(code.encode()).hexdigest(), "expires": now + OTP_SECONDS,
                           "tries": 0}
    email = target
    mailer.send(db, email, f"Your SentinelAI sign-in code: {code}",
                f"Hi {emp.name.split()[0]},\n\nYour one-time sign-in code is {code}. It expires in 5 minutes.\n\n"
                "If you did not try to sign in, someone may know your password: tell your security team now.",
                "otp", user_id)
    real = _real_delivery(email)
    return {"otp_required": True, "challenge_id": cid, "sent_to": _mask(email),
            "delivery": "email" if real else "demo",
            # Demo mode only (no SMTP / no real address): show the code so the demo still works.
            "demo_code": None if real else code}


@router.post("/api/auth/staff-otp")
def staff_otp(body: OtpRequest, db: Session = Depends(get_db)):
    """Step 2: the one-time code from the email completes the sign-in."""
    ch = otp_challenges.get(body.challenge_id)
    if not ch or ch["expires"] < time.time():
        otp_challenges.pop(body.challenge_id, None)
        raise HTTPException(401, "This code has expired. Sign in again to get a new one.")
    given = hashlib.sha256(body.code.strip().encode()).hexdigest()
    if not hmac.compare_digest(given, ch["code_hash"]):
        ch["tries"] += 1
        failed_logins[ch["username"]] = failed_logins.get(ch["username"], 0) + 1
        if ch["tries"] >= OTP_MAX_TRIES:
            otp_challenges.pop(body.challenge_id, None)
            emp = get_employee(db, ch["user_id"])
            _notify_admin(db, f"Repeated wrong OTP for {emp.name}",
                          f"Someone entered the correct password for {emp.name} but failed the one-time code "
                          f"{OTP_MAX_TRIES} times. The password may be stolen.", "alert", ch["user_id"])
            raise HTTPException(401, "Too many wrong codes. Sign in again to get a new code.")
        raise HTTPException(401, f"Wrong code. {OTP_MAX_TRIES - ch['tries']} tries left.")
    otp_challenges.pop(body.challenge_id, None)
    # Passing the code enrols the device, unless the code was redirected to an unfamiliar email.
    return _start_session(db, ch["username"], ch["user_id"], ch["where"], ch["ua"], ch["ip"], ch["new_email"],
                          enroll=ch["new_email"] is None)


# ------------------------------------------------------------------ staff portal
@router.get("/api/staff/me")
def staff_me(request: Request, db: Session = Depends(get_db)):
    c = _claims(request)
    return _staff_view(db, c["sub"], c["event_id"])


@router.post("/api/staff/me/heartbeat")
def staff_heartbeat(request: Request, db: Session = Depends(get_db)):
    c = _claims(request)
    with presence_lock:
        entry = presence.setdefault(c["sub"], {"event_id": c["event_id"], "login_at": simulator.now_ist()})
        entry["last_seen"] = time.time()
    row = get_event(db, c["event_id"])
    row.session_minutes = max(1, int((simulator.now_ist() - row.timestamp).total_seconds() // 60))
    db.commit()
    return _staff_view(db, c["sub"], c["event_id"])


class StaffActivity(BaseModel):
    kind: str  # work | extra | open | export | disable_audit_logs
    system: str | None = None


@router.post("/api/staff/me/activity")
def staff_activity(body: StaffActivity, request: Request, db: Session = Depends(get_db)):
    """Record real work done in the portal, then re-score the whole session."""
    c = _claims(request)
    user_id = c["sub"]
    emp = get_employee(db, user_id)
    if emp.status == "blocked":
        raise HTTPException(403, "This account is locked. Ask your security admin to unlock it.")
    p = simulator.PROFILES[user_id]
    acc = _access(db, user_id)
    perms = set(acc.permissions or [])
    row = get_event(db, c["event_id"])
    tier_before = row.tier
    resources, actions = set(row.resources or []), set(row.actions or [])
    denied_system = first_time_system = None

    if body.kind == "work":
        files = max(3, p["files"] // 2)
        row.files_downloaded += files
        row.mb_downloaded = round(row.mb_downloaded + files * p["mb_per_file"], 1)
        row.api_calls += max(5, p["api"] // 3)
        resources.update([r for r in p["resources"] if r in perms][:2])
    elif body.kind == "extra":
        files = p["files"] * 3
        row.files_downloaded += files
        row.mb_downloaded = round(row.mb_downloaded + files * p["mb_per_file"], 1)
        row.sensitive_access += max(1, files // 10)
        row.api_calls += p["api"] // 2
    elif body.kind == "open":
        system = body.system
        if not system:
            raise HTTPException(400, "Choose a system to open")
        if system in simulator.HONEYTOKENS:
            resources.add(system)  # the shared drive is open to everyone: that is what makes it a trap
        elif system not in perms:
            actions.add(f"denied:{system}")
            denied_system = system
        else:
            if system not in sentinel.twin(user_id).get("familiar_resources", []) and system not in resources:
                first_time_system = system
            resources.add(system)
            row.sensitive_access += 2
            row.api_calls += 15
    elif body.kind == "export":
        files = p["files"] * 30
        row.files_downloaded += files
        row.mb_downloaded = round(row.mb_downloaded + files * p["mb_per_file"] * 1.2, 1)
        row.sensitive_access += int(files * 0.6)
        row.api_calls += p["api"]
        actions.add("bulk_export")
    elif body.kind == "disable_audit_logs":
        actions.add("disable_audit_logs")
    else:
        raise HTTPException(400, "Unknown activity")

    row.resources, row.actions = sorted(resources), sorted(actions)
    row.session_minutes = max(1, int((simulator.now_ist() - row.timestamp).total_seconds() // 60))
    sentinel.rescore(db, row)
    staff_email = _staff_email(acc)

    if denied_system:
        _lock(db, user_id, f"Temporarily locked: tried to open {denied_system} without permission")
        _notify_admin(db, f"ACCESS DENIED: {emp.name} tried to open {denied_system}",
                      f"{emp.name} ({emp.role}) tried to open {denied_system}, which they have no permission for.\n"
                      f"The account is locked until you unlock it in SentinelAI > Access Control.\n\n"
                      f"Session risk: {row.risk}/100 ({row.tier}).", "denied", user_id)
        mailer.send(db, staff_email, "Security notice: your account is temporarily locked",
                    f"Hi {emp.name.split()[0]},\n\nYou tried to open {denied_system}, which your role does not have "
                    "access to. For safety your account is locked until the security admin reviews it.\n"
                    "If you need this system, ask your admin to grant access.", "denied", user_id)
    elif first_time_system:
        mailer.send(db, staff_email, f"Security notice: first-time access to {first_time_system}",
                    f"Hi {emp.name.split()[0]},\n\nYou opened {first_time_system} for the first time. "
                    "This was recorded by SentinelAI. If this was not you, tell your security team.",
                    "first_access", user_id)
        _notify_admin(db, f"{emp.name} opened {first_time_system} for the first time",
                      f"{emp.name} ({emp.role}) has permission for {first_time_system} and opened it for the first "
                      f"time.\nSession risk: {row.risk}/100 ({row.tier}).", "first_access", user_id)
    if row.tier in ALERT_TIERS and tier_before not in ALERT_TIERS:
        _notify_admin(db, f"{row.tier}: {emp.name} (risk {row.risk})",
                      f"SentinelAI raised {emp.name}'s live session to {row.tier} (risk {row.risk}/100).\n"
                      f"Likely threat: {row.threat or 'behavioural anomaly'}\nReasons:\n"
                      + "\n".join(f"- {r['signal']} (+{r['points']}): {r['detail']}" for r in row.reasons),
                      "alert", user_id)
    return _staff_view(db, user_id, c["event_id"]) | {"denied": denied_system, "first_time": first_time_system}


class AccessAsk(BaseModel):
    system: str


@router.post("/api/staff/me/request-access")
def request_access(body: AccessAsk, request: Request, db: Session = Depends(get_db)):
    c = _claims(request)
    if body.system not in ALL_SYSTEMS:
        raise HTTPException(400, "Unknown system")
    exists = db.scalar(select(AccessRequest).where(AccessRequest.user_id == c["sub"], AccessRequest.resource == body.system,
                                                   AccessRequest.status == "pending"))
    if not exists:
        db.add(AccessRequest(user_id=c["sub"], resource=body.system, created_at=simulator.now_ist(), status="pending"))
        db.commit()
        emp = get_employee(db, c["sub"])
        _notify_admin(db, f"Access request: {emp.name} wants {body.system}",
                      f"{emp.name} ({emp.role}) asked for access to {body.system}.\n"
                      "Approve or deny it in SentinelAI > Access Control.", "request", c["sub"])
    return _staff_view(db, c["sub"], c["event_id"])


class EmailChange(BaseModel):
    email: str


@router.post("/api/staff/me/email")
def change_my_email(body: EmailChange, request: Request, db: Session = Depends(get_db)):
    """Staff changes their contact email. A sudden switch to a never-used address is scored and reported."""
    c = _claims(request)
    user_id = c["sub"]
    email = body.email.strip().lower()
    if not _valid_email(email):
        raise HTTPException(400, "That does not look like an email address")
    acc = _access(db, user_id)
    emp = get_employee(db, user_id)
    old = _staff_email(acc)
    if email == old.lower():
        return _staff_view(db, user_id, c["event_id"])
    unusual = not _is_usual_email(acc, email)
    acc.email = email
    db.commit()
    if unusual:
        row = get_event(db, c["event_id"])
        tier_before = row.tier
        row.actions = sorted(set(row.actions or []) | {f"new_email:{email}"})
        sentinel.rescore(db, row)
        mailer.send(db, old, "Security alert: your account email was changed",
                    f"Hi {emp.name.split()[0]},\n\nYour account email was just changed to {email}. "
                    "If this was not you, your account may be taken over: tell your security team now.",
                    "alert", user_id)
        _notify_admin(db, f"{emp.name} changed email to an unfamiliar address",
                      f"{emp.name} switched their account email from {old} to {email} during a live session.\n"
                      f"Session risk is now {row.risk}/100 ({row.tier}). Attackers do this to receive future codes.",
                      "alert", user_id)
        if row.tier in ALERT_TIERS and tier_before not in ALERT_TIERS:
            _notify_admin(db, f"{row.tier}: {emp.name} (risk {row.risk})",
                          f"Likely threat: {row.threat}", "alert", user_id)
    return _staff_view(db, user_id, c["event_id"])


@router.post("/api/staff/me/logout")
def staff_logout(request: Request):
    with presence_lock:
        presence.pop(_claims(request)["sub"], None)
    return {"status": "logged out"}


# ------------------------------------------------------------------ admin: live staff
@router.post("/api/staff/{user_id}/signout")
def force_signout(user_id: str, request: Request, db: Session = Depends(get_db)):
    """SOC action: end someone's portal session right now."""
    with presence_lock:
        entry = presence.pop(user_id, None)
    if not entry:
        raise HTTPException(404, "That person is not signed in")
    revoked_sessions.add(entry["event_id"])
    audit(db, request, "force_signout", user_id)
    return {"status": "signed out", "user_id": user_id}


@router.get("/api/staff/challenge")
def challenge(db: Session = Depends(get_db)):
    """'Steal data without getting caught' scoreboard for guests who tried the staff portal (last 24 h)."""
    since = latest_time(db) - timedelta(hours=24)
    rows = db.scalars(select(Event).where(Event.source == "portal", Event.timestamp >= since)
                      .order_by(Event.timestamp.desc())).all()
    who = names(db)
    attempts = [{
        "event_id": e.id, "name": who.get(e.user_id, e.user_id), "timestamp": e.timestamp,
        "mb": e.mb_downloaded, "files": e.files_downloaded, "risk": e.risk, "tier": e.tier,
        "caught": e.tier in ALERT_TIERS, "threat": e.threat,
    } for e in rows]
    tried = [a for a in attempts if a["files"] > 0 or a["caught"]]
    return {
        "attempts": len(tried),
        "caught": sum(a["caught"] for a in tried),
        "best_undetected": sorted([a for a in tried if not a["caught"]], key=lambda a: -a["mb"])[:5],
        "recent": tried[:8],
    }


@router.get("/api/staff/active")
def staff_active(db: Session = Depends(get_db)):
    """Staff signed in to the portal right now, with their live session verdict (admin view)."""
    now = time.time()
    with presence_lock:
        for uid in [u for u, v in presence.items() if now - v["last_seen"] > ONLINE_SECONDS]:
            presence.pop(uid)
        current = dict(presence)
    who = names(db)
    out = []
    for uid, v in current.items():
        row = db.get(Event, v["event_id"])
        emp = get_employee(db, uid)
        if row:
            out.append(event_out(row, who) | {
                "event_id": row.id, "login_at": v["login_at"], "seconds_since_seen": round(now - v["last_seen"]),
                "role": emp.role, "account_status": emp.status,
            })
    return sorted(out, key=lambda x: x["login_at"], reverse=True)


# ------------------------------------------------------------------ admin: access control
@router.get("/api/access")
def access_overview(db: Session = Depends(get_db)):
    staff = []
    online = set(presence)
    for user_id, username in sorted(auth.staff_usernames().items()):
        emp = db.get(Employee, user_id)
        if emp is None:  # CERT mode: the demo staff accounts have no employee here
            continue
        acc = _access(db, user_id)
        staff.append({"user_id": user_id, "username": username, "name": emp.name, "role": emp.role,
                      "department": emp.department, "email": acc.email, "email_shown": _staff_email(acc),
                      "permissions": acc.permissions or [], "usual": simulator.PROFILES[user_id]["resources"],
                      "status": emp.status, "status_reason": emp.status_reason, "online": user_id in online})
    requests = db.scalars(select(AccessRequest).where(AccessRequest.status == "pending")
                          .order_by(AccessRequest.created_at.desc())).all()
    who = names(db)
    return {
        "systems": ALL_SYSTEMS,
        "staff": staff,
        "requests": [{"id": r.id, "user_id": r.user_id, "name": who.get(r.user_id, r.user_id),
                      "resource": r.resource, "created_at": r.created_at} for r in requests],
        "admin_email": _admin_email(db),
        "smtp_configured": mailer.smtp_config() is not None,
        "otp_required": OTP_REQUIRED,
    }


class AccessUpdate(BaseModel):
    permissions: list[str] | None = None
    email: str | None = None


@router.put("/api/access/{user_id}")
def update_access(user_id: str, body: AccessUpdate, request: Request, db: Session = Depends(get_db)):
    if user_id not in auth.staff_usernames():
        raise HTTPException(404, "Not a staff portal account")
    acc = _access(db, user_id)
    if body.permissions is not None:
        unknown = set(body.permissions) - set(ALL_SYSTEMS)
        if unknown:
            raise HTTPException(400, f"Unknown systems: {', '.join(sorted(unknown))}")
        acc.permissions = sorted(set(body.permissions))
    if body.email is not None:
        email = body.email.strip()
        if email and ("@" not in email or " " in email):
            raise HTTPException(400, "That does not look like an email address")
        acc.email = email.lower() or None
        if acc.email:
            acc.known_emails = sorted(set(acc.known_emails or []) | {acc.email})
    db.commit()
    changes = []
    if body.permissions is not None:
        changes.append("permissions: " + (", ".join(acc.permissions) or "none"))
    if body.email is not None:
        changes.append(f"email: {acc.email or 'cleared'}")
    audit(db, request, "access_changed", user_id, "; ".join(changes))
    return {"user_id": user_id, "permissions": acc.permissions, "email": acc.email}


@router.post("/api/access/{user_id}/unlock")
def unlock(user_id: str, request: Request, db: Session = Depends(get_db)):
    """Unlock a staff account after review. A reviewed denial no longer counts against the live session."""
    emp = get_employee(db, user_id)
    audit(db, request, "unlock", user_id, f"was: {emp.status_reason or emp.status}")
    failed_logins.pop(auth.staff_usernames().get(user_id, ""), None)
    emp.status, emp.status_reason, emp.status_changed_at = "active", None, simulator.now_ist()
    db.commit()
    entry = presence.get(user_id)
    if entry:
        row = db.get(Event, entry["event_id"])
        if row and any(a.startswith("denied:") for a in row.actions or []):
            row.actions = [a for a in row.actions if not a.startswith("denied:")]
            sentinel.rescore(db, row)
            emp.status, emp.status_reason = "active", None  # the admin's decision wins over the re-score
            db.commit()
    acc = _access(db, user_id)
    mailer.send(db, _staff_email(acc), "Your account has been unlocked",
                f"Hi {emp.name.split()[0]},\n\nThe security admin reviewed your account and unlocked it.",
                "unlock", user_id)
    return {"user_id": user_id, "status": emp.status}


class RequestDecision(BaseModel):
    approve: bool


@router.post("/api/access/requests/{request_id}")
def decide_request(request_id: int, body: RequestDecision, request: Request, db: Session = Depends(get_db)):
    req = db.get(AccessRequest, request_id)
    if not req or req.status != "pending":
        raise HTTPException(404, "No pending request with that id")
    req.status = "approved" if body.approve else "denied"
    acc = _access(db, req.user_id)
    if body.approve:
        acc.permissions = sorted(set(acc.permissions or []) | {req.resource})
    db.commit()
    audit(db, request, f"request_{req.status}", req.user_id, req.resource)
    emp = get_employee(db, req.user_id)
    mailer.send(db, _staff_email(acc), f"Access request {req.status}: {req.resource}",
                f"Hi {emp.name.split()[0]},\n\nYour request for {req.resource} was {req.status} by the security admin.",
                "request", req.user_id)
    return {"id": req.id, "status": req.status}


# ------------------------------------------------------------------ admin: mail
class MailSettings(BaseModel):
    admin_email: str


admin_email_change: dict = {}  # pending change: new address, hashed code, expiry, tries


def _apply_admin_email(db: Session, request: Request, email: str | None) -> dict:
    old = _admin_email(db)
    row = db.get(Setting, "admin_email") or Setting(key="admin_email")
    row.value = email or None
    db.merge(row)
    db.commit()
    audit(db, request, "admin_email_changed", None, f"{old} -> {email or 'cleared'}")
    if _real_delivery(old) and old != _admin_email(db):
        mailer.send(db, old, "SentinelAI admin email changed",
                    f"The SentinelAI admin email was changed from this address to {_mask(_admin_email(db))}. "
                    "Admin sign-in codes and security alerts now go there. If this wasn't you, sign in and change it back.",
                    "alert")
    return {"admin_email": _admin_email(db)}


@router.put("/api/settings/mail")
def set_mail_settings(body: MailSettings, request: Request, db: Session = Depends(get_db)):
    """Change the admin email. When email sending works, the new address must be confirmed with a code first,
    because admin sign-in codes go there: a typo must not lock the admin out."""
    email = body.admin_email.strip()
    if email and not _valid_email(email):
        raise HTTPException(400, "That does not look like an email address")
    if not email or not _real_delivery(email):
        return _apply_admin_email(db, request, email)
    code = f"{secrets.randbelow(1_000_000):06d}"
    admin_email_change.clear()
    admin_email_change.update(email=email, code=hashlib.sha256(code.encode()).hexdigest(),
                              expires=time.time() + OTP_SECONDS, tries=0)
    mailer.send(db, email, f"Confirm your SentinelAI admin email: {code}",
                f"Enter {code} in SentinelAI to make this the admin email. It expires in {OTP_SECONDS // 60} minutes.",
                "otp")
    audit(db, request, "admin_email_change_requested", None, email)
    return {"verify_required": True, "pending": _mask(email), "admin_email": _admin_email(db)}


class MailVerify(BaseModel):
    code: str


@router.post("/api/settings/mail/verify")
def verify_mail_settings(body: MailVerify, request: Request, db: Session = Depends(get_db)):
    p = admin_email_change
    if not p or p["expires"] < time.time():
        admin_email_change.clear()
        raise HTTPException(400, "No email change is waiting, or the code expired. Save the new address again.")
    if p["tries"] >= OTP_MAX_TRIES or not hmac.compare_digest(p["code"], hashlib.sha256(body.code.strip().encode()).hexdigest()):
        p["tries"] += 1
        raise HTTPException(400, "Wrong code. Check the email sent to the new address.")
    email = p["email"]
    admin_email_change.clear()
    return _apply_admin_email(db, request, email)


@router.post("/api/mail/test")
def test_mail(db: Session = Depends(get_db)):
    msg = mailer.send(db, _admin_email(db), "[SentinelAI] Test email",
                      "If you can read this, SentinelAI can email you about logins and security alerts.", "test")
    return {"id": msg.id, "to": msg.to, "delivery": msg.delivery}


@router.get("/api/security")
def security_status(limit: int = Query(60, le=300), db: Session = Depends(get_db)):
    """Security controls in force, plus the audit log."""
    rows = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)).all()
    return {
        "controls": {
            "admin_2fa": auth.ADMIN_2FA,
            "admin_2fa_enrolled": _setting(db, "admin_totp_secret") is not None,
            "admin_session_hours": auth.ADMIN_TOKEN_HOURS,
            "admin_lockout": f"{ADMIN_MAX_FAILURES} wrong attempts -> {ADMIN_LOCK_SECONDS // 60} min pause",
            "staff_otp": OTP_REQUIRED,
            "staff_lockout": f"{STAFF_MAX_FAILURES} wrong passwords in a row -> locked until an admin unlocks",
            "password_storage": "PBKDF2-SHA256, 200,000 iterations, per-user salt",
            "email_delivery": "SMTP" if mailer.smtp_config() else "demo (Mail Outbox)",
        },
        "audit": [{"id": r.id, "at": r.at, "actor": r.actor, "action": r.action, "target": r.target,
                   "detail": r.detail, "ip": r.ip} for r in rows],
    }


@router.get("/api/mail")
def outbox(limit: int = Query(50, le=200), db: Session = Depends(get_db)):
    rows = db.scalars(select(MailMessage).order_by(MailMessage.id.desc()).limit(limit)).all()
    return [{"id": m.id, "created_at": m.created_at, "to": m.to, "subject": m.subject, "body": m.body,
             "kind": m.kind, "user_id": m.user_id, "delivery": m.delivery, "error": m.error} for m in rows]


# ------------------------------------------------------------------ admin: onboarding
USERNAME_RE = r"^[a-z][a-z0-9._-]{2,23}$"


def load_onboarded(db: Session) -> None:
    """At start-up: bring back employees and logins created from the dashboard."""
    for account in db.scalars(select(StaffAccount)).all():
        emp = db.get(Employee, account.user_id)
        if emp is None:
            continue
        acc = db.get(StaffAccess, emp.id)
        simulator.register_profile(emp.id, emp.name, emp.department, emp.role, emp.home_city,
                                   list(acc.permissions or []) if acc else [])
        auth.ONBOARDED_ACCOUNTS[account.username] = (account.password_hash, emp.id)


def forget_onboarded() -> None:
    """After a demo reset the onboarded employees are gone from the database, so forget them too."""
    simulator.forget_onboarded()
    auth.ONBOARDED_ACCOUNTS.clear()


def _department_systems(db: Session, department: str) -> list[str]:
    """Systems most people in the department use: the default permissions for a new joiner."""
    counts: dict[str, int] = {}
    members = [p for p in simulator.PROFILES.values() if p["department"] == department]
    for p in members:
        for r in p.get("resources", []):
            counts[r] = counts.get(r, 0) + 1
    return sorted(r for r, n in counts.items() if n * 2 >= len(members)) if members else []


class NewEmployee(BaseModel):
    name: str
    department: str
    role: str
    home_city: str
    username: str
    password: str | None = None
    email: str | None = None
    permissions: list[str] | None = None


@router.get("/api/employees/options")
def onboarding_options(db: Session = Depends(get_db)):
    departments = sorted({e.department for e in db.scalars(select(Employee)).all()})
    return {"departments": departments, "cities": sorted(simulator.LOCATIONS), "systems": ALL_SYSTEMS,
            "suggested": {d: _department_systems(db, d) for d in departments}}


@router.post("/api/employees")
def onboard(body: NewEmployee, request: Request, db: Session = Depends(get_db)):
    """Add an employee with a staff portal login. Their twin starts from their department's habits."""
    if mode.CERT:
        raise HTTPException(400, mode.DEMO_ONLY)
    username = body.username.strip().lower()
    name, department, role = body.name.strip(), body.department.strip(), body.role.strip()
    if not re.match(USERNAME_RE, username):
        raise HTTPException(400, "Username: 3-24 characters, lowercase letters, digits, dot, dash or underscore")
    if auth.staff_account(username):
        raise HTTPException(409, "That username is taken")
    if not (2 <= len(name) <= 60 and 2 <= len(department) <= 40 and 2 <= len(role) <= 60):
        raise HTTPException(400, "Fill in name, department and role")
    if body.home_city not in simulator.LOCATIONS:
        raise HTTPException(400, "Choose a home city from the list")
    password = body.password or secrets.token_urlsafe(9)
    if len(password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    email = (body.email or "").strip() or None
    if email and not _valid_email(email):
        raise HTTPException(400, "That email address doesn't look right")
    permissions = body.permissions if body.permissions is not None else _department_systems(db, department)
    unknown = set(permissions) - set(ALL_SYSTEMS)
    if unknown:
        raise HTTPException(400, f"Unknown systems: {', '.join(sorted(unknown))}")

    numbers = [int(e[3:]) for e in db.scalars(select(Employee.id)).all() if e.startswith("EMP") and e[3:].isdigit()]
    uid = f"EMP{max(numbers, default=0) + 1:03d}"
    db.add(Employee(id=uid, name=name, department=department, role=role, home_city=body.home_city))
    db.flush()
    stored = auth.hash_password(password)
    db.add(StaffAccount(username=username, user_id=uid, password_hash=stored, created_at=simulator.now_ist()))
    db.add(StaffAccess(user_id=uid, email=email, permissions=sorted(permissions), known_emails=[email] if email else [],
                       known_devices=[]))
    db.commit()
    simulator.register_profile(uid, name, department, role, body.home_city, sorted(permissions))
    auth.ONBOARDED_ACCOUNTS[username] = (stored, uid)
    audit(db, request, "employee_onboarded", uid, f"{name} ({role}, {department}) as '{username}'")
    if email:
        mailer.send(db, email, "Welcome to SentinelAI",
                    f"Hi {name.split()[0]},\n\nYour staff portal account is ready. Username: {username}\n"
                    "Your admin will give you your first password. Each sign-in also needs a code sent to this email.",
                    "welcome", uid)
    return {"user_id": uid, "username": username, "password": password if not body.password else None,
            "permissions": sorted(permissions), "twin": sentinel.twin(uid)}


@router.post("/api/employees/{user_id}/offboard")
def offboard(user_id: str, request: Request, db: Session = Depends(get_db)):
    """Someone left: remove their login, end their session and lock the account (history is kept)."""
    emp = get_employee(db, user_id)
    account = db.scalar(select(StaffAccount).where(StaffAccount.user_id == user_id))
    if account:
        auth.ONBOARDED_ACCOUNTS.pop(account.username, None)
        db.delete(account)
    entry = presence.pop(user_id, None)
    if entry:
        revoked_sessions.add(entry["event_id"])
    emp.status, emp.status_reason, emp.status_changed_at = "blocked", "Offboarded: left the company", simulator.now_ist()
    db.commit()
    audit(db, request, "employee_offboarded", user_id, emp.name)
    return {"user_id": user_id, "status": emp.status}
