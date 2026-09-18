"""Logins, the staff portal, access control and the mail outbox.

Staff sign in with ID + password + a one-time code sent by email. Every portal session is a
real session scored by SentinelAI. Opening a system you have no permission for locks the
account until an admin unlocks it; the admin is emailed about logins, denials and requests.
"""
import hashlib
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
import simulator
from common import ALERT_TIERS, event_out, get_employee, get_event, latest_time, names
from database import get_db
from feature_engineering import haversine_km
from detection_service import sentinel
from models import AccessRequest, Event, MailMessage, Setting, StaffAccess

router = APIRouter()

OTP_REQUIRED = os.getenv("OTP_REQUIRED", "true").lower() == "true"
OTP_SECONDS, OTP_MAX_TRIES = 300, 3
ONLINE_SECONDS = 45
ALL_SYSTEMS = sorted(set(simulator.HIGH_VALUE) | {r for rs in simulator.ROLE_RESOURCES.values() for r in rs})
USERNAMES = {user_id: username for username, (_, user_id) in auth.STAFF_ACCOUNTS.items()}

# In-memory state (fine for a single-process demo server).
failed_logins: dict[str, int] = {}      # wrong passwords/codes per username since the last success
otp_challenges: dict[str, dict] = {}    # challenge id -> pending second factor
presence: dict[str, dict] = {}          # user_id -> signed-in portal session
presence_lock = threading.Lock()
revoked_sessions: set[int] = set()      # portal sessions the SOC force-signed-out
admin_failures: list[float] = []
ADMIN_MAX_FAILURES, ADMIN_LOCK_SECONDS = 5, 120


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
    return acc.email or f"{USERNAMES.get(acc.user_id, acc.user_id.lower())}@staff.demo"


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


@router.post("/api/auth/login")
def admin_login(body: LoginRequest):
    now = time.time()
    admin_failures[:] = [t for t in admin_failures if now - t < ADMIN_LOCK_SECONDS]
    if len(admin_failures) >= ADMIN_MAX_FAILURES:
        wait = int(ADMIN_LOCK_SECONDS - (now - admin_failures[0])) + 1
        raise HTTPException(429, f"Too many wrong attempts. Admin login is paused for {wait} seconds.")
    if not auth.check_admin(body.username, body.password):
        admin_failures.append(now)
        raise HTTPException(401, "Wrong username or password")
    admin_failures.clear()
    name = auth.ADMIN_USERNAME
    return {"token": auth.issue("admin", name, name), "role": "admin", "name": name}


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
    token = auth.issue("staff", user_id, emp.name, event_id=row.id)
    return {"token": token, "role": "staff", "name": emp.name}


@router.post("/api/auth/staff-login")
def staff_login(body: StaffLoginRequest, request: Request, db: Session = Depends(get_db)):
    """Step 1: staff ID + password. With OTP on, this emails a 6-digit code instead of signing in."""
    username = body.username.strip().lower()
    account = auth.staff_account(username)
    if not account or not hmac.compare_digest(account[0], body.password):
        if account:
            failed_logins[username] = failed_logins.get(username, 0) + 1
        raise HTTPException(401, "Wrong staff ID or password")
    user_id = account[1]
    if get_employee(db, user_id).status == "blocked":
        raise HTTPException(403, "This account is locked. Ask your security admin to unlock it.")
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
def force_signout(user_id: str):
    """SOC action: end someone's portal session right now."""
    with presence_lock:
        entry = presence.pop(user_id, None)
    if not entry:
        raise HTTPException(404, "That person is not signed in")
    revoked_sessions.add(entry["event_id"])
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
    for user_id, username in sorted(USERNAMES.items()):
        emp = get_employee(db, user_id)
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
def update_access(user_id: str, body: AccessUpdate, db: Session = Depends(get_db)):
    if user_id not in USERNAMES:
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
    return {"user_id": user_id, "permissions": acc.permissions, "email": acc.email}


@router.post("/api/access/{user_id}/unlock")
def unlock(user_id: str, db: Session = Depends(get_db)):
    """Unlock a staff account after review. A reviewed denial no longer counts against the live session."""
    emp = get_employee(db, user_id)
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
def decide_request(request_id: int, body: RequestDecision, db: Session = Depends(get_db)):
    req = db.get(AccessRequest, request_id)
    if not req or req.status != "pending":
        raise HTTPException(404, "No pending request with that id")
    req.status = "approved" if body.approve else "denied"
    acc = _access(db, req.user_id)
    if body.approve:
        acc.permissions = sorted(set(acc.permissions or []) | {req.resource})
    db.commit()
    emp = get_employee(db, req.user_id)
    mailer.send(db, _staff_email(acc), f"Access request {req.status}: {req.resource}",
                f"Hi {emp.name.split()[0]},\n\nYour request for {req.resource} was {req.status} by the security admin.",
                "request", req.user_id)
    return {"id": req.id, "status": req.status}


# ------------------------------------------------------------------ admin: mail
class MailSettings(BaseModel):
    admin_email: str


@router.put("/api/settings/mail")
def set_mail_settings(body: MailSettings, db: Session = Depends(get_db)):
    email = body.admin_email.strip()
    if email and ("@" not in email or " " in email):
        raise HTTPException(400, "That does not look like an email address")
    row = db.get(Setting, "admin_email") or Setting(key="admin_email")
    row.value = email or None
    db.merge(row)
    db.commit()
    return {"admin_email": _admin_email(db)}


@router.post("/api/mail/test")
def test_mail(db: Session = Depends(get_db)):
    msg = mailer.send(db, _admin_email(db), "[SentinelAI] Test email",
                      "If you can read this, SentinelAI can email you about logins and security alerts.", "test")
    return {"id": msg.id, "to": msg.to, "delivery": msg.delivery}


@router.get("/api/mail")
def outbox(limit: int = Query(50, le=200), db: Session = Depends(get_db)):
    rows = db.scalars(select(MailMessage).order_by(MailMessage.id.desc()).limit(limit)).all()
    return [{"id": m.id, "created_at": m.created_at, "to": m.to, "subject": m.subject, "body": m.body,
             "kind": m.kind, "user_id": m.user_id, "delivery": m.delivery, "error": m.error} for m in rows]
