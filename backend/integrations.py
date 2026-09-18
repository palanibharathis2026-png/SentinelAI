"""Connect SentinelAI to real company systems.

In:   sign-in logs from Okta, Microsoft Entra ID, Google Workspace, AWS CloudTrail (or our own schema)
      are posted to /api/ingest/<source> with an API key, turned into sessions and scored like any other.
Out:  every new MFA / BLOCK alert is pushed to the channels the admin enabled: Slack, Microsoft Teams,
      SMS or WhatsApp (Twilio), a signed webhook for SOAR playbooks, and a SIEM over syslog (CEF).
      Alerts can also be exported as CEF, JSON lines or CSV.
Only Python's standard library is used for the network calls.
"""
import base64
import csv
import hashlib
import hmac
import io
import json
import logging
import os
import secrets
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

import auth
import simulator
from database import SessionLocal
from models import Employee, Event, IntegrationLog, Setting, StaffAccess

log = logging.getLogger("sentinel.integrations")

CONFIG_KEY, KEYS_KEY = "integrations", "ingest_keys"
TIER_RANK = {"ALLOW": 0, "MONITOR": 1, "MFA": 2, "BLOCK": 3}
CHANNELS = {
    "slack": {"label": "Slack", "fields": ["webhook_url"],
              "env": {"webhook_url": "SLACK_WEBHOOK_URL"}},
    "teams": {"label": "Microsoft Teams", "fields": ["webhook_url"],
              "env": {"webhook_url": "TEAMS_WEBHOOK_URL"}},
    "webhook": {"label": "Webhook (SOAR / custom)", "fields": ["url", "secret"],
                "env": {"url": "ALERT_WEBHOOK_URL", "secret": "ALERT_WEBHOOK_SECRET"}},
    "sms": {"label": "SMS (Twilio)", "fields": ["account_sid", "auth_token", "from_number", "to_number"],
            "env": {"account_sid": "TWILIO_ACCOUNT_SID", "auth_token": "TWILIO_AUTH_TOKEN",
                    "from_number": "TWILIO_FROM", "to_number": "ALERT_SMS_TO"}},
    "whatsapp": {"label": "WhatsApp (Twilio)", "fields": ["account_sid", "auth_token", "from_number", "to_number"],
                 "env": {"account_sid": "TWILIO_ACCOUNT_SID", "auth_token": "TWILIO_AUTH_TOKEN",
                         "from_number": "TWILIO_WHATSAPP_FROM", "to_number": "ALERT_WHATSAPP_TO"}},
    "syslog": {"label": "SIEM (syslog, CEF over UDP)", "fields": ["host", "port"],
               "env": {"host": "SIEM_SYSLOG_HOST", "port": "SIEM_SYSLOG_PORT"}},
}
SECRET_FIELDS = {"webhook_url", "url", "secret", "auth_token"}
MASK = "••••"
SOURCES = {
    "okta": "Okta System Log",
    "entra": "Microsoft Entra ID sign-in logs",
    "google": "Google Workspace login audit",
    "cloudtrail": "AWS CloudTrail (ConsoleLogin)",
    "sentinel": "SentinelAI session schema",
}
COUNTRY_CODES = {
    "IN": "India", "US": "United States", "GB": "United Kingdom", "SG": "Singapore", "NG": "Nigeria",
    "RU": "Russia", "CN": "China", "AE": "United Arab Emirates", "DE": "Germany", "BR": "Brazil",
    "NL": "Netherlands", "JP": "Japan", "AU": "Australia", "FR": "France", "CA": "Canada",
}
IST = timezone(timedelta(hours=5, minutes=30))
pending_failures: dict[str, int] = {}  # failed sign-ins waiting for that person's next successful one


# ----------------------------------------------------------------- settings
def _get(db: Session, key: str, default):
    row = db.get(Setting, key)
    try:
        return json.loads(row.value) if row and row.value else default
    except ValueError:
        return default


def _put(db: Session, key: str, value) -> None:
    db.merge(Setting(key=key, value=json.dumps(value)))
    db.commit()


def load_config(db: Session) -> dict:
    """Saved settings, with .env values filling anything left empty."""
    saved = _get(db, CONFIG_KEY, {})
    cfg = {"min_tier": saved.get("min_tier", "MFA"), "channels": {}}
    for name, spec in CHANNELS.items():
        ch = dict(saved.get("channels", {}).get(name, {}))
        for field in spec["fields"]:
            if not ch.get(field):
                ch[field] = os.getenv(spec["env"][field], "")
        if "enabled" not in ch:  # never toggled in the dashboard: on when .env configures it
            ch["enabled"] = all(os.getenv(spec["env"][f]) for f in spec["fields"] if f != "secret")
        cfg["channels"][name] = ch
    return cfg


def _configured(name: str, ch: dict) -> bool:
    return all(ch.get(f) for f in CHANNELS[name]["fields"] if f != "secret")


def public_config(db: Session) -> dict:
    cfg = load_config(db)
    out = {"min_tier": cfg["min_tier"], "channels": []}
    for name, ch in cfg["channels"].items():
        fields = {f: (MASK + ch[f][-4:] if f in SECRET_FIELDS and ch.get(f) else ch.get(f, ""))
                  for f in CHANNELS[name]["fields"]}
        out["channels"].append({"id": name, "label": CHANNELS[name]["label"], "enabled": ch["enabled"],
                                "configured": _configured(name, ch), "fields": fields})
    return out


def save_config(db: Session, channel: str | None, fields: dict, enabled: bool | None, min_tier: str | None) -> None:
    saved = _get(db, CONFIG_KEY, {})
    if min_tier in TIER_RANK:
        saved["min_tier"] = min_tier
    if channel in CHANNELS:
        ch = saved.setdefault("channels", {}).setdefault(channel, {})
        for f in CHANNELS[channel]["fields"]:
            value = (fields or {}).get(f)
            if value is not None and not str(value).startswith(MASK):  # masked = keep the stored secret
                ch[f] = str(value).strip()
        if enabled is not None:
            ch["enabled"] = enabled
    _put(db, CONFIG_KEY, saved)


# ------------------------------------------------------------ alert content
def _names(db: Session) -> dict:
    return dict(db.execute(select(Employee.id, Employee.name)).all())


def _reason_texts(ev: Event) -> list[str]:
    return [r["signal"] if isinstance(r, dict) else str(r) for r in (ev.reasons or [])]


def alert_payload(ev: Event, name: str) -> dict:
    return {
        "type": "sentinel.alert", "id": ev.id, "time": ev.timestamp.isoformat(), "user_id": ev.user_id,
        "name": name, "risk": ev.risk, "tier": ev.tier, "action": ev.action, "threat": ev.threat,
        "reasons": _reason_texts(ev), "city": ev.city, "country": ev.country, "ip": ev.ip,
        "device": f"{ev.os} / {ev.browser}", "source": ev.source,
    }


def alert_text(p: dict) -> str:
    return (f"SentinelAI {p['tier']} alert #{p['id']}: {p['name']} ({p['user_id']}), risk {p['risk']}/100 - "
            f"{p['threat'] or 'behavioural anomaly'}. {p['city']}, {p['country']} · {p['device']}. "
            f"Why: {', '.join(p['reasons'][:4]) or 'anomaly'}. Action: {p['action']}.")


def _cef_escape(value, header=False) -> str:
    s = str(value if value is not None else "").replace("\\", "\\\\").replace("\r", " ").replace("\n", " ")
    return s.replace("|", "\\|") if header else s.replace("=", "\\=")


def cef_line(p: dict) -> str:
    severity = {"ALLOW": 1, "MONITOR": 4, "MFA": 7, "BLOCK": 10}.get(p["tier"], 5)
    ts = datetime.fromisoformat(p["time"]).replace(tzinfo=IST)
    ext = {
        "rt": int(ts.timestamp() * 1000), "externalId": p["id"], "suid": p["user_id"], "suser": p["name"],
        "src": p["ip"], "act": p["action"], "cs1Label": "city", "cs1": p["city"], "cs2Label": "country",
        "cs2": p["country"], "cn1Label": "risk", "cn1": p["risk"], "requestClientApplication": p["device"],
        "msg": "; ".join(p["reasons"]),
    }
    head = "|".join(_cef_escape(x, True) for x in (
        "CEF:0", "INNOVEX", "SentinelAI", "1.0", (p["threat"] or "anomaly").lower().replace(" ", "_")[:60],
        p["threat"] or "Behavioural anomaly", severity))
    return head + "|" + " ".join(f"{k}={_cef_escape(v)}" for k, v in ext.items())


# ----------------------------------------------------------------- senders
def _http(url: str, data: bytes, headers: dict) -> str:
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310 (admin-configured URL)
        return f"HTTP {r.status}"


def _send(name: str, ch: dict, p: dict) -> str:
    text = alert_text(p)
    if name == "slack":
        emoji = ":rotating_light:" if p["tier"] == "BLOCK" else ":warning:"
        return _http(ch["webhook_url"], json.dumps({"text": f"{emoji} {text}"}).encode(), {"Content-Type": "application/json"})
    if name == "teams":
        return _http(ch["webhook_url"], json.dumps({"text": text}).encode(), {"Content-Type": "application/json"})
    if name == "webhook":
        body = json.dumps(p).encode()
        headers = {"Content-Type": "application/json", "User-Agent": "SentinelAI-webhook"}
        if ch.get("secret"):
            headers["X-Sentinel-Signature"] = "sha256=" + hmac.new(ch["secret"].encode(), body, hashlib.sha256).hexdigest()
        return _http(ch["url"], body, headers)
    if name in ("sms", "whatsapp"):
        prefix = "whatsapp:" if name == "whatsapp" else ""
        to, sender = ch["to_number"], ch["from_number"]
        form = urllib.parse.urlencode({
            "To": to if to.startswith(prefix) else prefix + to,
            "From": sender if sender.startswith(prefix) else prefix + sender,
            "Body": text[:1500],
        }).encode()
        basic = base64.b64encode(f"{ch['account_sid']}:{ch['auth_token']}".encode()).decode()
        url = f"https://api.twilio.com/2010-04-01/Accounts/{urllib.parse.quote(ch['account_sid'])}/Messages.json"
        return _http(url, form, {"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded"})
    if name == "syslog":
        severity = 2 if p["tier"] == "BLOCK" else 4  # critical / warning
        msg = f"<{10 * 8 + severity}>{datetime.now(IST).strftime('%b %d %H:%M:%S')} sentinelai SentinelAI: {cef_line(p)}"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(msg.encode()[:8000], (ch["host"], int(ch["port"] or 514)))
        return "UDP datagram sent"
    raise ValueError(f"unknown channel {name}")


def _log(db: Session, channel: str, event_id: int | None, status: str, detail: str) -> None:
    db.add(IntegrationLog(at=simulator.now_ist(), channel=channel, event_id=event_id, status=status, detail=detail[:400]))
    db.commit()


def dispatch(event_id: int | None, only: str | None = None) -> list[dict]:
    """Push one alert (or a test alert when event_id is None) to every enabled channel."""
    results = []
    with SessionLocal() as db:
        cfg = load_config(db)
        if event_id is None:
            p = {"type": "sentinel.test", "id": 0, "time": simulator.now_ist().isoformat(), "user_id": "TEST",
                 "name": "Test alert", "risk": 88, "tier": "BLOCK", "action": "No action (test)",
                 "threat": "Integration test", "reasons": ["This is a test from SentinelAI"], "city": "Vellore",
                 "country": "India", "ip": "127.0.0.1", "device": "SentinelAI", "source": "test"}
        else:
            ev = db.get(Event, event_id)
            if ev is None or TIER_RANK.get(ev.tier, 0) < TIER_RANK.get(cfg["min_tier"], 2):
                return results
            p = alert_payload(ev, _names(db).get(ev.user_id, ev.user_id))
        for name, ch in cfg["channels"].items():
            if (only and name != only) or (not only and not ch["enabled"]):
                continue
            if not _configured(name, ch):
                results.append({"channel": name, "status": "skipped", "detail": "not configured"})
                continue
            try:
                detail, status = _send(name, ch, p), "sent"
            except urllib.error.HTTPError as e:
                detail, status = f"HTTP {e.code}: {e.read()[:200].decode(errors='replace')}", "failed"
            except (OSError, ValueError) as e:
                detail, status = str(e), "failed"
            _log(db, name, event_id, status, detail)
            results.append({"channel": name, "status": status, "detail": detail})
    return results


def dispatch_async(event_id: int) -> None:
    threading.Thread(target=dispatch, args=(event_id,), daemon=True).start()


# ------------------------------------------------------------------ export
def export(db: Session, fmt: str, hours: int, alerts_only: bool) -> tuple[str, str]:
    since = simulator.now_ist() - timedelta(hours=hours)
    q = select(Event).where(Event.timestamp >= since)
    if alerts_only:
        q = q.where(Event.tier.in_(("MFA", "BLOCK")))
    names = _names(db)
    rows = [alert_payload(e, names.get(e.user_id, e.user_id)) for e in db.scalars(q.order_by(Event.timestamp))]
    if fmt == "cef":
        return "\n".join(cef_line(p) for p in rows) + "\n", "text/plain"
    if fmt == "jsonl":
        return "\n".join(json.dumps(p) for p in rows) + "\n", "application/x-ndjson"
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=["id", "time", "user_id", "name", "risk", "tier", "action", "threat",
                                        "reasons", "city", "country", "ip", "device", "source"], extrasaction="ignore")
    w.writeheader()
    for p in rows:
        w.writerow({**p, "reasons": "; ".join(p["reasons"])})
    return buf.getvalue(), "text/csv"


# ---------------------------------------------------------------- API keys
def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def create_key(db: Session, label: str) -> dict:
    key = "sk_sentinel_" + secrets.token_urlsafe(24)
    keys = _get(db, KEYS_KEY, [])
    item = {"id": secrets.token_hex(4), "label": label[:40] or "ingest", "hash": _hash_key(key),
            "last4": key[-4:], "created": simulator.now_ist().isoformat()}
    keys.append(item)
    _put(db, KEYS_KEY, keys)
    return {**{k: v for k, v in item.items() if k != "hash"}, "key": key}


def list_keys(db: Session) -> list[dict]:
    return [{k: v for k, v in item.items() if k != "hash"} for item in _get(db, KEYS_KEY, [])]


def revoke_key(db: Session, key_id: str) -> None:
    _put(db, KEYS_KEY, [k for k in _get(db, KEYS_KEY, []) if k["id"] != key_id])


def valid_key(db: Session, key: str) -> bool:
    if not key:
        return False
    env = os.getenv("INGEST_API_KEY")
    if env and hmac.compare_digest(key, env):
        return True
    h = _hash_key(key)
    return any(hmac.compare_digest(h, k["hash"]) for k in _get(db, KEYS_KEY, []))


# --------------------------------------------------------------- ingestion
def _records(source: str, payload) -> list[dict]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("records", "value", "items", "Records", "events"):
            if isinstance(payload.get(key), list):
                return payload[key]
        return [payload]
    raise ValueError("Expected a JSON list or object")


def _time(text: str | None) -> datetime:
    """Provider timestamps are UTC ISO-8601; SentinelAI stores India time without a zone."""
    if not text:
        return simulator.now_ist()
    ts = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    if ts.tzinfo is None:
        return ts
    return ts.astimezone(IST).replace(tzinfo=None, microsecond=0)


def _country(value: str | None) -> str | None:
    if not value:
        return None
    return COUNTRY_CODES.get(value.upper(), value) if len(value) == 2 else value


def normalize(source: str, r: dict) -> dict:
    """One provider record -> identity, time, success, network and device details."""
    def g(d, *path):
        value = _dig(d, path)
        return None if value == "" else value

    if source == "okta":
        ua = g(r, "client", "userAgent") or {}
        return {"identity": g(r, "actor", "alternateId") or g(r, "actor", "displayName"), "time": _time(r.get("published")),
                "success": (g(r, "outcome", "result") or "SUCCESS").upper() == "SUCCESS",
                "is_login": r.get("eventType", "user.session.start") in ("user.session.start", "user.authentication.sso",
                                                                          "user.authentication.auth_via_mfa"),
                "ip": g(r, "client", "ipAddress"), "city": g(r, "client", "geographicalContext", "city"),
                "country": _country(g(r, "client", "geographicalContext", "country")),
                "lat": g(r, "client", "geographicalContext", "geolocation", "lat"),
                "lon": g(r, "client", "geographicalContext", "geolocation", "lon"),
                "os": ua.get("os"), "browser": (ua.get("browser") or "").title() or None, "ua": ua.get("rawUserAgent")}
    if source == "entra":
        return {"identity": r.get("userPrincipalName") or r.get("userDisplayName"), "time": _time(r.get("createdDateTime")),
                "success": int(g(r, "status", "errorCode") or 0) == 0, "is_login": True,
                "ip": r.get("ipAddress"), "city": g(r, "location", "city"),
                "country": _country(g(r, "location", "countryOrRegion")),
                "lat": g(r, "location", "geoCoordinates", "latitude"), "lon": g(r, "location", "geoCoordinates", "longitude"),
                "os": g(r, "deviceDetail", "operatingSystem"),
                "browser": (g(r, "deviceDetail", "browser") or "").split(" ")[0] or None, "ua": None}
    if source == "google":
        names = [e.get("name", "") for e in r.get("events", [])]
        return {"identity": g(r, "actor", "email"), "time": _time(g(r, "id", "time")),
                "success": "login_failure" not in names, "is_login": any(n.startswith("login_") for n in names) or not names,
                "ip": r.get("ipAddress"), "city": None, "country": None, "lat": None, "lon": None,
                "os": None, "browser": None, "ua": None}
    if source == "cloudtrail":
        ident = r.get("userIdentity", {})
        return {"identity": ident.get("userName") or (ident.get("arn") or "").split("/")[-1] or None,
                "time": _time(r.get("eventTime")),
                "success": (g(r, "responseElements", "ConsoleLogin") or "Success") == "Success",
                "is_login": r.get("eventName", "ConsoleLogin") == "ConsoleLogin",
                "ip": r.get("sourceIPAddress"), "city": None, "country": None, "lat": None, "lon": None,
                "os": None, "browser": None, "ua": r.get("userAgent")}
    return {"identity": r.get("user_id") or r.get("email"), "time": _time(r.get("timestamp")),
            "success": r.get("success", True), "is_login": True, "ip": r.get("ip"), "city": r.get("city"),
            "country": r.get("country"), "lat": r.get("lat"), "lon": r.get("lon"), "os": r.get("os"),
            "browser": r.get("browser"), "ua": r.get("user_agent"), "extra": r}


def _dig(d, path):
    for p in path:
        if not isinstance(d, dict):
            return None
        d = d.get(p)
    return d


def resolve_user(db: Session, identity: str | None) -> str | None:
    """Map an external identity (email, UPN, username, employee id) to an employee."""
    if not identity:
        return None
    ident = identity.strip().lower()
    ids = {e.lower(): e for e in db.scalars(select(Employee.id)).all()}
    if ident in ids:
        return ids[ident]
    for acc in db.scalars(select(StaffAccess)).all():
        emails = [acc.email or ""] + list(acc.known_emails or [])
        if ident in (x.lower() for x in emails if x):
            return acc.user_id
    local = ident.split("@")[0].split("\\")[-1]
    for username, (_, uid) in auth.STAFF_ACCOUNTS.items():
        if username in (local, local.split(".")[0]):
            return uid
    for uid, name in db.execute(select(Employee.id, Employee.name)).all():
        parts = name.lower().split()
        if local in (parts[0], ".".join(parts), "".join(parts), f"{parts[0][0]}{parts[-1]}"):
            return uid
    return None


def to_session(db: Session, user_id: str, n: dict, source: str) -> dict:
    emp = db.get(Employee, user_id)
    city, country, lat, lon = n.get("city"), n.get("country"), n.get("lat"), n.get("lon")
    if city in simulator.LOCATIONS and (lat is None or lon is None):
        country, lat, lon = country or simulator.LOCATIONS[city][0], *simulator.LOCATIONS[city][1:]
    if lat is None or lon is None:  # the source gave no location: assume the home office
        city = emp.home_city if emp else "Unknown"
        country, lat, lon = simulator.LOCATIONS.get(city, ("India", 12.92, 79.13))
    os_name, browser = n.get("os"), n.get("browser")
    if (not os_name or not browser) and n.get("ua"):
        os_name, browser = auth.device_from_user_agent(n["ua"])
    extra = n.get("extra") or {}
    return {
        "user_id": user_id, "timestamp": n["time"], "city": city or "Unknown", "country": country or "Unknown",
        "lat": float(lat), "lon": float(lon), "ip": n.get("ip") or "0.0.0.0",
        "os": os_name or "Unknown OS", "browser": browser or "Unknown browser",
        "failed_attempts": pending_failures.pop(user_id, 0) + int(extra.get("failed_attempts", 0)),
        "files_downloaded": int(extra.get("files_downloaded", 0)), "mb_downloaded": float(extra.get("mb_downloaded", 0)),
        "api_calls": int(extra.get("api_calls", 0)), "sensitive_access": int(extra.get("sensitive_access", 0)),
        "session_minutes": int(extra.get("session_minutes", 30)),
        "resources": list(extra.get("resources", [])), "actions": list(extra.get("actions", [])),
        "scenario": None,
    }


def ingest(db: Session, engine, source: str, payload) -> dict:
    if source not in SOURCES:
        raise ValueError(f"Unknown source. Use one of: {', '.join(SOURCES)}")
    records = _records(source, payload)
    if len(records) > 5000:
        raise ValueError("At most 5000 records per request")
    summary = {"source": SOURCES[source], "received": len(records), "sessions": 0, "failed_logins": 0,
               "ignored": 0, "unknown_users": [], "alerts": []}
    normalized = []
    for r in records:
        if not isinstance(r, dict):
            summary["ignored"] += 1
            continue
        try:
            normalized.append(normalize(source, r))
        except (ValueError, TypeError):
            summary["ignored"] += 1
    for n in sorted(normalized, key=lambda n: n["time"]):
        if not n["is_login"]:
            summary["ignored"] += 1
            continue
        uid = resolve_user(db, n["identity"])
        if uid is None:
            if n["identity"] and n["identity"] not in summary["unknown_users"]:
                summary["unknown_users"].append(n["identity"])
            continue
        if not n["success"]:
            pending_failures[uid] = pending_failures.get(uid, 0) + 1
            summary["failed_logins"] += 1
            continue
        row = engine.ingest(db, to_session(db, uid, n, source), source)
        summary["sessions"] += 1
        if row.tier in ("MFA", "BLOCK"):
            summary["alerts"].append({"id": row.id, "user_id": uid, "risk": row.risk, "tier": row.tier, "threat": row.threat})
    return summary


# ------------------------------------------------------------ demo samples
def sample(db: Session, engine, source: str):
    """A small realistic log in the provider's own format: two normal sign-ins built from the people's
    digital twins, then a brute-force attack from abroad that succeeds on the sixth try."""
    staff = list(auth.STAFF_ACCOUNTS.items())[:3]
    now = datetime.now(timezone.utc).replace(microsecond=0)
    specs = []
    for i, (username, (_, uid)) in enumerate(staff[:2]):
        twin = engine.twin(uid)
        os_name, _, browser = twin["primary_device"].partition(" / ")
        city = twin["home_city"] if twin["home_city"] in simulator.LOCATIONS else "Chennai"
        country, lat, lon = simulator.LOCATIONS[city]
        specs.append({"email": f"{username}@innovex.example", "time": now - timedelta(minutes=40 - 10 * i),
                      "success": True, "ip": f"49.36.{10 + i}.{20 + i}", "city": city, "cc": "IN", "country": country,
                      "lat": lat, "lon": lon, "os": os_name, "browser": browser,
                      "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0 Safari/537.36"})
    username = staff[2][0]
    for k in range(6):
        specs.append({"email": f"{username}@innovex.example", "time": now - timedelta(minutes=6 - k),
                      "success": k == 5, "ip": "102.89.34.7", "city": "Lagos", "cc": "NG", "country": "Nigeria",
                      "lat": 6.52, "lon": 3.38, "os": "Linux", "browser": "Firefox",
                      "ua": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"})

    def z(t):
        return t.strftime("%Y-%m-%dT%H:%M:%SZ")

    out = []
    for s in specs:
        if source == "okta":
            out.append({"eventType": "user.session.start", "published": z(s["time"]),
                        "actor": {"alternateId": s["email"], "type": "User"},
                        "outcome": {"result": "SUCCESS" if s["success"] else "FAILURE"},
                        "client": {"ipAddress": s["ip"],
                                   "userAgent": {"rawUserAgent": s["ua"], "os": s["os"], "browser": s["browser"].upper()},
                                   "geographicalContext": {"city": s["city"], "country": s["country"],
                                                           "geolocation": {"lat": s["lat"], "lon": s["lon"]}}}})
        elif source == "entra":
            out.append({"createdDateTime": z(s["time"]), "userPrincipalName": s["email"], "ipAddress": s["ip"],
                        "clientAppUsed": "Browser", "status": {"errorCode": 0 if s["success"] else 50126},
                        "deviceDetail": {"operatingSystem": s["os"], "browser": s["browser"]},
                        "location": {"city": s["city"], "countryOrRegion": s["cc"],
                                     "geoCoordinates": {"latitude": s["lat"], "longitude": s["lon"]}}})
        elif source == "google":
            out.append({"id": {"time": z(s["time"]), "applicationName": "login"}, "actor": {"email": s["email"]},
                        "ipAddress": s["ip"], "events": [{"name": "login_success" if s["success"] else "login_failure"}]})
        elif source == "cloudtrail":
            out.append({"eventTime": z(s["time"]), "eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com",
                        "userIdentity": {"type": "IAMUser", "userName": s["email"].split("@")[0]},
                        "sourceIPAddress": s["ip"], "userAgent": s["ua"],
                        "responseElements": {"ConsoleLogin": "Success" if s["success"] else "Failure"}})
        else:
            out.append({"email": s["email"], "timestamp": z(s["time"]), "success": s["success"], "ip": s["ip"],
                        "city": s["city"], "country": s["country"], "lat": s["lat"], "lon": s["lon"],
                        "os": s["os"], "browser": s["browser"]})
    key = {"entra": "value", "google": "items", "cloudtrail": "Records"}.get(source)
    return {key: out} if key else out


# --------------------------------------------------------------------- API
from fastapi import APIRouter, Depends, HTTPException, Query, Request  # noqa: E402
from fastapi.responses import Response  # noqa: E402
from pydantic import BaseModel  # noqa: E402

from common import audit  # noqa: E402
from database import get_db  # noqa: E402

router = APIRouter()
DEMO_RECEIVER = "/api/hooks/demo"
OPEN_PREFIXES = ("/api/ingest/", DEMO_RECEIVER)  # these check their own credentials


class IntegrationUpdate(BaseModel):
    channel: str | None = None
    fields: dict = {}
    enabled: bool | None = None
    min_tier: str | None = None


class ChannelTest(BaseModel):
    channel: str | None = None


class KeyCreate(BaseModel):
    label: str = "ingest"


@router.get("/api/integrations")
def integrations_overview(db: Session = Depends(get_db)):
    rows = db.scalars(select(IntegrationLog).order_by(IntegrationLog.id.desc()).limit(40)).all()
    return {**public_config(db), "sources": SOURCES, "keys": list_keys(db),
            "log": [{"id": r.id, "at": r.at.isoformat(), "channel": r.channel, "event_id": r.event_id,
                     "status": r.status, "detail": r.detail} for r in rows]}


@router.put("/api/integrations")
def integrations_update(body: IntegrationUpdate, request: Request, db: Session = Depends(get_db)):
    if body.channel and body.channel not in CHANNELS:
        raise HTTPException(400, "Unknown channel")
    save_config(db, body.channel, body.fields, body.enabled, body.min_tier)
    changes = [f"{k}={v}" for k, v in (("enabled", body.enabled), ("min_tier", body.min_tier)) if v is not None]
    audit(db, request, "integration_change", body.channel or "alerts", ", ".join(changes) or "settings updated")
    return public_config(db)


@router.post("/api/integrations/test")
def integrations_test(body: ChannelTest):
    results = dispatch(None, only=body.channel)
    if not results:
        raise HTTPException(400, "No channel is enabled. Turn one on first.")
    return {"results": results}


@router.post("/api/integrations/demo-receiver")
def use_demo_receiver(request: Request, db: Session = Depends(get_db)):
    """Point the webhook channel at SentinelAI's own test receiver, to show signed delivery end to end."""
    url = f"http://127.0.0.1:{os.getenv('PORT', '8000')}{DEMO_RECEIVER}"
    save_config(db, "webhook", {"url": url, "secret": secrets.token_hex(16)}, True, None)
    audit(db, request, "integration_change", "webhook", "built-in test receiver")
    return public_config(db)


@router.post(DEMO_RECEIVER)
async def demo_receiver(request: Request, db: Session = Depends(get_db)):
    """Stands in for a SOAR tool: checks the HMAC signature and records what arrived."""
    body = await request.body()
    secret = load_config(db)["channels"]["webhook"].get("secret") or ""
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    ok = bool(secret) and hmac.compare_digest(expected, request.headers.get("x-sentinel-signature", ""))
    try:
        p = json.loads(body)
    except ValueError:
        p = {}
    verdict = "signature valid" if ok else "BAD signature"
    _log(db, "receiver", p.get("id") or None, "received" if ok else "rejected",
         f"{verdict}: {p.get('tier', '?')} alert for {p.get('name', '?')} (risk {p.get('risk', '?')})")
    if not ok:
        raise HTTPException(401, "Bad signature")
    return {"ok": True}


@router.post("/api/integrations/keys")
def integrations_new_key(body: KeyCreate, request: Request, db: Session = Depends(get_db)):
    item = create_key(db, body.label)
    audit(db, request, "ingest_key_created", item["id"], body.label)
    return item


@router.delete("/api/integrations/keys/{key_id}")
def integrations_revoke_key(key_id: str, request: Request, db: Session = Depends(get_db)):
    revoke_key(db, key_id)
    audit(db, request, "ingest_key_revoked", key_id)
    return {"keys": list_keys(db)}


@router.get("/api/integrations/sample/{source}")
def integrations_sample(source: str, db: Session = Depends(get_db)):
    from detection_service import sentinel
    if source not in SOURCES:
        raise HTTPException(404, "Unknown source")
    return sample(db, sentinel, source)


@router.post("/api/ingest/{source}")
async def ingest_logs(source: str, request: Request, db: Session = Depends(get_db)):
    """Sign-in logs from a company system. Authenticate with an X-API-Key header (or an admin login)."""
    from detection_service import sentinel
    header = request.headers.get("authorization", "")
    claims = auth.verify(header[7:]) if header.lower().startswith("bearer ") else None
    if not (claims and claims.get("role") == "admin") and not valid_key(db, request.headers.get("x-api-key", "")):
        raise HTTPException(401, "Send a valid X-API-Key header (create one on the Integrations page)")
    if int(request.headers.get("content-length") or 0) > 5_000_000:
        raise HTTPException(413, "Send at most 5 MB per request")
    try:
        payload = await request.json()
        summary = ingest(db, sentinel, source, payload)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    audit(db, request, "logs_ingested", source,
          f"{summary['sessions']} sessions, {summary['failed_logins']} failed sign-ins, {len(summary['alerts'])} alerts",
          actor=(claims or {}).get("sub") or "api-key")
    return summary


@router.get("/api/export/events")
def export_events(format: str = Query("cef", pattern="^(cef|jsonl|csv)$"), hours: int = Query(24, ge=1, le=24 * 90),
                  alerts_only: bool = True, db: Session = Depends(get_db)):
    """Alerts for a SIEM (Splunk, Microsoft Sentinel, QRadar, Elastic) as CEF, JSON lines or CSV."""
    text, media = export(db, format, hours, alerts_only)
    ext = {"cef": "cef.log", "jsonl": "jsonl", "csv": "csv"}[format]
    return Response(text, media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="sentinelai-alerts.{ext}"'})
