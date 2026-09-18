"""SentinelAI API: behavioural security for detecting compromised accounts and insider threats."""
from dotenv import load_dotenv

load_dotenv()

import asyncio  # noqa: E402
import json  # noqa: E402
import logging  # noqa: E402
import os  # noqa: E402
import socket  # noqa: E402
from contextlib import asynccontextmanager  # noqa: E402
from datetime import timedelta  # noqa: E402

from fastapi import Depends, FastAPI, HTTPException, Query, Request  # noqa: E402
from fastapi.responses import FileResponse, JSONResponse  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from pydantic import BaseModel  # noqa: E402
from sqlalchemy import func, select  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

import analyst  # noqa: E402
import integrations  # noqa: E402
import auth  # noqa: E402
import portal  # noqa: E402
import simulator  # noqa: E402
from database import SessionLocal, get_db, init_db  # noqa: E402
from common import ALERT_TIERS, audit, employee_out, event_out  # noqa: E402
from common import get_employee as _get_employee  # noqa: E402
from common import get_event as _get_event  # noqa: E402
from common import latest_time as _latest_time  # noqa: E402
from common import names as _names  # noqa: E402
from detection_service import CARD_FILE, MODEL_DIR, MODEL_FILE, sentinel  # noqa: E402
from models import Employee, Event  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("sentinel.api")

live = {
    "enabled": os.getenv("LIVE_TRAFFIC", "true").lower() == "true",
    "interval": float(os.getenv("LIVE_INTERVAL_SECONDS", "8")),
}


async def live_traffic_loop():
    """Background 'company activity': a normal session every few seconds so the dashboard is alive."""
    def tick():
        with SessionLocal() as db:
            sentinel.live_tick(db)

    while True:
        await asyncio.sleep(live["interval"])
        if live["enabled"]:
            try:
                await asyncio.to_thread(tick)
            except Exception:
                log.exception("live traffic tick failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    with SessionLocal() as db:
        sentinel.bootstrap(db)
    task = asyncio.create_task(live_traffic_loop())
    yield
    task.cancel()


app = FastAPI(title="SentinelAI", version="1.0.0", lifespan=lifespan)

# Everything under /api needs a login except these. Staff tokens may only use their own portal endpoints.
OPEN_PATHS = {"/api/health", "/api/auth/login", "/api/auth/admin-2fa", "/api/auth/staff-login", "/api/auth/staff-otp"}


@app.middleware("http")
async def require_login(request: Request, call_next):
    path = request.url.path
    if (request.method == "OPTIONS" or not path.startswith("/api/") or path in OPEN_PATHS
            or path.startswith(integrations.OPEN_PREFIXES)):
        return await call_next(request)
    header = request.headers.get("authorization", "")
    claims = auth.verify(header[7:] if header.lower().startswith("bearer ") else "")
    if not claims:
        return JSONResponse({"detail": "Please log in"}, status_code=401)
    if claims["role"] != "admin" and not path.startswith("/api/staff/me"):
        return JSONResponse({"detail": "Admins only"}, status_code=403)
    request.state.user = claims
    return await call_next(request)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Browser hardening headers on every API response."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


# Added after the auth middleware so it wraps it and 401 responses still carry CORS headers.
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


def _lan_ip() -> str | None:
    """This machine's address on the local network, so guests on the same Wi-Fi can open the staff portal."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))  # UDP connect sends no packets; it only picks the outgoing interface
            return sock.getsockname()[0]
    except OSError:
        return None


@app.get("/api/health")
def health():
    return {"status": "ok", "model_trained": sentinel.detector is not None,
            "ai_analyst": "claude" if analyst.llm_enabled() else "template", "lan_ip": _lan_ip()}


@app.get("/api/stats")
def stats(db: Session = Depends(get_db)):
    since = _latest_time(db) - timedelta(hours=24)
    recent = db.scalars(select(Event).where(Event.timestamp >= since)).all()
    tiers = {t: 0 for t in ("ALLOW", "MONITOR", "MFA", "BLOCK")}
    for e in recent:
        tiers[e.tier] += 1
    top: dict[str, int] = {}
    for e in recent:
        top[e.user_id] = max(top.get(e.user_id, 0), e.risk)
    names = _names(db)
    return {
        "sessions_24h": len(recent),
        "total_sessions": db.scalar(select(func.count()).select_from(Event)),
        "open_alerts": db.scalar(select(func.count()).select_from(Event)
                                 .where(Event.tier.in_(ALERT_TIERS), Event.status == "open")),
        "blocked_users": db.scalar(select(func.count()).select_from(Employee).where(Employee.status == "blocked")),
        "employees": db.scalar(select(func.count()).select_from(Employee)),
        "avg_risk_24h": round(sum(e.risk for e in recent) / len(recent), 1) if recent else 0,
        "tiers_24h": tiers,
        "top_risky_users": [{"user_id": u, "name": names.get(u, u), "max_risk": r}
                            for u, r in sorted(top.items(), key=lambda x: -x[1])[:5]],
        "live_traffic": live["enabled"],
    }


@app.get("/api/events")
def list_events(limit: int = Query(50, le=500), min_risk: int = 0, user_id: str | None = None,
                tier: str | None = None, db: Session = Depends(get_db)):
    q = select(Event).where(Event.risk >= min_risk)
    if user_id:
        q = q.where(Event.user_id == user_id)
    if tier:
        q = q.where(Event.tier == tier.upper())
    rows = db.scalars(q.order_by(Event.timestamp.desc(), Event.id.desc()).limit(limit)).all()
    names = _names(db)
    return [event_out(e, names) for e in rows]


@app.get("/api/alerts")
def list_alerts(status: str = "open", limit: int = Query(30, le=200), db: Session = Depends(get_db)):
    q = select(Event).where(Event.tier.in_(ALERT_TIERS))
    if status != "all":
        q = q.where(Event.status == status)
    rows = db.scalars(q.order_by(Event.timestamp.desc(), Event.id.desc()).limit(limit)).all()
    names = _names(db)
    return [event_out(e, names) for e in rows]


@app.get("/api/events/{event_id}")
def get_event(event_id: int, db: Session = Depends(get_db)):
    event = _get_event(db, event_id)
    emp = _get_employee(db, event.user_id)
    return {
        "event": event_out(event, {emp.id: emp.name}),
        "employee": employee_out(emp),
        "twin": sentinel.twin(emp.id),
        "comparison": sentinel.compare(event),
        "explanation": event.explanation,
        "explanation_source": event.explanation_source,
    }


@app.post("/api/events/{event_id}/explain")
def explain_event(event_id: int, refresh: bool = False, db: Session = Depends(get_db)):
    event = _get_event(db, event_id)
    if event.explanation and not refresh:
        return {"explanation": event.explanation, "source": event.explanation_source}
    emp = _get_employee(db, event.user_id)
    verdict = {k: getattr(event, k) for k in ("risk", "tier", "action", "threat", "reasons", "ml_score", "rule_score")}
    session = event_out(event, {emp.id: emp.name}) | {"features": event.features}
    text, source = analyst.explain(employee_out(emp), session, sentinel.twin(emp.id), verdict)
    event.explanation, event.explanation_source = text, source
    db.commit()
    return {"explanation": text, "source": source}


class StatusUpdate(BaseModel):
    status: str


@app.patch("/api/events/{event_id}/status")
def update_event_status(event_id: int, body: StatusUpdate, request: Request, db: Session = Depends(get_db)):
    if body.status not in ("open", "resolved", "false_positive"):
        raise HTTPException(400, "status must be open, resolved or false_positive")
    event = _get_event(db, event_id)
    before = {"risk": event.risk, "tier": event.tier, "threat": event.threat}
    was = event.status
    event.status = body.status
    db.commit()
    out = {"id": event.id, "status": event.status}
    if "false_positive" in (was, body.status):
        # Feedback loop: the twin learns (or un-learns) this session straight away.
        changes = sentinel.learn_user(db, event.user_id)
        out["learning"] = {"changes": changes, "before": before, "after": sentinel.rescore_preview(db, event)}
    audit(db, request, "alert_feedback", str(event.id), f"{event.user_id}: {was} -> {body.status}")
    return out


@app.get("/api/learning")
def learning(db: Session = Depends(get_db)):
    """State of the self-learning loop: labels, twins that learned, and every model version."""
    out = sentinel.learning_summary(db)
    who = _names(db)
    for t in out["twins"]:
        t["name"] = who.get(t["user_id"], t["user_id"])
    return out


@app.post("/api/learning/retrain")
def learning_retrain(request: Request, db: Session = Depends(get_db)):
    result = sentinel.retrain(db)
    audit(db, request, "model_retrain", result.get("version"),
          ("accepted: " if result["accepted"] else "rejected: ") + result["reason"])
    return result


@app.get("/api/users")
def list_users(db: Session = Depends(get_db)):
    since = _latest_time(db) - timedelta(hours=24)
    latest = {}
    for e in db.scalars(select(Event).order_by(Event.timestamp)).all():
        latest[e.user_id] = e
    peak = dict(db.execute(select(Event.user_id, func.max(Event.risk))
                           .where(Event.timestamp >= since).group_by(Event.user_id)).all())
    counts = dict(db.execute(select(Event.user_id, func.count()).group_by(Event.user_id)).all())
    out = []
    for emp in db.scalars(select(Employee).order_by(Employee.id)).all():
        last = latest.get(emp.id)
        out.append(employee_out(emp) | {
            "sessions": counts.get(emp.id, 0),
            "last_seen": last.timestamp if last else None,
            "last_risk": last.risk if last else 0,
            "last_tier": last.tier if last else "ALLOW",
            "peak_risk_24h": peak.get(emp.id, 0),
        })
    return out


@app.get("/api/users/{user_id}")
def get_user(user_id: str, db: Session = Depends(get_db)):
    emp = _get_employee(db, user_id)
    rows = db.scalars(select(Event).where(Event.user_id == user_id)
                      .order_by(Event.timestamp.desc()).limit(60)).all()
    return {"employee": employee_out(emp), "twin": sentinel.twin(user_id),
            "events": [event_out(e, {emp.id: emp.name}) for e in rows]}


class BlockRequest(BaseModel):
    reason: str | None = None


@app.post("/api/users/{user_id}/block")
def block_user(user_id: str, request: Request, body: BlockRequest | None = None, db: Session = Depends(get_db)):
    emp = _get_employee(db, user_id)
    emp.status = "blocked"
    emp.status_reason = (body.reason if body and body.reason else "Blocked manually by SOC analyst")
    emp.status_changed_at = simulator.now_ist()
    db.commit()
    audit(db, request, "block", user_id, emp.status_reason)
    return employee_out(emp)


@app.post("/api/users/{user_id}/unblock")
def unblock_user(user_id: str, request: Request, db: Session = Depends(get_db)):
    emp = _get_employee(db, user_id)
    audit(db, request, "unlock", user_id, f"was: {emp.status_reason or emp.status}")
    emp.status, emp.status_reason, emp.status_changed_at = "active", None, simulator.now_ist()
    db.commit()
    return employee_out(emp)


@app.get("/api/timeline")
def timeline(hours: int = Query(72, le=24 * 60), db: Session = Depends(get_db)):
    since = _latest_time(db) - timedelta(hours=hours)
    rows = db.scalars(select(Event).where(Event.timestamp >= since).order_by(Event.timestamp)).all()
    names = _names(db)
    return [{"id": e.id, "timestamp": e.timestamp, "risk": e.risk, "tier": e.tier,
             "user_id": e.user_id, "name": names.get(e.user_id, e.user_id), "threat": e.threat}
            for e in rows]


@app.get("/api/scenarios")
def scenarios():
    return [{"id": k, **v} for k, v in simulator.SCENARIOS.items()]


class SimulateRequest(BaseModel):
    scenario: str
    user_id: str | None = None


@app.post("/api/simulate")
def simulate(body: SimulateRequest, request: Request, db: Session = Depends(get_db)):
    if body.scenario not in simulator.SCENARIOS:
        raise HTTPException(400, f"Unknown scenario. Choose from: {', '.join(simulator.SCENARIOS)}")
    if body.user_id and body.user_id not in simulator.PROFILES:
        raise HTTPException(404, "Simulation needs one of the built-in employee profiles")
    events = sentinel.simulate(db, body.scenario, body.user_id)
    audit(db, request, "simulate_attack", events[-1].user_id, simulator.SCENARIOS[body.scenario]["label"])
    names = _names(db)
    return [event_out(e, names) for e in events]


app.include_router(portal.router)
app.include_router(integrations.router)
sentinel.on_alert = integrations.dispatch_async


# ------------------------------------------------------------------ risk lab
LAB_DEVICES = {
    "usual": "Usual work device",
    "second": "Known second device (phone)",
    "new": "Brand-new laptop",
    "bot": "Automation script (python-httpx)",
}


@app.get("/api/lab/options")
def lab_options():
    return {
        "cities": [{"city": c, "country": v[0]} for c, v in simulator.LOCATIONS.items()],
        "devices": [{"id": k, "label": v} for k, v in LAB_DEVICES.items()],
        "resources": sorted({r for rs in simulator.ROLE_RESOURCES.values() for r in rs} | set(simulator.HIGH_VALUE)),
        "actions": sorted({a for acts in simulator.ROLE_ACTIONS.values() for a in acts}
                          | simulator.TAMPERING_ACTIONS | {"bulk_export"}),
        "employees": [{"id": p["id"], "name": p["name"], "role": p["role"], "home_city": p["home_city"],
                       "resources": p["resources"], "actions": p["actions"], "files": p["files"],
                       "api": p["api"], "hours": p["hours"]} for p in simulator.PROFILES.values()],
    }


class ScoreRequest(BaseModel):
    user_id: str
    hour: int = 11
    weekend: bool = False
    city: str = "Chennai"
    device: str = "usual"
    files: int = 10
    mb_per_file: float | None = None
    api_calls: int = 100
    sensitive: int = 0
    failed_attempts: int = 0
    minutes_since_last: float = 240
    resources: list[str] = []
    actions: list[str] = []


@app.post("/api/lab/score")
def lab_score(body: ScoreRequest, db: Session = Depends(get_db)):
    """What-if scoring: build a hypothetical session and score it without storing it."""
    p = simulator.PROFILES.get(body.user_id)
    if not p:
        raise HTTPException(404, "Unknown employee")
    if body.city not in simulator.LOCATIONS or body.device not in LAB_DEVICES:
        raise HTTPException(400, "Unknown city or device")
    country, lat, lon = simulator.LOCATIONS[body.city]
    device = {"usual": p["device"], "second": p["alt_device"], "new": ("Linux", "Firefox"),
              "bot": ("Linux", "python-httpx")}[body.device]
    ts = simulator.now_ist().replace(hour=max(0, min(23, body.hour)), minute=15, second=0)
    while (ts.weekday() >= 5) != body.weekend:
        ts -= timedelta(days=1)
    files = max(0, body.files)
    event = {
        "user_id": p["id"], "timestamp": ts, "city": body.city, "country": country, "lat": lat, "lon": lon,
        "ip": "10.0.0.1" if country == "India" else "185.220.101.7", "os": device[0], "browser": device[1],
        "failed_attempts": max(0, body.failed_attempts), "files_downloaded": files,
        "mb_downloaded": round(files * (body.mb_per_file or p["mb_per_file"]), 1),
        "api_calls": max(0, body.api_calls), "sensitive_access": max(0, body.sensitive),
        "session_minutes": 60, "resources": sorted(set(body.resources)), "actions": sorted(set(body.actions)),
        "scenario": None,
    }
    with sentinel.lock:
        result = sentinel.preview(db, event, max(1.0, body.minutes_since_last))
    return result | {"formula": f"1 - (1 - {result['ml_score'] / 100:.2f}) x (1 - {result['rule_score'] / 100:.2f})"}


# ------------------------------------------------------------------ threat map
@app.get("/api/map")
def threat_map(hours: int = Query(24 * 7, le=24 * 60), db: Session = Depends(get_db)):
    """Where sessions come from, plus attack arcs from the employee's home city to the suspicious login."""
    since = _latest_time(db) - timedelta(hours=hours)
    rows = db.scalars(select(Event).where(Event.timestamp >= since).order_by(Event.timestamp)).all()
    names = _names(db)
    cities: dict[str, dict] = {}
    arcs = []
    for e in rows:
        c = cities.setdefault(e.city, {"city": e.city, "country": e.country, "lat": e.lat, "lon": e.lon,
                                       "sessions": 0, "alerts": 0, "max_risk": 0})
        c["sessions"] += 1
        c["max_risk"] = max(c["max_risk"], e.risk)
        if e.tier in ALERT_TIERS:
            c["alerts"] += 1
            home = simulator.PROFILES.get(e.user_id, {}).get("home_city")
            if home in simulator.LOCATIONS and home != e.city:
                _, hlat, hlon = simulator.LOCATIONS[home]
                arcs.append({"id": e.id, "from": {"city": home, "lat": hlat, "lon": hlon},
                             "to": {"city": e.city, "lat": e.lat, "lon": e.lon},
                             "risk": e.risk, "tier": e.tier, "threat": e.threat,
                             "name": names.get(e.user_id, e.user_id), "timestamp": e.timestamp})
    return {"cities": sorted(cities.values(), key=lambda c: -c["sessions"]), "arcs": arcs[-40:]}


# ------------------------------------------------------------------ departments
@app.get("/api/departments")
def departments(db: Session = Depends(get_db)):
    """Department x threat-type heatmap over the last 7 days."""
    since = _latest_time(db) - timedelta(days=7)
    dept = dict(db.execute(select(Employee.id, Employee.department)).all())
    rows = db.scalars(select(Event).where(Event.timestamp >= since)).all()
    out: dict[str, dict] = {}
    for e in rows:
        d = out.setdefault(dept.get(e.user_id, "Unknown"),
                           {"department": dept.get(e.user_id, "Unknown"), "sessions": 0, "alerts": 0,
                            "risk_sum": 0, "max_risk": 0, "signals": {}})
        d["sessions"] += 1
        d["risk_sum"] += e.risk
        d["max_risk"] = max(d["max_risk"], e.risk)
        if e.tier in ALERT_TIERS:
            d["alerts"] += 1
        for r in e.reasons or []:
            d["signals"][r["signal"]] = d["signals"].get(r["signal"], 0) + 1
    for d in out.values():
        d["avg_risk"] = round(d.pop("risk_sum") / d["sessions"], 1)
    return sorted(out.values(), key=lambda d: (-d["alerts"], -d["avg_risk"]))


@app.get("/api/model")
def model_info():
    return sentinel.metrics


@app.get("/api/model/card")
def model_card():
    """What the trained model is, what it learned and how it was tested."""
    return sentinel.card


@app.get("/api/model/evaluation")
def model_evaluation():
    """Cross-validation over many datasets and results on real labelled data (written by evaluate.py)."""
    try:
        return json.loads((MODEL_DIR / "evaluation.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


@app.get("/api/model/download/{name}")
def model_download(name: str):
    """The trained model files, so anyone can open and inspect them."""
    files = {"model": MODEL_FILE, "card": CARD_FILE}
    if name not in files or not (MODEL_DIR / files[name]).exists():
        raise HTTPException(404, "Model file not found")
    return FileResponse(MODEL_DIR / files[name], filename=files[name])


class LiveUpdate(BaseModel):
    enabled: bool


@app.get("/api/live")
def get_live():
    return live


@app.post("/api/live")
def set_live(body: LiveUpdate):
    live["enabled"] = body.enabled
    return live


@app.post("/api/reset")
def reset(request: Request, db: Session = Depends(get_db)):
    sentinel.reset(db)
    audit(db, request, "reset_demo_data")
    return {"status": "reset", "sessions": db.scalar(select(func.count()).select_from(Event))}
