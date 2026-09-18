"""SentinelAI API: behavioural security for detecting compromised accounts and insider threats."""
from dotenv import load_dotenv

load_dotenv()

import asyncio  # noqa: E402
import logging  # noqa: E402
import os  # noqa: E402
from contextlib import asynccontextmanager  # noqa: E402
from datetime import timedelta  # noqa: E402

from fastapi import Depends, FastAPI, HTTPException, Query  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from pydantic import BaseModel  # noqa: E402
from sqlalchemy import func, select  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

import analyst  # noqa: E402
import simulator  # noqa: E402
from database import SessionLocal, get_db, init_db  # noqa: E402
from detection_service import sentinel  # noqa: E402
from models import Employee, Event  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("sentinel.api")

ALERT_TIERS = ("MFA", "BLOCK")
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
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


# ------------------------------------------------------------------ serializers
def employee_out(e: Employee) -> dict:
    return {"id": e.id, "name": e.name, "department": e.department, "role": e.role,
            "home_city": e.home_city, "status": e.status, "status_reason": e.status_reason,
            "status_changed_at": e.status_changed_at}


def event_out(e: Event, names: dict[str, str]) -> dict:
    return {
        "id": e.id, "user_id": e.user_id, "name": names.get(e.user_id, e.user_id),
        "timestamp": e.timestamp, "city": e.city, "country": e.country, "ip": e.ip,
        "device": f"{e.os} / {e.browser}", "failed_attempts": e.failed_attempts,
        "files_downloaded": e.files_downloaded, "mb_downloaded": e.mb_downloaded,
        "api_calls": e.api_calls, "sensitive_access": e.sensitive_access,
        "session_minutes": e.session_minutes, "source": e.source,
        "ml_score": e.ml_score, "rule_score": e.rule_score, "risk": e.risk, "tier": e.tier,
        "action": e.action, "threat": e.threat, "reasons": e.reasons, "status": e.status,
        "simulated_scenario": simulator.SCENARIOS[e.scenario]["label"] if e.source == "simulated" and e.scenario else None,
    }


def _names(db: Session) -> dict[str, str]:
    return dict(db.execute(select(Employee.id, Employee.name)).all())


def _latest_time(db: Session):
    return db.scalar(select(func.max(Event.timestamp))) or simulator.now_ist()


def _get_event(db: Session, event_id: int) -> Event:
    event = db.get(Event, event_id)
    if not event:
        raise HTTPException(404, "Event not found")
    return event


def _get_employee(db: Session, user_id: str) -> Employee:
    emp = db.get(Employee, user_id)
    if not emp:
        raise HTTPException(404, "Employee not found")
    return emp


# ------------------------------------------------------------------ endpoints
@app.get("/api/health")
def health():
    return {"status": "ok", "model_trained": sentinel.detector is not None,
            "ai_analyst": "claude" if analyst.llm_enabled() else "template"}


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
def update_event_status(event_id: int, body: StatusUpdate, db: Session = Depends(get_db)):
    if body.status not in ("open", "resolved", "false_positive"):
        raise HTTPException(400, "status must be open, resolved or false_positive")
    event = _get_event(db, event_id)
    event.status = body.status
    db.commit()
    return {"id": event.id, "status": event.status}


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
def block_user(user_id: str, body: BlockRequest | None = None, db: Session = Depends(get_db)):
    emp = _get_employee(db, user_id)
    emp.status = "blocked"
    emp.status_reason = (body.reason if body and body.reason else "Blocked manually by SOC analyst")
    emp.status_changed_at = simulator.now_ist()
    db.commit()
    return employee_out(emp)


@app.post("/api/users/{user_id}/unblock")
def unblock_user(user_id: str, db: Session = Depends(get_db)):
    emp = _get_employee(db, user_id)
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
def simulate(body: SimulateRequest, db: Session = Depends(get_db)):
    if body.scenario not in simulator.SCENARIOS:
        raise HTTPException(400, f"Unknown scenario. Choose from: {', '.join(simulator.SCENARIOS)}")
    if body.user_id and body.user_id not in simulator.PROFILES:
        raise HTTPException(404, "Simulation needs one of the built-in employee profiles")
    events = sentinel.simulate(db, body.scenario, body.user_id)
    names = _names(db)
    return [event_out(e, names) for e in events]


@app.get("/api/model")
def model_info():
    return sentinel.metrics


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
def reset(db: Session = Depends(get_db)):
    sentinel.reset(db)
    return {"status": "reset", "sessions": db.scalar(select(func.count()).select_from(Event))}
