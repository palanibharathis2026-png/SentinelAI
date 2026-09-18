"""Helpers shared by the API modules: serializers and lookups."""
from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

import simulator
from models import AuditLog, Employee, Event

ALERT_TIERS = ("MFA", "BLOCK")


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
        "resources": e.resources or [], "actions": e.actions or [], "lat": e.lat, "lon": e.lon,
        "ml_score": e.ml_score, "rule_score": e.rule_score, "risk": e.risk, "tier": e.tier,
        "action": e.action, "threat": e.threat, "reasons": e.reasons, "status": e.status,
        "simulated_scenario": simulator.SCENARIOS[e.scenario]["label"] if e.source == "simulated" and e.scenario else None,
    }


def names(db: Session) -> dict[str, str]:
    return dict(db.execute(select(Employee.id, Employee.name)).all())


def latest_time(db: Session):
    return db.scalar(select(func.max(Event.timestamp))) or simulator.now_ist()


def get_event(db: Session, event_id: int) -> Event:
    event = db.get(Event, event_id)
    if not event:
        raise HTTPException(404, "Event not found")
    return event


def audit(db: Session, request, action: str, target: str | None = None, detail: str | None = None,
          actor: str | None = None) -> None:
    """Record a security-relevant action in the audit log."""
    claims = getattr(getattr(request, "state", None), "user", None) or {}
    ip = request.client.host if request is not None and request.client else None
    db.add(AuditLog(at=simulator.now_ist(), actor=actor or claims.get("sub") or "anonymous", action=action,
                    target=target, detail=detail, ip=ip))
    db.commit()


def get_employee(db: Session, user_id: str) -> Employee:
    emp = db.get(Employee, user_id)
    if not emp:
        raise HTTPException(404, "Employee not found")
    return emp
