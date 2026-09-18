"""SentinelAI detection pipeline.

History timeline (45 days by default):
  days  0-13  baseline -> first digital twins
  days 14-34  training -> the anomaly models learn what normal drift looks like
  days 35-45  test     -> attacks are planted here; used to measure accuracy
Live and simulated sessions are scored against twins built from days 0-34.
"""
import logging
import os
import random
import threading
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import numpy as np
from sqlalchemy import func, select
from sqlalchemy.orm import Session

import simulator
from database import reset_db
from feature_engineering import FEATURE_NAMES, build_twin, compute_features
from ml_detector import AnomalyDetector
from models import Employee, Event
from risk_engine import TIERS, assess

log = logging.getLogger("sentinel.engine")

DATA_PATH = Path(os.getenv(
    "SENTINEL_DATA",
    Path(__file__).resolve().parent.parent / "data" / "synthetic_security_events.csv",
))
BASELINE_DAYS = 14
TRAIN_END_DAY = 35
ALERT_THRESHOLD = 60  # MFA or BLOCK counts as "detected"

EVENT_FIELDS = [
    "user_id", "timestamp", "city", "country", "lat", "lon", "ip", "os", "browser",
    "failed_attempts", "files_downloaded", "mb_downloaded", "api_calls",
    "sensitive_access", "session_minutes", "resources", "actions", "scenario",
]


def event_dict(e: Event) -> dict:
    return {k: getattr(e, k) for k in EVENT_FIELDS}


def _score_report(labels: np.ndarray, flagged: np.ndarray) -> dict:
    tp = int(np.sum(flagged & labels))
    fp = int(np.sum(flagged & ~labels))
    fn = int(np.sum(~flagged & labels))
    tn = int(np.sum(~flagged & ~labels))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
        "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0.0,
    }


class SentinelEngine:
    def __init__(self):
        self.detector: AnomalyDetector | None = None
        self.twins: dict[str, dict] = {}
        self.metrics: dict = {}
        self.lock = threading.RLock()

    # ------------------------------------------------------------------ setup
    def bootstrap(self, db: Session) -> None:
        with self.lock:
            if db.scalar(select(func.count()).select_from(Employee)) == 0:
                self._seed(db)
            else:
                history = db.scalars(select(Event).where(Event.source == "history").order_by(Event.timestamp)).all()
                self._fit([event_dict(e) for e in history])

    def reset(self, db: Session) -> None:
        with self.lock:
            reset_db()
            self._seed(db)

    def _load_history(self) -> list[dict]:
        if DATA_PATH.exists():
            events = simulator.load_csv(DATA_PATH)
            log.info("Loaded %d events from %s", len(events), DATA_PATH)
        else:
            events = simulator.generate_history()
            try:
                simulator.save_csv(events, DATA_PATH)
            except OSError:
                log.warning("Could not write %s", DATA_PATH)
        # Shift the dataset so its last event is "now" and the dashboard looks live.
        shift = simulator.now_ist() - max(e["timestamp"] for e in events)
        for e in events:
            e["timestamp"] = e["timestamp"] + shift
        return events

    def _seed(self, db: Session) -> None:
        events = self._load_history()
        for uid in sorted({e["user_id"] for e in events}):
            p = simulator.PROFILES.get(uid)
            db.add(Employee(
                id=uid,
                name=p["name"] if p else uid,
                department=p["department"] if p else "Unknown",
                role=p["role"] if p else "Unknown",
                home_city=p["home_city"] if p else "Unknown",
            ))
        db.flush()
        self._fit(events)
        for e, facts, verdict in self._score_sequence(events):
            db.add(Event(**{k: e[k] for k in EVENT_FIELDS}, source="history", features=facts, **verdict))
        db.commit()
        log.info("Seeded %d sessions", len(events))

    def _score_sequence(self, events: list[dict]) -> list[tuple[dict, dict, dict]]:
        """Score chronologically ordered sessions, each compared with that user's last trusted session."""
        results, trusted = [], {}
        for e in events:
            vec, facts = compute_features(e, self.twin(e["user_id"]), trusted.get(e["user_id"]))
            verdict = assess(facts, float(self.detector.risk(vec)[0]))
            results.append((e, facts, verdict))
            if verdict["tier"] != "BLOCK":
                trusted[e["user_id"]] = e
        return results

    def _fit(self, events: list[dict]) -> None:
        start = min(e["timestamp"] for e in events)

        def day(e):
            return (e["timestamp"] - start).days

        users = {e["user_id"] for e in events}
        baseline_twins = {u: build_twin([e for e in events if e["user_id"] == u and day(e) < BASELINE_DAYS])
                          for u in users}

        X, last = [], {}
        for e in events:
            if BASELINE_DAYS <= day(e) < TRAIN_END_DAY:
                vec, _ = compute_features(e, baseline_twins[e["user_id"]], last.get(e["user_id"]))
                X.append(vec)
            last[e["user_id"]] = e

        self.detector = AnomalyDetector().fit(np.array(X))
        self.twins = {u: build_twin([e for e in events if e["user_id"] == u and day(e) < TRAIN_END_DAY])
                      for u in users}
        self.metrics = self._evaluate(events, day)
        log.info("Model trained on %d sessions; test recall %.2f precision %.2f",
                 len(X), self.metrics["hybrid"]["recall"], self.metrics["hybrid"]["precision"])

    def _evaluate(self, events: list[dict], day) -> dict:
        rows = [(e["scenario"], v["ml_score"], v["rule_score"], v["risk"])
                for e, _, v in self._score_sequence(events) if day(e) >= TRAIN_END_DAY]
        labels = np.array([r[0] is not None for r in rows])
        ml = np.array([r[1] for r in rows])
        rules = np.array([r[2] for r in rows])
        hybrid = np.array([r[3] for r in rows])
        per_scenario = {}
        for name in simulator.SCENARIOS:
            hits = [r[3] >= ALERT_THRESHOLD for r in rows if r[0] == name]
            per_scenario[name] = {"label": simulator.SCENARIOS[name]["label"],
                                  "caught": int(sum(hits)), "total": len(hits)}
        return {
            "test_sessions": len(rows),
            "test_attacks": int(labels.sum()),
            "alert_threshold": ALERT_THRESHOLD,
            "ml_only": _score_report(labels, ml >= ALERT_THRESHOLD),
            "rules_only": _score_report(labels, rules >= ALERT_THRESHOLD),
            "hybrid": _score_report(labels, hybrid >= ALERT_THRESHOLD),
            "per_scenario": per_scenario,
            "trained_on": self.detector.trained_on,
            "features": FEATURE_NAMES,
            "tiers": [{"min": t[0], "tier": t[1], "action": t[2]} for t in TIERS],
        }

    # ---------------------------------------------------------------- scoring
    def twin(self, user_id: str) -> dict:
        return self.twins.get(user_id) or build_twin([])

    def _score(self, e: dict, prev: dict | None, source: str) -> Event:
        vec, facts = compute_features(e, self.twin(e["user_id"]), prev)
        verdict = assess(facts, float(self.detector.risk(vec)[0]))
        return Event(**{k: e[k] for k in EVENT_FIELDS}, source=source, features=facts, **verdict)

    def _trusted_prev(self, db: Session, user_id: str, before, exclude_id: int | None = None) -> dict | None:
        """Last trusted (non-blocked) session, so an attacker's session never becomes the reference point."""
        q = select(Event).where(Event.user_id == user_id, Event.timestamp <= before, Event.tier != "BLOCK")
        if exclude_id is not None:
            q = q.where(Event.id != exclude_id)
        prev = db.scalars(q.order_by(Event.timestamp.desc(), Event.id.desc()).limit(1)).first()
        return event_dict(prev) if prev else None

    @staticmethod
    def _auto_block(db: Session, row: Event) -> None:
        emp = db.get(Employee, row.user_id)
        if row.tier == "BLOCK" and emp and emp.status != "blocked":
            emp.status = "blocked"
            emp.status_reason = f"Auto-blocked: session #{row.id} scored {row.risk}/100 ({row.threat})"
            emp.status_changed_at = simulator.now_ist()

    def ingest(self, db: Session, e: dict, source: str) -> Event:
        """Score a new session, store it, and auto-block the account on a BLOCK verdict."""
        with self.lock:
            row = self._score(e, self._trusted_prev(db, e["user_id"], e["timestamp"]), source)
            db.add(row)
            db.flush()
            self._auto_block(db, row)
            db.commit()
            db.refresh(row)
            return row

    def rescore(self, db: Session, row: Event) -> Event:
        """Re-score a stored session after its activity changed (staff portal sessions grow as people work)."""
        with self.lock:
            e = event_dict(row)
            fresh = self._score(e, self._trusted_prev(db, row.user_id, row.timestamp, exclude_id=row.id), row.source)
            for k in ("ml_score", "rule_score", "risk", "tier", "action", "threat", "reasons", "features"):
                setattr(row, k, getattr(fresh, k))
            row.explanation = row.explanation_source = None
            self._auto_block(db, row)
            db.commit()
            db.refresh(row)
            return row

    def simulate(self, db: Session, scenario: str, user_id: str | None = None) -> list[Event]:
        rng = random.Random()
        if user_id:
            profile = simulator.PROFILES[user_id]
        else:
            active = {e.id for e in db.scalars(select(Employee).where(Employee.status == "active"))}
            pool = [p for uid, p in simulator.PROFILES.items() if uid in active and p["hours"][0] < p["hours"][1] < 24]
            profile = rng.choice(pool or list(simulator.PROFILES.values()))
        events = simulator.make_attack(profile, scenario, simulator.now_ist(), rng)
        return [self.ingest(db, e, "simulated") for e in events]

    def live_tick(self, db: Session) -> Event | None:
        """Generate one ordinary session from someone whose shift is running right now."""
        now = simulator.now_ist()
        active = {e.id for e in db.scalars(select(Employee).where(Employee.status == "active"))}
        pool = [p for uid, p in simulator.PROFILES.items()
                if uid in active and now.hour in simulator.work_hours(p)]
        if not pool:
            return None
        rng = random.Random()
        return self.ingest(db, simulator.normal_session(rng.choice(pool), now, rng), "live")

    def preview(self, db: Session, e: dict, minutes_since_last: float) -> dict:
        """Score a hypothetical session without storing it (Risk Lab)."""
        prev = self._trusted_prev(db, e["user_id"], simulator.now_ist() + timedelta(days=1))
        if prev:
            prev = {**prev, "timestamp": e["timestamp"] - timedelta(minutes=minutes_since_last)}
        vec, facts = compute_features(e, self.twin(e["user_id"]), prev)
        verdict = assess(facts, float(self.detector.risk(vec)[0]))
        session = SimpleNamespace(**e, features=facts)
        return verdict | {"comparison": self.compare(session), "last_city": prev["city"] if prev else None}

    def compare(self, event: Event) -> list[dict]:
        """Digital twin vs this session, row by row, for the dashboard."""
        t, f = self.twin(event.user_id), event.features

        def level(bad, critical=False):
            return "critical" if bad and critical else "warn" if bad else "ok"

        return [
            {"label": "Login time", "normal": t["usual_hours"], "current": f["time"],
             "level": level(f["hours_outside"] > 0, f["hours_outside"] >= 3)},
            {"label": "Location", "normal": ", ".join(t["known_cities"][:3]) or "unknown",
             "current": f"{event.city}, {event.country}",
             "level": level(f["new_city"] or f["new_country"], f["new_country"])},
            {"label": "Device", "normal": t["primary_device"], "current": f["device"],
             "level": level(f["new_device"], f["automation_client"])},
            {"label": "Failed logins", "normal": f"~{t['avg_failed']:.1f}", "current": str(event.failed_attempts),
             "level": level(event.failed_attempts >= 3, event.failed_attempts >= 5)},
            {"label": "Files downloaded", "normal": f"~{t['avg_files']:.0f}", "current": f"{event.files_downloaded:,}",
             "level": level(f["files_ratio"] >= 3, f["files_ratio"] >= 8)},
            {"label": "Data volume", "normal": f"~{t['avg_mb']:.0f} MB", "current": f"{event.mb_downloaded:,.0f} MB",
             "level": level(f["mb_ratio"] >= 3, f["mb_ratio"] >= 8)},
            {"label": "API requests", "normal": f"~{t['avg_api']:.0f}", "current": f"{event.api_calls:,}",
             "level": level(f["api_ratio"] >= 3, f["api_ratio"] >= 20)},
            {"label": "Sensitive access", "normal": f"~{t['avg_sensitive']:.0f}", "current": str(event.sensitive_access),
             "level": level(f["sensitive_ratio"] >= 2.5, f["sensitive_ratio"] >= 4)},
            {"label": "Systems opened", "normal": ", ".join(t.get("familiar_resources", [])[:3]) or "none",
             "current": ", ".join(f.get("resources", [])) or "none",
             "level": level(bool(f.get("new_resources")), len(f.get("new_resources", [])) >= 2)},
            {"label": "Admin actions", "normal": ", ".join(t.get("familiar_actions", [])) or "none",
             "current": ", ".join(f.get("actions", [])) or "none",
             "level": level(bool(f.get("new_actions")), bool(f.get("tampering")))},
        ]


sentinel = SentinelEngine()
