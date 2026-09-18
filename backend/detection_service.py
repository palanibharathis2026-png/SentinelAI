"""SentinelAI detection pipeline.

History timeline (45 days by default):
  days  0-13  baseline -> first digital twins
  days 14-34  training -> the anomaly models learn what normal drift looks like
  days 35-45  test     -> attacks are planted here; used to measure accuracy
Live and simulated sessions are scored against twins built from days 0-34.

Self-learning loop (analyst feedback):
  - An alert marked "false positive" is folded into that person's twin at once.
  - Twins also absorb low-risk (ALLOW) live sessions from the last 30 days once they
    are 12 hours old, so they follow slow changes in habits. Alerts, blocked accounts and
    confirmed attacks are never learned, so an attacker cannot teach the model.
  - "Retrain" trains a challenger model with the labelled false alarms added (weighted),
    tests it on the held-out attacks, and only replaces the live model if it misses
    no more attacks and raises no more false alarms (champion / challenger).
"""
import hashlib
import json
import logging
import os
import random
import threading
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import numpy as np
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

import simulator
from database import reset_db
from feature_engineering import FEATURE_NAMES, build_twin, compute_features
from ml_detector import AnomalyDetector, save_detector, split_usage
from model_export import export_readable
from models import Employee, Event, Setting
from risk_engine import TIERS, assess

log = logging.getLogger("sentinel.engine")

DATA_PATH = Path(os.getenv(
    "SENTINEL_DATA",
    Path(__file__).resolve().parent.parent / "data" / "synthetic_security_events.csv",
))
MODEL_DIR = Path(os.getenv("SENTINEL_MODEL_DIR", Path(__file__).resolve().parent.parent / "model"))
MODEL_FILE, CARD_FILE = "sentinel_model.npz", "model_card.json"
BASELINE_DAYS = 14
TRAIN_END_DAY = 35
LONG_DATASET_DAYS = 60  # longer datasets (e.g. CERT, 17 months) are split by share of time instead
EXTERNAL_LABELS = {"cert_insider": "CERT insider (real labelled data)"}


def split_days(span_days: int) -> tuple[int, int]:
    """(baseline end, training end) day numbers: fixed for the 45-day demo data, 30% / 75% for long datasets."""
    if span_days <= LONG_DATASET_DAYS:
        return BASELINE_DAYS, TRAIN_END_DAY
    return round(span_days * 0.30), round(span_days * 0.75)


def _curves(labels: np.ndarray, scores: np.ndarray) -> dict:
    """ROC and precision-recall curves over every alert threshold 0-100, with their areas."""
    pos, neg = int(labels.sum()), int((~labels).sum())
    roc, pr = [(0.0, 0.0)], []
    for t in range(101, -1, -1):
        flagged = scores >= t
        tp, fp = int(np.sum(flagged & labels)), int(np.sum(flagged & ~labels))
        tpr, fpr = (tp / pos if pos else 0.0), (fp / neg if neg else 0.0)
        roc.append((fpr, tpr))
        if tp + fp:
            pr.append((tpr, tp / (tp + fp)))
    roc.append((1.0, 1.0))
    auc = sum((x2 - x1) * (y1 + y2) / 2 for (x1, y1), (x2, y2) in zip(roc, roc[1:]))
    ap, last_recall = 0.0, 0.0
    for recall, precision in pr:
        ap += (recall - last_recall) * precision
        last_recall = recall

    def thin(points):
        keep, seen = [], set()
        for x, y in points:
            key = (round(x, 3), round(y, 3))
            if key not in seen:
                seen.add(key)
                keep.append([round(x, 4), round(y, 4)])
        return keep

    at_fpr = {}
    for budget in (0.01, 0.05, 0.10):  # best recall while flagging at most this share of normal sessions
        ok = [(tpr, t) for (fpr, tpr), t in zip(roc[1:-1], range(101, -1, -1)) if fpr <= budget]
        tpr, t = max(ok) if ok else (0.0, 101)
        at_fpr[str(budget)] = {"recall": round(tpr, 4), "threshold": t}
    return {"roc": thin(roc), "pr": thin(pr), "auc": round(auc, 4), "average_precision": round(ap, 4),
            "recall_at_false_alarm_rate": at_fpr}
ALERT_THRESHOLD = 60  # MFA or BLOCK counts as "detected"
LEARN_WINDOW_DAYS = 30  # twins absorb recent low-risk sessions from this many days
LEARN_MIN_AGE_HOURS = 12  # a session is learned only once it is finished
FEEDBACK_WEIGHT = 5  # each analyst-labelled false alarm counts as this many training sessions
MIN_OWN_SESSIONS = 10  # below this, a twin is completed from the person's peer group (same department)
VERSIONS_KEY = "model_versions"

FEATURE_DESCRIPTIONS = {
    "hours_outside_usual_window": "Hours between the login time and the person's usual working window",
    "unusual_weekend_login": "1 if a weekend login by someone who rarely works weekends",
    "new_device": "1 if the OS/browser was never used by this person",
    "new_country": "1 if this person never logged in from this country",
    "new_city": "1 if this person never logged in from this city",
    "travel_speed_log": "log(1 + km/h) needed to travel from the last trusted session",
    "failed_logins": "Failed attempts before the successful login",
    "download_ratio_log": "log of files downloaded vs. this person's average",
    "data_volume_ratio_log": "log of MB downloaded vs. this person's average",
    "api_ratio_log": "log of API calls vs. this person's average",
    "sensitive_ratio_log": "log of sensitive records opened vs. this person's average",
    "new_sensitive_systems": "Number of sensitive systems opened for the first time",
    "unfamiliar_admin_actions": "Number of admin actions this person never performed before",
}

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
        self.card: dict = {}
        self.twins: dict[str, dict] = {}
        self.base_twins: dict[str, dict] = {}  # built from history only; used for the fixed test set
        self.learned: dict[str, dict] = {}  # user -> sessions learned since training
        self.metrics: dict = {}
        self.version = "1.0"
        self.on_alert = None  # called with the event id of every new MFA / BLOCK alert (integrations)
        self.learn_sources = ("live", "portal", "okta", "entra", "google", "cloudtrail", "sentinel")
        self.feedback_used = 0
        self._events: list[dict] = []
        self._day = None
        self.baseline_days, self.train_end_day = BASELINE_DAYS, TRAIN_END_DAY
        self._train_X: np.ndarray | None = None
        # Devices enrolled by passing an email one-time code (staff portal): trusted like known devices.
        self.enrolled_devices: dict[str, set[str]] = {}
        self.lock = threading.RLock()

    # ------------------------------------------------------------------ setup
    def bootstrap(self, db: Session) -> None:
        with self.lock:
            if db.scalar(select(func.count()).select_from(Employee)) == 0:
                self._seed(db)
            else:
                history = db.scalars(select(Event).where(Event.source == "history").order_by(Event.timestamp)).all()
                self._fit([event_dict(e) for e in history])
            self._versions(db)
            self.learn_all(db)
            if self._feedback_rows(db):
                self.retrain(db, record=False)  # restore the model that the saved feedback produced

    def reset(self, db: Session) -> None:
        with self.lock:
            reset_db()
            db.query(Setting).filter(Setting.key == VERSIONS_KEY).delete()
            db.commit()
            self._seed(db)
            self.learned = {}
            self._versions(db)

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
        # Shift the dataset by whole days so it ends within the last 24 hours and the dashboard looks live.
        # Whole days keep every session's time of day, so each person's usual working hours stay right.
        shift = timedelta(days=(simulator.now_ist() - max(e["timestamp"] for e in events)).days)
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

    def _score_sequence(self, events: list[dict], detector: AnomalyDetector | None = None,
                        twins: dict | None = None, skip=None) -> list[tuple[dict, dict, dict]]:
        """Score chronologically ordered sessions, each compared with that user's last trusted session.
        Sessions where skip(e) is true are not scored; they only become the reference for the next one."""
        detector = detector or self.detector
        results, trusted = [], {}
        for e in events:
            if skip is not None and skip(e):
                trusted[e["user_id"]] = e
                continue
            twin = (twins.get(e["user_id"]) or build_twin([])) if twins is not None else self.twin(e["user_id"])
            vec, facts = compute_features(e, twin, trusted.get(e["user_id"]))
            verdict = assess(facts, float(detector.risk(vec)[0]))
            results.append((e, facts, verdict))
            if verdict["tier"] != "BLOCK":
                trusted[e["user_id"]] = e
        return results

    def _fit(self, events: list[dict], save: bool = True) -> None:
        start = min(e["timestamp"] for e in events)

        def day(e):
            return (e["timestamp"] - start).days

        BASELINE_DAYS, TRAIN_END_DAY = split_days(max(day(e) for e in events) + 1)  # noqa: N806
        self.baseline_days, self.train_end_day = BASELINE_DAYS, TRAIN_END_DAY

        users = {e["user_id"] for e in events}
        baseline_twins = {u: build_twin([e for e in events if e["user_id"] == u and day(e) < BASELINE_DAYS])
                          for u in users}

        X, last = [], {}
        for e in events:
            if BASELINE_DAYS <= day(e) < TRAIN_END_DAY:
                vec, _ = compute_features(e, baseline_twins[e["user_id"]], last.get(e["user_id"]))
                X.append(vec)
            last[e["user_id"]] = e

        self._events, self._day, self._train_X = events, day, np.array(X)
        self.detector = AnomalyDetector().fit(self._train_X)
        self.base_twins = {u: build_twin(self._history_of(u)) for u in users}
        self.twins = dict(self.base_twins)
        self._build_peer_twins()
        self.version, self.feedback_used = "1.0", 0
        self.metrics = self._evaluate(events, day)
        self.card = self._model_card(events, day, self._train_X)
        if save:
            self._save_model()
        log.info("Model trained on %d sessions; test recall %.2f precision %.2f",
                 len(X), self.metrics["hybrid"]["recall"], self.metrics["hybrid"]["precision"])

    def _model_card(self, events: list[dict], day, X: np.ndarray) -> dict:
        """Human-readable description of the trained model: what it is, what it learned, how good it is."""
        det = self.detector
        BASELINE_DAYS, TRAIN_END_DAY = self.baseline_days, self.train_end_day  # noqa: N806
        usage = split_usage(det, len(FEATURE_NAMES))
        data_bytes = DATA_PATH.read_bytes() if DATA_PATH.exists() else b""
        train = [e for e in events if BASELINE_DAYS <= day(e) < TRAIN_END_DAY]
        return {
            "name": "SentinelAI behavioural anomaly detector",
            "version": self.version,
            "trained_at": simulator.now_ist().isoformat(),
            "type": "Unsupervised anomaly detection ensemble (trained only on normal behaviour)",
            "algorithms": [
                {"name": "Isolation Forest", "role": "Finds unusual combinations of features",
                 "params": {"trees": det.forest.model.n_trees, "sample_size": det.forest.model.sample_size,
                            "max_depth": det.forest.model.max_depth, "random_state": det.forest.model.random_state}},
                {"name": "Robust Distance (median / MAD)", "role": "Measures how extreme each value is",
                 "params": {"scale_floor": 0.25, "direction": "upward deviations only"}},
            ],
            "combination": "ML risk = max(calibrated forest score, calibrated distance score); "
                           "final risk = 1 - (1 - ML/100) x (1 - rules/100)",
            "calibration": {"median_normal_session": 0, "p95_normal_session": det.at_risk,
                            "forest_raw": [round(det.forest.lo, 4), round(det.forest.hi, 4)],
                            "distance_raw": [round(det.distance.lo, 4), round(det.distance.hi, 4)]},
            "features": [{"name": n, "description": FEATURE_DESCRIPTIONS[n], "split_share": round(float(usage[i]), 4),
                          "normal_median": round(float(det.distance.model.median[i]), 4),
                          "normal_spread": round(float(det.distance.model.scale[i]), 4)}
                         for i, n in enumerate(FEATURE_NAMES)],
            "training_data": {
                "source": "Synthetic company activity from simulator.py (data/synthetic_security_events.csv)"
                          if DATA_PATH.name == "synthetic_security_events.csv" else f"External dataset: {DATA_PATH.name}",
                "span_days": max(day(e) for e in events) + 1,
                "sha256": hashlib.sha256(data_bytes).hexdigest() if data_bytes else None,
                "employees": len({e["user_id"] for e in events}),
                "sessions_total": len(events),
                "baseline_days": f"0-{BASELINE_DAYS - 1} (builds digital twins)",
                "training_days": f"{BASELINE_DAYS}-{TRAIN_END_DAY - 1}",
                "training_sessions": len(X),
                "analyst_feedback_sessions": self.feedback_used,
                "feedback_weight": FEEDBACK_WEIGHT,
                "training_attacks": sum(1 for e in train if e["scenario"]),
                "test_days": f"{TRAIN_END_DAY}+ (held out, contains the attacks)",
            },
            "evaluation": {**{k: self.metrics[k] for k in ("test_sessions", "test_attacks", "alert_threshold",
                                                           "ml_only", "rules_only", "hybrid", "per_scenario")},
                           "auc": {k: v["auc"] for k, v in self.metrics["curves"].items()},
                           "average_precision": {k: v["average_precision"] for k, v in self.metrics["curves"].items()}},
            "files": {"model": f"model/{MODEL_FILE}", "card": f"model/{CARD_FILE}"},
            "limitations": [
                "Trained on synthetic data; accuracy on real enterprise logs will be lower.",
                "A new employee has no twin yet, so early sessions are scored against defaults.",
                "Twins follow drift only through low-risk sessions and analyst labels; a very slow, "
                "patient attacker could still shift a twin over many weeks.",
            ],
        }

    def _save_model(self) -> None:
        try:
            MODEL_DIR.mkdir(parents=True, exist_ok=True)
            save_detector(self.detector, MODEL_DIR / MODEL_FILE)
            (MODEL_DIR / CARD_FILE).write_text(json.dumps(self.card, indent=2), encoding="utf-8")
            export_readable(self, MODEL_DIR, FEATURE_NAMES, FEATURE_DESCRIPTIONS)
        except OSError:
            log.warning("Could not save the model to %s", MODEL_DIR)

    def _evaluate(self, events: list[dict], day, detector: AnomalyDetector | None = None) -> dict:
        """Accuracy on the held-out test days, always against the history-only twins so versions compare fairly."""
        detector = detector or self.detector
        test_from = self.train_end_day
        scored = self._score_sequence(events, detector, self.base_twins, skip=lambda e: day(e) < test_from)
        rows = [(e["scenario"], v["ml_score"], v["rule_score"], v["risk"]) for e, _, v in scored]
        users = [e["user_id"] for e, _, _ in scored]
        labels = np.array([r[0] is not None for r in rows])
        ml = np.array([r[1] for r in rows])
        rules = np.array([r[2] for r in rows])
        hybrid = np.array([r[3] for r in rows])
        per_scenario = {}
        present = {r[0] for r in rows if r[0]}
        for name in [s for s in simulator.SCENARIOS if s in present or not present - set(simulator.SCENARIOS)] + \
                sorted(present - set(simulator.SCENARIOS)):
            hits = [r[3] >= ALERT_THRESHOLD for r in rows if r[0] == name]
            label = simulator.SCENARIOS[name]["label"] if name in simulator.SCENARIOS else \
                EXTERNAL_LABELS.get(name, name.replace("_", " ").capitalize())
            per_scenario[name] = {"label": label, "caught": int(sum(hits)), "total": len(hits)}
        curves = {"ml_only": _curves(labels, ml), "rules_only": _curves(labels, rules), "hybrid": _curves(labels, hybrid)}
        # Attackers caught: people with at least one flagged attack session (at our threshold, and at a 5% alert budget)
        attackers = {u for u, lab in zip(users, labels) if lab}
        t5 = curves["hybrid"]["recall_at_false_alarm_rate"]["0.05"]["threshold"]
        per_attacker = {
            "attackers": len(attackers),
            "caught": len({u for u, lab, r in zip(users, labels, hybrid) if lab and r >= ALERT_THRESHOLD}),
            "caught_at_5pct_alerts": len({u for u, lab, r in zip(users, labels, hybrid) if lab and r >= t5}),
        }
        return {
            "test_sessions": len(rows),
            "test_attacks": int(labels.sum()),
            "per_attacker": per_attacker,
            "alert_threshold": ALERT_THRESHOLD,
            "ml_only": _score_report(labels, ml >= ALERT_THRESHOLD),
            "rules_only": _score_report(labels, rules >= ALERT_THRESHOLD),
            "hybrid": _score_report(labels, hybrid >= ALERT_THRESHOLD),
            "per_scenario": per_scenario,
            "curves": curves,
            "trained_on": detector.trained_on,
            "features": FEATURE_NAMES,
            "tiers": [{"min": t[0], "tier": t[1], "action": t[2]} for t in TIERS],
        }

    # ---------------------------------------------------------- self-learning
    def _history_of(self, user_id: str) -> list[dict]:
        return [e for e in self._events if e["user_id"] == user_id and self._day(e) < self.train_end_day]

    @staticmethod
    def _feedback_rows(db: Session, user_id: str | None = None) -> list[Event]:
        q = select(Event).where(Event.status == "false_positive")
        if user_id:
            q = q.where(Event.user_id == user_id)
        return db.scalars(q.order_by(Event.timestamp)).all()

    def _learnable(self, db: Session, user_id: str) -> tuple[list[Event], list[Event]]:
        """(analyst-confirmed false alarms, recent finished low-risk sessions) for one person."""
        emp = db.get(Employee, user_id)
        feedback = self._feedback_rows(db, user_id)
        if emp is not None and emp.status == "blocked":
            return feedback, []
        now = simulator.now_ist()
        recent = db.scalars(select(Event).where(
            Event.user_id == user_id, Event.source.in_(self.learn_sources), Event.tier == "ALLOW",
            Event.status == "open", Event.timestamp >= now - timedelta(days=LEARN_WINDOW_DAYS),
            Event.timestamp <= now - timedelta(hours=LEARN_MIN_AGE_HOURS),
        )).all()
        return feedback, recent

    def learn_user(self, db: Session, user_id: str) -> dict:
        """Rebuild one twin from history + what the analyst and recent safe sessions taught it."""
        with self.lock:
            before = self.twins.get(user_id) or build_twin([])
            feedback, recent = self._learnable(db, user_id)
            self.twins[user_id] = build_twin(self._history_of(user_id) + [event_dict(r) for r in feedback + recent])
            self.learned[user_id] = {"feedback": len(feedback), "recent": len(recent)}
            after = self.twins[user_id]
            added = {key: [x for x in after[key] if x not in before[key]]
                     for key in ("known_devices", "known_cities", "known_countries",
                                 "familiar_resources", "familiar_actions", "active_hours")}
            return {"learned_sessions": len(feedback) + len(recent), **{k: v for k, v in added.items() if v}}

    def learn_all(self, db: Session) -> None:
        for uid in db.scalars(select(Employee.id)).all():
            self.learn_user(db, uid)

    def rescore_preview(self, db: Session, row: Event) -> dict:
        """How the same session would score now, with the current twin and model (nothing is stored)."""
        prev = self._trusted_prev(db, row.user_id, row.timestamp, exclude_id=row.id)
        vec, facts = compute_features(event_dict(row), self.twin(row.user_id), prev)
        v = assess(facts, float(self.detector.risk(vec)[0]))
        return {"risk": v["risk"], "tier": v["tier"], "threat": v["threat"]}

    def _versions(self, db: Session) -> list[dict]:
        row = db.get(Setting, VERSIONS_KEY)
        versions = json.loads(row.value) if row and row.value else []
        if not versions:
            h = self.metrics["hybrid"]
            versions = [{"version": "1.0", "at": simulator.now_ist().isoformat(), "accepted": True,
                         "feedback_labels": 0, "recall": h["recall"], "precision": h["precision"], "fp": h["fp"],
                         "note": "Base model trained on normal history"}]
            db.merge(Setting(key=VERSIONS_KEY, value=json.dumps(versions)))
            db.commit()
        return versions

    def retrain(self, db: Session, record: bool = True) -> dict:
        """Champion / challenger retraining with the analyst's false-positive labels."""
        with self.lock:
            self.learn_all(db)
            feedback = self._feedback_rows(db)
            if not feedback:
                return {"accepted": False, "reason": "No false-positive labels yet. Mark a wrong alert as "
                                                     "'False positive' on its incident page, then retrain."}
            if record and len(feedback) == self.feedback_used:
                return {"accepted": False, "version": self.version,
                        "reason": f"No new labels since version {self.version}. Twins were refreshed."}
            vecs = []
            for r in feedback:
                prev = self._trusted_prev(db, r.user_id, r.timestamp, exclude_id=r.id)
                vec, _ = compute_features(event_dict(r), self.base_twins.get(r.user_id) or build_twin([]), prev)
                vecs.append(vec)
            V = np.array(vecs)
            X = np.vstack([self._train_X, np.repeat(V, FEEDBACK_WEIGHT, axis=0)])
            challenger = AnomalyDetector().fit(X)

            new = self._evaluate(self._events, self._day, challenger)
            o, n = self.metrics["hybrid"], new["hybrid"]  # champion = the live model
            # ML risk the labelled false alarms get (lower = the model learned they are normal)
            ml_before = round(float(np.mean(self.detector.risk(V))), 1)
            ml_after = round(float(np.mean(challenger.risk(V))), 1)
            accepted = n["recall"] >= o["recall"] and n["fp"] <= o["fp"]

            versions = self._versions(db)
            if accepted:
                self.detector, self.metrics, self.feedback_used = challenger, new, len(feedback)
                if record:
                    major, minor = versions[-1]["version"].split(".") if versions else ("1", "0")
                    self.version = f"{major}.{int(minor) + 1}"
                else:
                    self.version = next((v["version"] for v in reversed(versions) if v["accepted"]), self.version)
                self.card = self._model_card(self._events, self._day, X)
                self._save_model()
            result = {
                "accepted": accepted, "version": self.version, "feedback_labels": len(feedback),
                "weight": FEEDBACK_WEIGHT, "training_sessions": len(X),
                "labelled_ml_risk": {"before": ml_before, "after": ml_after},
                "champion": {k: o[k] for k in ("recall", "precision", "fp")},
                "challenger": {k: n[k] for k in ("recall", "precision", "fp")},
                "reason": "Challenger is at least as good on the held-out attacks, so it replaced the live model."
                          if accepted else
                          "Challenger would miss more attacks or raise more false alarms on the held-out test, "
                          "so the current model stays live.",
            }
            if record:
                versions.append({"version": self.version if accepted else f"{self.version} (rejected)",
                                 "at": simulator.now_ist().isoformat(), "accepted": accepted,
                                 "feedback_labels": len(feedback), "recall": n["recall"],
                                 "precision": n["precision"], "fp": n["fp"], "note": result["reason"]})
                db.merge(Setting(key=VERSIONS_KEY, value=json.dumps(versions)))
                db.commit()
            return result

    def learning_summary(self, db: Session) -> dict:
        counts = dict(db.execute(select(Event.status, func.count()).where(
            or_(Event.tier.in_(("MFA", "BLOCK")), Event.status != "open")).group_by(Event.status)).all())
        fp, confirmed = counts.get("false_positive", 0), counts.get("resolved", 0)
        return {
            "version": self.version,
            "versions": list(reversed(self._versions(db))),
            "labels": {"false_positive": fp, "confirmed_attack": confirmed, "open_alerts": counts.get("open", 0)},
            "analyst_precision": round(confirmed / (confirmed + fp), 3) if confirmed + fp else None,
            "feedback_used": self.feedback_used,
            "settings": {"window_days": LEARN_WINDOW_DAYS, "min_age_hours": LEARN_MIN_AGE_HOURS,
                         "feedback_weight": FEEDBACK_WEIGHT},
            "twins": [{"user_id": u, **v} for u, v in sorted(self.learned.items()) if v["feedback"] or v["recent"]],
        }

    # ---------------------------------------------------------------- scoring
    # ------------------------------------------------------------ peer groups
    @staticmethod
    def _department(user_id: str) -> str | None:
        p = simulator.PROFILES.get(user_id)
        return p["department"] if p else None

    def _build_peer_twins(self) -> None:
        """One twin per department (and one for the whole company) from everyone's normal history."""
        by_dept: dict[str, list[dict]] = {}
        everyone = []
        for e in self._events:
            if self._day(e) < self.train_end_day and not e["scenario"]:
                by_dept.setdefault(self._department(e["user_id"]) or "Unknown", []).append(e)
                everyone.append(e)
        self.peer_twins = {d: build_twin(evs) for d, evs in by_dept.items()}
        self.peer_twins["*"] = build_twin(everyone)
        self.peer_members = {d: sorted({e["user_id"] for e in evs}) for d, evs in by_dept.items()}

    def _peer_blend(self, user_id: str, own: dict) -> dict:
        """A new joiner has little history: habits come from their department, identity facts from themselves."""
        dept = self._department(user_id)
        peer = self.peer_twins.get(dept) or self.peer_twins.get("*") or build_twin([])
        p = simulator.PROFILES.get(user_id, {})
        home = p.get("home_city") or own["home_city"]
        country = simulator.LOCATIONS.get(home, ("India",))[0]
        return {
            **peer,
            "sessions": own["sessions"],
            "active_hours": sorted(set(peer["active_hours"]) | set(own["active_hours"] if own["sessions"] else [])),
            "known_devices": own["known_devices"],
            "primary_device": own["primary_device"] if own["sessions"] else "not seen yet",
            "known_cities": own["known_cities"] or [home],
            "known_countries": own["known_countries"] or [country],
            "home_city": own["home_city"] if own["sessions"] else home,
            "familiar_resources": sorted(set(peer["familiar_resources"]) | set(own["familiar_resources"])),
            "familiar_actions": sorted(set(peer["familiar_actions"]) | set(own["familiar_actions"])),
            "baseline": "peer group",
            "peer_group": dept if dept in self.peer_twins else "whole company",
        }

    def peer_comparison(self, user_id: str) -> dict:
        """This person's usual activity next to their department's, with where they rank."""
        dept = self._department(user_id)
        members = [u for u in self.peer_members.get(dept, []) if u != user_id]
        own = self.twin(user_id)
        rows = []
        for key, label in (("avg_files", "Files per session"), ("avg_mb", "MB per session"),
                           ("avg_api", "API calls per session"), ("avg_sensitive", "Sensitive records per session")):
            peer_values = [self.twins[u][key] for u in members if u in self.twins and self.twins[u]["sessions"]]
            below = sum(v < own[key] for v in peer_values)
            rows.append({"metric": label, "you": own[key],
                         "peers": round(float(np.median(peer_values)), 2) if peer_values else None,
                         "percentile": round(100 * below / len(peer_values)) if peer_values else None})
        return {"department": dept, "peers": len(members), "baseline": own.get("baseline", "own history"), "rows": rows}

    def twin(self, user_id: str) -> dict:
        t = self.twins.get(user_id) or build_twin([])
        if t["sessions"] < MIN_OWN_SESSIONS and getattr(self, "peer_twins", None):
            t = self._peer_blend(user_id, t)
        extra = self.enrolled_devices.get(user_id)
        if extra:
            t = {**t, "known_devices": t["known_devices"] + sorted(extra - set(t["known_devices"]))}
        return t

    def enroll_device(self, user_id: str, device: str) -> None:
        self.enrolled_devices.setdefault(user_id, set()).add(device)

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
            self._notify(row, None)
            return row

    def rescore(self, db: Session, row: Event) -> Event:
        """Re-score a stored session after its activity changed (staff portal sessions grow as people work)."""
        with self.lock:
            e = event_dict(row)
            old_tier = row.tier
            fresh = self._score(e, self._trusted_prev(db, row.user_id, row.timestamp, exclude_id=row.id), row.source)
            for k in ("ml_score", "rule_score", "risk", "tier", "action", "threat", "reasons", "features"):
                setattr(row, k, getattr(fresh, k))
            row.explanation = row.explanation_source = None
            self._auto_block(db, row)
            db.commit()
            db.refresh(row)
            self._notify(row, old_tier)
            return row

    def _notify(self, row: Event, old_tier: str | None) -> None:
        """Tell the integrations about a new alert, or one that just escalated (MFA -> BLOCK)."""
        rank = {"MFA": 1, "BLOCK": 2}
        if self.on_alert and rank.get(row.tier, 0) > rank.get(old_tier, 0):
            try:
                self.on_alert(row.id)
            except Exception:  # an outside channel must never break scoring
                log.exception("Alert dispatch failed")

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
