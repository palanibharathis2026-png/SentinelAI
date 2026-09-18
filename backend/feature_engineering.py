"""Digital Behavioral Twin + feature extraction.

A twin summarises how one employee normally behaves. Every new session is
turned into a feature vector that measures how far it drifts from that twin.
"""
import math
from collections import Counter

import numpy as np

from simulator import TAMPERING_ACTIONS

FEATURE_NAMES = [
    "hours_outside_usual_window",
    "unusual_weekend_login",
    "new_device",
    "new_country",
    "new_city",
    "travel_speed_log",
    "failed_logins",
    "download_ratio_log",
    "data_volume_ratio_log",
    "api_ratio_log",
    "sensitive_ratio_log",
    "new_sensitive_systems",
    "unfamiliar_admin_actions",
]

AUTOMATION_CLIENTS = {"python-httpx", "python-requests", "curl", "Headless Chrome", "Go-http-client"}


def device_key(event: dict) -> str:
    return f"{event['os']} / {event['browser']}"


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def _hours_label(active: list[int]) -> str:
    if not active:
        return "unknown"
    if len(active) == 24:
        return "24x7"
    hours = sorted(active)
    # The usual window starts right after the largest gap on the 24h clock.
    gaps = [((hours[(i + 1) % len(hours)] - h) % 24, i) for i, h in enumerate(hours)]
    _, i = max(gaps)
    start, end = hours[(i + 1) % len(hours)], hours[i]
    return f"{start:02d}:00 - {(end + 1) % 24:02d}:00"


def build_twin(events: list[dict]) -> dict:
    """Summarise an employee's normal behaviour from their past sessions."""
    if not events:
        return {
            "sessions": 0, "active_hours": list(range(24)), "usual_hours": "unknown",
            "known_devices": [], "primary_device": "unknown", "known_cities": [],
            "known_countries": [], "home_city": "unknown", "weekend_rate": 0.0,
            "avg_files": 10.0, "avg_mb": 20.0, "avg_api": 100.0, "avg_sensitive": 1.0,
            "avg_failed": 0.0, "avg_session_minutes": 240.0,
            "familiar_resources": [], "familiar_actions": [],
        }
    hours = Counter(e["timestamp"].hour for e in events)
    devices = Counter(device_key(e) for e in events)
    cities = Counter(e["city"] for e in events)
    countries = Counter(e["country"] for e in events)
    active = sorted(hours)

    def avg(key):
        return round(float(np.mean([e[key] for e in events])), 2)

    return {
        "sessions": len(events),
        "active_hours": active,
        "usual_hours": _hours_label(active),
        "known_devices": [d for d, _ in devices.most_common()],
        "primary_device": devices.most_common(1)[0][0],
        "known_cities": [c for c, _ in cities.most_common()],
        "known_countries": [c for c, _ in countries.most_common()],
        "home_city": cities.most_common(1)[0][0],
        "weekend_rate": round(sum(e["timestamp"].weekday() >= 5 for e in events) / len(events), 3),
        "avg_files": avg("files_downloaded"),
        "avg_mb": avg("mb_downloaded"),
        "avg_api": avg("api_calls"),
        "avg_sensitive": avg("sensitive_access"),
        "avg_failed": avg("failed_attempts"),
        "avg_session_minutes": avg("session_minutes"),
        "familiar_resources": sorted({r for e in events for r in e.get("resources", [])}),
        "familiar_actions": sorted({a for e in events for a in e.get("actions", [])}),
    }


def _hours_outside(hour: int, active: list[int]) -> int:
    if not active or hour in active:
        return 0
    return min(min((hour - h) % 24, (h - hour) % 24) for h in active)


def _log_ratio(value: float, baseline: float) -> float:
    return math.log((value + 1.0) / (baseline + 1.0))


def compute_features(event: dict, twin: dict, prev: dict | None) -> tuple[np.ndarray, dict]:
    """Return (feature vector for the ML model, human-readable facts for the risk engine)."""
    ts = event["timestamp"]
    hours_outside = _hours_outside(ts.hour, twin["active_hours"])
    weekend = ts.weekday() >= 5
    unusual_weekend = weekend and twin["weekend_rate"] < 0.1
    dev = device_key(event)
    new_device = bool(twin["known_devices"]) and dev not in twin["known_devices"]
    new_country = bool(twin["known_countries"]) and event["country"] not in twin["known_countries"]
    new_city = bool(twin["known_cities"]) and event["city"] not in twin["known_cities"]

    travel_km, travel_minutes, travel_speed = 0.0, None, 0.0
    if prev is not None and prev["city"] != event["city"]:
        travel_km = haversine_km(prev["lat"], prev["lon"], event["lat"], event["lon"])
        travel_minutes = max(1.0, (ts - prev["timestamp"]).total_seconds() / 60)
        travel_speed = travel_km / (travel_minutes / 60)

    files_ratio = (event["files_downloaded"] + 1) / (twin["avg_files"] + 1)
    mb_ratio = (event["mb_downloaded"] + 1) / (twin["avg_mb"] + 1)
    api_ratio = (event["api_calls"] + 1) / (twin["avg_api"] + 1)
    sensitive_ratio = (event["sensitive_access"] + 1) / (twin["avg_sensitive"] + 1)

    resources, actions = event.get("resources", []), event.get("actions", [])
    new_resources = [r for r in resources if r not in twin["familiar_resources"]]
    new_actions = [a for a in actions if a not in twin["familiar_actions"]]
    tampering = [a for a in actions if a in TAMPERING_ACTIONS]

    vector = np.array([
        hours_outside,
        float(unusual_weekend),
        float(new_device),
        float(new_country),
        float(new_city),
        math.log1p(travel_speed),
        event["failed_attempts"],
        _log_ratio(event["files_downloaded"], twin["avg_files"]),
        _log_ratio(event["mb_downloaded"], twin["avg_mb"]),
        _log_ratio(event["api_calls"], twin["avg_api"]),
        _log_ratio(event["sensitive_access"], twin["avg_sensitive"]),
        len(new_resources),
        len(new_actions),
    ], dtype=float)

    facts = {
        "hour": ts.hour,
        "time": ts.strftime("%H:%M"),
        "weekday": ts.strftime("%A"),
        "usual_hours": twin["usual_hours"],
        "hours_outside": hours_outside,
        "unusual_weekend": unusual_weekend,
        "device": dev,
        "primary_device": twin["primary_device"],
        "new_device": new_device,
        "automation_client": event["browser"] in AUTOMATION_CLIENTS,
        "city": event["city"],
        "country": event["country"],
        "home_city": twin["home_city"],
        "new_city": new_city,
        "new_country": new_country,
        "prev_city": prev["city"] if prev else None,
        "travel_km": round(travel_km),
        "travel_minutes": round(travel_minutes) if travel_minutes else None,
        "travel_speed_kmh": round(travel_speed),
        "failed_attempts": event["failed_attempts"],
        "files": event["files_downloaded"],
        "avg_files": twin["avg_files"],
        "files_ratio": round(files_ratio, 1),
        "mb": event["mb_downloaded"],
        "avg_mb": twin["avg_mb"],
        "mb_ratio": round(mb_ratio, 1),
        "api": event["api_calls"],
        "avg_api": twin["avg_api"],
        "api_ratio": round(api_ratio, 1),
        "sensitive": event["sensitive_access"],
        "avg_sensitive": twin["avg_sensitive"],
        "sensitive_ratio": round(sensitive_ratio, 1),
        "resources": resources,
        "new_resources": new_resources,
        "actions": actions,
        "new_actions": new_actions,
        "tampering": tampering,
    }
    return vector, facts
