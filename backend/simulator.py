"""Synthetic company activity for SentinelAI.

Generates realistic employee sessions (login + file/API activity) and plants
six kinds of attacks so the detector can be trained and evaluated.
Swap in real logs by providing a CSV with the same columns (see CSV_FIELDS).
"""
import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

IST = timezone(timedelta(hours=5, minutes=30))


def now_ist() -> datetime:
    return datetime.now(IST).replace(tzinfo=None, microsecond=0)


INDIAN_CITIES = {
    "Chennai": (13.08, 80.27),
    "Bengaluru": (12.97, 77.59),
    "Hyderabad": (17.39, 78.49),
    "Mumbai": (19.08, 72.88),
    "Pune": (18.52, 73.86),
    "Delhi": (28.61, 77.21),
    "Kolkata": (22.57, 88.36),
    "Vellore": (12.92, 79.13),
}

# city -> (country, lat, lon)
FOREIGN_CITIES = {
    "Frankfurt": ("Germany", 50.11, 8.68),
    "Moscow": ("Russia", 55.76, 37.62),
    "Lagos": ("Nigeria", 6.52, 3.38),
    "Sao Paulo": ("Brazil", -23.55, -46.63),
    "Amsterdam": ("Netherlands", 52.37, 4.90),
    "Ashburn": ("United States", 39.04, -77.49),
    "Singapore": ("Singapore", 1.35, 103.82),
}

# Every known city -> (country, lat, lon)
LOCATIONS = {c: ("India", lat, lon) for c, (lat, lon) in INDIAN_CITIES.items()} | FOREIGN_CITIES

# hours=(start, end): active from start up to end, wrapping past midnight when start > end.
PROFILES = {p["id"]: p for p in [
    {"id": "EMP001", "name": "Pradish Kumar", "department": "Engineering", "role": "Backend Developer", "home_city": "Chennai", "hours": (9, 19), "device": ("Windows 11", "Chrome"), "alt_device": ("Android", "Chrome Mobile"), "files": 14, "api": 220, "mb_per_file": 1.8, "sensitive": 0.03, "weekend": 0.10},
    {"id": "EMP002", "name": "Ananya Iyer", "department": "Finance", "role": "Financial Analyst", "home_city": "Chennai", "hours": (9, 18), "device": ("Windows 11", "Edge"), "alt_device": ("iOS", "Safari"), "files": 22, "api": 40, "mb_per_file": 0.9, "sensitive": 0.35, "weekend": 0.02},
    {"id": "EMP003", "name": "Rahul Menon", "department": "HR", "role": "HR Manager", "home_city": "Bengaluru", "hours": (10, 19), "device": ("macOS", "Safari"), "alt_device": ("iOS", "Safari"), "files": 10, "api": 25, "mb_per_file": 0.6, "sensitive": 0.40, "weekend": 0.02},
    {"id": "EMP004", "name": "Karthik Raj", "department": "Engineering", "role": "DevOps Engineer", "home_city": "Bengaluru", "hours": (11, 21), "device": ("Ubuntu", "Firefox"), "alt_device": ("Android", "Chrome Mobile"), "files": 30, "api": 900, "mb_per_file": 4.0, "sensitive": 0.08, "weekend": 0.25},
    {"id": "EMP005", "name": "Divya Nair", "department": "Sales", "role": "Account Executive", "home_city": "Mumbai", "hours": (9, 18), "device": ("Windows 11", "Chrome"), "alt_device": ("Android", "Chrome Mobile"), "files": 8, "api": 15, "mb_per_file": 2.5, "sensitive": 0.05, "weekend": 0.05},
    {"id": "EMP006", "name": "Arjun Reddy", "department": "Engineering", "role": "Data Scientist", "home_city": "Hyderabad", "hours": (10, 20), "device": ("macOS", "Chrome"), "alt_device": ("iOS", "Safari"), "files": 40, "api": 350, "mb_per_file": 12.0, "sensitive": 0.10, "weekend": 0.15},
    {"id": "EMP007", "name": "Meera Krishnan", "department": "Legal", "role": "Legal Counsel", "home_city": "Delhi", "hours": (9, 18), "device": ("Windows 11", "Edge"), "alt_device": ("iOS", "Safari"), "files": 12, "api": 10, "mb_per_file": 1.2, "sensitive": 0.50, "weekend": 0.03},
    {"id": "EMP008", "name": "Vikram Singh", "department": "Finance", "role": "Payroll Specialist", "home_city": "Pune", "hours": (9, 18), "device": ("Windows 11", "Chrome"), "alt_device": ("Android", "Chrome Mobile"), "files": 18, "api": 30, "mb_per_file": 0.8, "sensitive": 0.45, "weekend": 0.02},
    {"id": "EMP009", "name": "Sneha Patel", "department": "Marketing", "role": "Content Lead", "home_city": "Mumbai", "hours": (10, 19), "device": ("macOS", "Safari"), "alt_device": ("iOS", "Safari"), "files": 25, "api": 20, "mb_per_file": 6.0, "sensitive": 0.02, "weekend": 0.10},
    {"id": "EMP010", "name": "Aditya Rao", "department": "Engineering", "role": "Frontend Developer", "home_city": "Chennai", "hours": (10, 20), "device": ("macOS", "Chrome"), "alt_device": ("Android", "Chrome Mobile"), "files": 12, "api": 280, "mb_per_file": 2.0, "sensitive": 0.02, "weekend": 0.10},
    {"id": "EMP011", "name": "Lakshmi Sundar", "department": "Executive", "role": "Chief Financial Officer", "home_city": "Chennai", "hours": (8, 20), "device": ("macOS", "Safari"), "alt_device": ("iOS", "Safari"), "files": 15, "api": 12, "mb_per_file": 1.5, "sensitive": 0.60, "weekend": 0.20},
    {"id": "EMP012", "name": "Farhan Ali", "department": "IT", "role": "IT Administrator", "home_city": "Hyderabad", "hours": (8, 18), "device": ("Windows 11", "Edge"), "alt_device": ("Android", "Chrome Mobile"), "files": 20, "api": 450, "mb_per_file": 3.0, "sensitive": 0.15, "weekend": 0.10},
    {"id": "EMP013", "name": "Nisha Thomas", "department": "Support", "role": "Global Support Engineer (night shift)", "home_city": "Kolkata", "hours": (21, 6), "device": ("Windows 11", "Chrome"), "alt_device": ("Android", "Chrome Mobile"), "files": 9, "api": 120, "mb_per_file": 1.0, "sensitive": 0.05, "weekend": 0.50},
    {"id": "EMP014", "name": "Rohan Gupta", "department": "IT", "role": "SRE (24x7 on-call)", "home_city": "Bengaluru", "hours": (0, 24), "device": ("Ubuntu", "Firefox"), "alt_device": ("Android", "Chrome Mobile"), "files": 16, "api": 600, "mb_per_file": 2.5, "sensitive": 0.10, "weekend": 0.60},
    {"id": "EMP015", "name": "Priya Das", "department": "Operations", "role": "Operations Analyst", "home_city": "Vellore", "hours": (9, 18), "device": ("Windows 11", "Chrome"), "alt_device": ("Android", "Chrome Mobile"), "files": 14, "api": 35, "mb_per_file": 1.0, "sensitive": 0.10, "weekend": 0.03},
]}

SCENARIOS = {
    "account_takeover": {
        "label": "Account takeover",
        "description": "Stolen credentials used from abroad at night on an unknown device, followed by a mass download of sensitive files.",
    },
    "insider_exfiltration": {
        "label": "Insider data exfiltration",
        "description": "A legitimate employee on their usual device suddenly downloads huge volumes of sensitive data.",
    },
    "credential_stuffing": {
        "label": "Credential stuffing",
        "description": "Dozens of failed logins from a datacenter IP, then a successful login by an automated client.",
    },
    "impossible_travel": {
        "label": "Impossible travel",
        "description": "A normal login from the office, then 30 minutes later a login from another continent.",
    },
    "rogue_ai_agent": {
        "label": "Rogue AI agent / API abuse",
        "description": "An autonomous script using a stolen session token hammers internal APIs far beyond any human rate.",
    },
    "stealth_exfiltration": {
        "label": "Stealth (low-and-slow) exfiltration",
        "description": "A careful attacker keeps every signal just under the rule thresholds. Only the ML model sees that everything is slightly off at once.",
    },
}

# Named sensitive systems each role normally works with.
HIGH_VALUE = ["Customer PII DB", "Payroll DB", "Finance ledger", "HR records", "Source code repo", "Board reports"]
ROLE_RESOURCES = {
    "EMP001": ["Source code repo", "CI/CD pipeline"],
    "EMP002": ["Finance ledger", "Board reports"],
    "EMP003": ["HR records", "Payroll DB"],
    "EMP004": ["CI/CD pipeline", "Production servers", "Source code repo", "Admin console"],
    "EMP005": ["Sales CRM", "Customer PII DB"],
    "EMP006": ["Customer PII DB", "Source code repo"],
    "EMP007": ["Legal contracts", "HR records"],
    "EMP008": ["Payroll DB", "Finance ledger"],
    "EMP009": ["Marketing assets", "Sales CRM"],
    "EMP010": ["Source code repo", "Marketing assets"],
    "EMP011": ["Finance ledger", "Board reports", "Payroll DB"],
    "EMP012": ["Admin console", "Production servers"],
    "EMP013": ["Customer PII DB", "Sales CRM"],
    "EMP014": ["Production servers", "Admin console", "CI/CD pipeline"],
    "EMP015": ["Finance ledger", "Sales CRM"],
}
# Privileged actions each role legitimately performs.
ROLE_ACTIONS = {
    "EMP003": ["grant_access"],
    "EMP004": ["deploy_release", "restart_service", "create_api_token"],
    "EMP008": ["run_payroll"],
    "EMP011": ["approve_payment"],
    "EMP012": ["reset_user_password", "grant_access"],
    "EMP014": ["restart_service", "deploy_release"],
}
# Decoy files planted on the shared drive. No real employee has a reason to open them,
# so touching one is a near-certain sign of snooping (deception technology).
HONEYTOKENS = ["CEO_Salaries_2026.xlsx", "Merger_Plan_CONFIDENTIAL.pdf", "Admin_Passwords_backup.txt"]
# Attackers switch these off to stay hidden or keep access.
TAMPERING_ACTIONS = {"disable_audit_logs", "disable_mfa", "delete_backups"}

for _pid, _p in PROFILES.items():
    _p["resources"] = ROLE_RESOURCES.get(_pid, [])
    _p["actions"] = ROLE_ACTIONS.get(_pid, [])

CSV_FIELDS = [
    "user_id", "timestamp", "city", "country", "lat", "lon", "ip", "os", "browser",
    "failed_attempts", "files_downloaded", "mb_downloaded", "api_calls",
    "sensitive_access", "session_minutes", "resources", "actions", "scenario",
]
LIST_FIELDS = ("resources", "actions")


def work_hours(profile: dict) -> list[int]:
    start, end = profile["hours"]
    if end - start >= 24:
        return list(range(24))
    if start < end:
        return list(range(start, end))
    return list(range(start, 24)) + list(range(0, end))


def _indian_ip(rng: random.Random) -> str:
    return f"{rng.choice([49, 106, 117, 122, 157])}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _foreign_ip(rng: random.Random) -> str:
    return f"{rng.choice([45, 91, 185, 193, 194])}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _event(profile, ts, city, country, lat, lon, ip, device, failed, files, mb, api, sensitive, minutes,
           scenario=None, resources=(), actions=()) -> dict:
    return {
        "user_id": profile["id"], "timestamp": ts, "city": city, "country": country,
        "lat": lat, "lon": lon, "ip": ip, "os": device[0], "browser": device[1],
        "failed_attempts": int(failed), "files_downloaded": int(max(0, round(files))),
        "mb_downloaded": round(max(0.0, mb), 1), "api_calls": int(max(0, round(api))),
        "sensitive_access": int(max(0, round(sensitive))), "session_minutes": int(max(1, round(minutes))),
        "resources": sorted(set(resources)), "actions": sorted(set(actions)),
        "scenario": scenario,
    }


def _usual_resources(profile: dict, rng: random.Random) -> list[str]:
    own = profile["resources"]
    return rng.sample(own, min(len(own), rng.choice([0, 1, 1, 2])))


def _new_resources(profile: dict, rng: random.Random, n: int) -> list[str]:
    """High-value systems this employee has never touched."""
    unfamiliar = [r for r in HIGH_VALUE if r not in profile["resources"]]
    return rng.sample(unfamiliar, min(n, len(unfamiliar)))


def normal_session(profile: dict, ts: datetime, rng: random.Random, city: str | None = None) -> dict:
    """One ordinary working session that matches the employee's habits (at home unless `city` is given)."""
    city = city or profile["home_city"]
    lat, lon = INDIAN_CITIES[city]
    device = profile["alt_device"] if rng.random() < 0.15 else profile["device"]
    failed = rng.choices([0, 1, 2], weights=[90, 8, 2])[0]
    files = max(0, round(rng.gauss(profile["files"], profile["files"] * 0.35)))
    mb = files * profile["mb_per_file"] * rng.uniform(0.6, 1.4)
    api = rng.gauss(profile["api"], profile["api"] * 0.25)
    sensitive = sum(1 for _ in range(files) if rng.random() < profile["sensitive"])
    minutes = rng.gauss(240, 90)
    actions = [rng.choice(profile["actions"])] if profile["actions"] and rng.random() < 0.35 else []
    return _event(profile, ts, city, "India", lat, lon, _indian_ip(rng), device,
                  failed, files, mb, api, sensitive, minutes,
                  resources=_usual_resources(profile, rng), actions=actions)


def _foreign(rng: random.Random, choices: list[str]):
    city = rng.choice(choices)
    country, lat, lon = FOREIGN_CITIES[city]
    return city, country, lat, lon


def make_attack(profile: dict, scenario: str, ts: datetime, rng: random.Random) -> list[dict]:
    """Return the event(s) for one attack. impossible_travel returns a normal login first."""
    p = profile
    if scenario == "account_takeover":
        city, country, lat, lon = _foreign(rng, ["Frankfurt", "Moscow", "Lagos", "Sao Paulo"])
        files = p["files"] * rng.uniform(25, 70)
        actions = ["bulk_export"] + (["disable_audit_logs"] if rng.random() < 0.5 else [])
        return [_event(p, ts, city, country, lat, lon, _foreign_ip(rng), ("Linux", "Firefox"),
                       rng.randint(0, 1), files, files * p["mb_per_file"] * 1.2,
                       p["api"] * rng.uniform(3, 8), files * rng.uniform(0.5, 0.8),
                       rng.uniform(25, 60), scenario,
                       resources=p["resources"] + _new_resources(p, rng, 2), actions=actions)]
    if scenario == "insider_exfiltration":
        lat, lon = INDIAN_CITIES[p["home_city"]]
        files = p["files"] * rng.uniform(15, 40)
        return [_event(p, ts, p["home_city"], "India", lat, lon, _indian_ip(rng), p["device"],
                       0, files, files * p["mb_per_file"] * rng.uniform(2.5, 4.0),
                       p["api"] * rng.uniform(0.8, 1.5), files * rng.uniform(0.6, 0.85),
                       rng.uniform(60, 150), scenario,
                       resources=p["resources"] + _new_resources(p, rng, 1), actions=["bulk_export"])]
    if scenario == "credential_stuffing":
        city, country, lat, lon = _foreign(rng, ["Amsterdam", "Ashburn", "Singapore"])
        files = p["files"] * rng.uniform(2, 6)
        return [_event(p, ts, city, country, lat, lon, _foreign_ip(rng), ("Linux", "Headless Chrome"),
                       rng.randint(8, 30), files, files * p["mb_per_file"],
                       p["api"] * rng.uniform(1.5, 3), files * rng.uniform(0.2, 0.5),
                       rng.uniform(5, 20), scenario, resources=p["resources"][:1])]
    if scenario == "impossible_travel":
        before = normal_session(p, ts - timedelta(minutes=rng.randint(20, 45)), rng)
        lat0, lon0 = INDIAN_CITIES[p["home_city"]]
        before.update(city=p["home_city"], country="India", lat=lat0, lon=lon0,
                      os=p["device"][0], browser=p["device"][1])
        city, country, lat, lon = _foreign(rng, ["Frankfurt", "Sao Paulo", "Ashburn", "Moscow"])
        files = p["files"] * rng.uniform(3, 8)
        after = _event(p, ts, city, country, lat, lon, _foreign_ip(rng), ("Windows 10", "Firefox"),
                       rng.randint(0, 2), files, files * p["mb_per_file"],
                       p["api"] * rng.uniform(1, 2), files * rng.uniform(0.3, 0.6),
                       rng.uniform(20, 50), scenario,
                       resources=p["resources"] + _new_resources(p, rng, 1), actions=["disable_mfa"])
        return [before, after]
    if scenario == "rogue_ai_agent":
        city, country, lat, lon = _foreign(rng, ["Ashburn", "Singapore", "Frankfurt"])
        files = p["files"] * rng.uniform(5, 15)
        return [_event(p, ts, city, country, lat, lon, _foreign_ip(rng), ("Linux", "python-httpx"),
                       0, files, files * p["mb_per_file"],
                       max(p["api"], 50) * rng.uniform(40, 120), files * rng.uniform(0.3, 0.6),
                       rng.uniform(5, 15), scenario,
                       resources=p["resources"] + _new_resources(p, rng, 1),
                       actions=["create_api_token", "bulk_export"])]
    if scenario == "stealth_exfiltration":
        # Each signal stays below its rule threshold (downloads < 4x, API < 5x, sensitive < 4x, 2 failed logins).
        city = rng.choice([c for c in INDIAN_CITIES if c != p["home_city"]])
        lat, lon = INDIAN_CITIES[city]
        files = p["files"] * rng.uniform(3.0, 3.6)
        return [_event(p, ts, city, "India", lat, lon, _indian_ip(rng), p["alt_device"],
                       2, files, files * p["mb_per_file"] * 1.1,
                       p["api"] * rng.uniform(3.5, 4.5),
                       max(1.0, p["files"] * p["sensitive"]) * rng.uniform(2.5, 3.2),
                       rng.uniform(40, 90), scenario, resources=_usual_resources(p, rng))]
    raise ValueError(f"Unknown scenario: {scenario}")


def _attack_time(scenario: str, profile: dict, day: datetime, rng: random.Random) -> datetime:
    if scenario in ("account_takeover", "credential_stuffing"):
        hour = rng.randint(1, 4)
    elif scenario == "insider_exfiltration":
        hour = rng.randint(21, 23)
    elif scenario == "stealth_exfiltration":
        hour = profile["hours"][1] % 24  # the hour right after their shift ends
    else:
        hour = rng.randint(10, 17)
    return day.replace(hour=hour, minute=rng.randint(0, 59), second=0)


def generate_history(days: int = 45, attack_days: int = 10, attacks_per_scenario: int = 3,
                     seed: int = 7, end: datetime | None = None) -> list[dict]:
    """Normal activity for every employee for `days` days, with attacks planted in the last `attack_days`."""
    rng = random.Random(seed)
    end = end or now_ist()
    first_day = (end - timedelta(days=days)).replace(hour=0, minute=0, second=0)
    events = []
    for d in range(days + 1):
        day = first_day + timedelta(days=d)
        weekend = day.weekday() >= 5
        for profile in PROFILES.values():
            if weekend and rng.random() > profile["weekend"]:
                continue
            # Occasional whole-day business trip inside India.
            city = profile["home_city"]
            if rng.random() < 0.06:
                city = rng.choice([c for c in INDIAN_CITIES if c != profile["home_city"]])
            hours = work_hours(profile)
            for _ in range(rng.choices([1, 2], weights=[70, 30])[0]):
                ts = day.replace(hour=rng.choice(hours), minute=rng.randint(0, 59))
                if ts <= end:
                    events.append(normal_session(profile, ts, rng, city))

    # Day-shift employees only, so "odd hours" means something for every target.
    targets = [p for p in PROFILES.values() if p["hours"][0] < p["hours"][1] < 24]
    for scenario in SCENARIOS:
        for _ in range(attacks_per_scenario):
            day = first_day + timedelta(days=rng.randint(days - attack_days + 1, days - 1))
            profile = rng.choice(targets)
            events.extend(make_attack(profile, scenario, _attack_time(scenario, profile, day, rng), rng))

    events.sort(key=lambda e: e["timestamp"])
    return events


def save_csv(events: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for e in events:
            writer.writerow({**{k: e[k] for k in CSV_FIELDS},
                             **{k: "|".join(e[k]) for k in LIST_FIELDS},
                             "timestamp": e["timestamp"].isoformat(), "scenario": e["scenario"] or ""})


def load_csv(path: Path) -> list[dict]:
    ints = {"failed_attempts", "files_downloaded", "api_calls", "sensitive_access", "session_minutes"}
    floats = {"lat", "lon", "mb_downloaded"}
    events = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            e = dict(row)
            e["timestamp"] = datetime.fromisoformat(row["timestamp"])
            for k in ints:
                e[k] = int(float(row[k]))
            for k in floats:
                e[k] = float(row[k])
            for k in LIST_FIELDS:  # older CSVs may not have these columns
                e[k] = [x for x in (row.get(k) or "").split("|") if x]
            e["scenario"] = row.get("scenario") or None
            events.append(e)
    events.sort(key=lambda e: e["timestamp"])
    return events
