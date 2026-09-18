"""Risk engine: combine the ML anomaly score with explainable security signals.

ML answers "how unusual is this session?"; the signals answer "why?".
The two are fused as independent evidence (noisy-OR):
    risk = 1 - (1 - ml) * (1 - rules)
so strong evidence from either side raises the risk, and agreement raises it most.
"""

TIERS = [
    (80, "BLOCK", "Block session and alert SOC"),
    (60, "MFA", "Challenge with MFA"),
    (30, "MONITOR", "Allow and monitor"),
    (0, "ALLOW", "Allow"),
]


def fuse(ml_risk: float, rule_score: float) -> int:
    return round(100 * (1 - (1 - ml_risk / 100) * (1 - rule_score / 100)))


def tier_for(risk: float) -> tuple[str, str]:
    for threshold, tier, action in TIERS:
        if risk >= threshold:
            return tier, action
    return "ALLOW", "Allow"


def _signals(f: dict) -> list[dict]:
    s = []

    def add(signal, points, detail):
        severity = "critical" if points >= 25 else "high" if points >= 15 else "medium"
        s.append({"signal": signal, "points": points, "severity": severity, "detail": detail})

    impossible = f["travel_speed_kmh"] > 900 and f["travel_km"] > 500
    if impossible:
        add("Impossible travel", 35,
            f"{f['prev_city']} to {f['city']} ({f['travel_km']:,} km) in {f['travel_minutes']} min "
            f"would need {f['travel_speed_kmh']:,} km/h")
    if f["new_country"]:
        add("New country", 25, f"First login ever from {f['country']} ({f['city']})")
    elif f["new_city"]:
        add("New city", 8, f"First login from {f['city']}; usually {f['home_city']}")
    if f["new_device"]:
        add("Unrecognised device", 15, f"{f['device']} has never been used; usual device is {f['primary_device']}")
    if f["automation_client"]:
        add("Automation client", 20, f"Session driven by '{f['device'].split(' / ')[-1]}', not a human browser")
    if f["hours_outside"] >= 2:
        add("Unusual login time", min(20, 10 + 3 * (f["hours_outside"] - 2)),
            f"Login at {f['time']}; normal window is {f['usual_hours']}")
    elif f["hours_outside"] == 1:
        add("Slightly unusual time", 5, f"Login at {f['time']}; normal window is {f['usual_hours']}")
    if f["unusual_weekend"]:
        add("Weekend activity", 8, f"Active on a {f['weekday']}, which this user rarely is")
    if f["failed_attempts"] >= 5:
        add("Brute-force pattern", 20, f"{f['failed_attempts']} failed login attempts before success")
    elif f["failed_attempts"] >= 3:
        add("Repeated failed logins", 8, f"{f['failed_attempts']} failed login attempts")

    ratio = max(f["files_ratio"], f["mb_ratio"])
    volume = f"{f['files']:,} files / {f['mb']:,.0f} MB downloaded (normally ~{f['avg_files']:.0f} files / {f['avg_mb']:.0f} MB)"
    if ratio >= 20:
        add("Mass data download", 35, f"{volume}: {ratio:.0f}x normal")
    elif ratio >= 8:
        add("Abnormal data download", 25, f"{volume}: {ratio:.0f}x normal")
    elif ratio >= 4:
        add("Elevated downloads", 12, f"{volume}: {ratio:.0f}x normal")

    if f["sensitive"] >= 5 and f["sensitive_ratio"] >= 4:
        add("Sensitive data access", 20,
            f"{f['sensitive']} sensitive resources accessed (normally ~{f['avg_sensitive']:.0f})")
    if f["api_ratio"] >= 20:
        add("Machine-speed API usage", 30,
            f"{f['api']:,} API requests vs ~{f['avg_api']:.0f} normally ({f['api_ratio']:.0f}x)")
    elif f["api_ratio"] >= 5:
        add("High API usage", 12, f"{f['api']:,} API requests vs ~{f['avg_api']:.0f} normally")
    return sorted(s, key=lambda x: -x["points"])


def likely_threat(f: dict, signals: list[dict]) -> str | None:
    names = {s["signal"] for s in signals}
    if not names:
        return None
    if "Impossible travel" in names:
        return "Account takeover (impossible travel)"
    if "Brute-force pattern" in names:
        return "Credential stuffing / brute force"
    if "Machine-speed API usage" in names or "Automation client" in names:
        return "Rogue automation / AI-agent API abuse"
    if names & {"Mass data download", "Abnormal data download"}:
        if not (f["new_country"] or f["new_device"]):
            return "Insider data exfiltration"
        return "Account takeover with data theft"
    if f["new_country"] or f["new_device"]:
        return "Possible account compromise"
    return "Behavioural anomaly"


def assess(facts: dict, ml_risk: float) -> dict:
    signals = _signals(facts)
    rule_score = min(100, sum(s["points"] for s in signals))
    risk = fuse(ml_risk, rule_score)
    tier, action = tier_for(risk)
    return {
        "ml_score": round(float(ml_risk), 1),
        "rule_score": rule_score,
        "risk": risk,
        "tier": tier,
        "action": action,
        "reasons": signals,
        "threat": likely_threat(facts, signals) if risk >= 30 else None,
    }
