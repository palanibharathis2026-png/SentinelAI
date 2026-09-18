"""Convert the CMU CERT Insider Threat Test Dataset (r4.2) into SentinelAI sessions.

Download from Carnegie Mellon's KiltHub ("Insider Threat Test Dataset"): r4.2.tar.bz2 and answers.tar.bz2.
Extract only what is needed (keep it outside OneDrive, e.g. C:\\cert):
    tar -xjf answers.tar.bz2
    tar -xjf r4.2.tar.bz2 r4.2/logon.csv r4.2/device.csv r4.2/file.csv r4.2/LDAP
    (optional, 1.3 GB)  tar -xjf r4.2.tar.bz2 r4.2/email.csv

Then (from the backend folder):
    python cert_to_sentinel.py --cert C:\\cert
    python evaluate.py --data ../data/cert_sessions.csv --name "CERT r4.2"
    python train_model.py --data ../data/cert_sessions.csv      # optional: make it the live model

One SentinelAI session = one employee's working day (first logon to last logoff), the unit used
in most CERT research. Mapping:
    device (os)          -> the PC used, so logging into someone else's PC is a "new device"
    sensitive_access     -> USB drive connections that day
    files_downloaded     -> files copied (file.csv)
    mb_downloaded        -> MB of email attachments sent outside the company (email.csv, optional)
    api_calls            -> emails sent that day (email.csv, optional)
    resources / actions  -> "USB drive", "Other employee's PC" / "usb_file_copy", "external_attachment"
    scenario             -> "cert_insider" on days listed in the answers for an insider, else normal
CERT has no locations, failed logins or API logs, so those features stay at their normal values:
this dataset tests the insider-theft part of the model (after hours, new PCs, USB, data leaving).
Only Python's standard library is used, and files are streamed line by line.

Licence: the CERT data (Copyright 2011 ExactData, LLC) may not be redistributed, and neither may data
converted from it. data/cert_sessions.csv is git-ignored; only accuracy results are published.
"""
import argparse
import csv
import random
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

OFFICE = ("Pittsburgh", "United States", 40.44, -79.99)
COMPANY_DOMAIN = "dtaa.com"  # the fictional company in CERT r4.x
FORMATS = ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y")
OUT_FIELDS = ["user_id", "timestamp", "city", "country", "lat", "lon", "ip", "os", "browser",
              "failed_attempts", "files_downloaded", "mb_downloaded", "api_calls",
              "sensitive_access", "session_minutes", "resources", "actions", "scenario"]


def parse_time(text: str) -> datetime | None:
    text = text.strip()
    for fmt in FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            pass
    return None


def find(root: Path, name: str) -> Path | None:
    hits = sorted(root.rglob(name))
    return hits[0] if hits else None


def rows(path: Path):
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        header = [h.strip().lower() for h in next(reader)]
        for row in reader:
            if len(row) >= len(header):
                yield dict(zip(header, row))


def load_answers(root: Path, dataset: str) -> tuple[set[str], set[tuple[str, str]]]:
    """(insider user ids, {(user, 'YYYY-MM-DD')} days with malicious activity)."""
    insiders_csv = find(root, "insiders.csv")
    if insiders_csv is None:
        sys.exit(f"answers/insiders.csv not found under {root}. Extract answers.tar.bz2 there.")
    users, days, ranges = set(), set(), []
    for r in rows(insiders_csv):
        if str(r.get("dataset", "")).strip() not in (dataset, dataset.lstrip("r")):
            continue
        user = r["user"].strip()
        users.add(user)
        ranges.append((user, parse_time(r.get("start", "")), parse_time(r.get("end", ""))))
    # Exact malicious days from the per-insider detail files, e.g. answers/r4.2-1/r4.2-1-AAM0658.csv
    # Each line: type,{id},MM/DD/YYYY HH:MM:SS,USER,PC,...
    for detail in root.rglob(f"r{dataset.lstrip('r')}-*.csv"):
        for line in open(detail, encoding="utf-8", errors="replace"):
            parts = line.split(",", 5)
            ts = parse_time(parts[2]) if len(parts) > 4 else None
            if ts and parts[3].strip() in users:
                days.add((parts[3].strip(), ts.date().isoformat()))
    if not days:  # no detail files: fall back to the start-end window
        for user, start, end in ranges:
            if start and end:
                d = start.date()
                while d <= end.date():
                    days.add((user, d.isoformat()))
                    d += timedelta(days=1)
    return users, days


def write_directory(root: Path, users: set[str], path: Path) -> None:
    """Name, role and department per kept user, from the LDAP snapshots (the latest one each user appears in)."""
    info = {}
    for month in sorted(root.rglob("LDAP/*.csv")):
        for r in rows(month):
            uid = r.get("user_id", "").strip()
            if uid in users:
                dept = (r.get("department") or "").split(" - ", 1)[-1]
                info[uid] = {"user_id": uid, "name": r.get("employee_name", uid).strip(),
                             "role": r.get("role", "").strip(), "department": dept.strip()}
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["user_id", "name", "role", "department"])
        w.writeheader()
        w.writerows(info.get(u, {"user_id": u, "name": u, "role": "", "department": ""}) for u in sorted(users))
    print(f"Wrote {len(users)} employees ({len(info)} found in LDAP) to {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cert", type=Path, required=True, help="folder containing r4.2/ and answers/")
    parser.add_argument("--dataset", default="4.2")
    parser.add_argument("--normal-users", type=int, default=130, help="non-insider employees to include (plus all insiders)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parent.parent / "data" / "cert_sessions.csv")
    args = parser.parse_args()

    root = args.cert
    logon_csv = find(root, "logon.csv")
    if logon_csv is None:
        sys.exit(f"logon.csv not found under {root}. Extract r4.2/logon.csv there.")
    insiders, bad_days = load_answers(root, args.dataset)
    print(f"Insiders: {len(insiders)}, labelled malicious days: {len(bad_days)}")

    all_users = set()
    for r in rows(logon_csv):
        all_users.add(r["user"])
    normal = sorted(all_users - insiders)
    random.Random(args.seed).shuffle(normal)
    keep = (insiders & all_users) | set(normal[: args.normal_users])
    print(f"Users in logon.csv: {len(all_users)}; keeping {len(keep)} ({len(insiders & all_users)} insiders)")

    # day[(user, date)] -> activity summary
    day = defaultdict(lambda: {"first": None, "last": None, "pcs": set(), "usb": 0, "files": 0,
                               "emails": 0, "ext_mb": 0.0, "ext_attach": 0})
    primary_pc = defaultdict(lambda: defaultdict(int))

    def touch(r):
        ts = parse_time(r["date"])
        if ts is None or r["user"] not in keep:
            return None, None
        d = day[(r["user"], ts.date().isoformat())]
        d["first"] = ts if d["first"] is None or ts < d["first"] else d["first"]
        d["last"] = ts if d["last"] is None or ts > d["last"] else d["last"]
        if r.get("pc"):
            d["pcs"].add(r["pc"])
        return ts, d

    n = 0
    for r in rows(logon_csv):
        ts, d = touch(r)
        if d is not None and r.get("activity", "").strip().lower() == "logon":
            primary_pc[r["user"]][r["pc"]] += 1
        n += 1
    print(f"logon.csv: {n} rows")

    for name, handler in (("device.csv", "usb"), ("file.csv", "files")):
        path = find(root, name)
        if path is None:
            print(f"{name} not found, skipped")
            continue
        n = 0
        for r in rows(path):
            ts, d = touch(r)
            if d is not None and (handler == "files" or r.get("activity", "").strip().lower() == "connect"):
                d[handler] += 1
            n += 1
        print(f"{name}: {n} rows")

    email_csv = find(root, "email.csv")
    if email_csv is not None:
        n = 0
        for r in rows(email_csv):
            ts, d = touch(r)
            n += 1
            if d is None:
                continue
            d["emails"] += 1
            recipients = " ".join(r.get(k, "") for k in ("to", "cc", "bcc"))
            external = any(a and not a.strip().endswith(COMPANY_DOMAIN) for a in re.split(r"[;, ]+", recipients))
            attachments = int(float(r.get("attachments") or 0)) if (r.get("attachments") or "").strip().replace(".", "").isdigit() else 0
            if external and attachments:
                d["ext_attach"] += attachments
                d["ext_mb"] += float(r.get("size") or 0) / 1_000_000
        print(f"email.csv: {n} rows")
    else:
        print("email.csv not found, skipped (optional)")

    main_pc = {u: max(pcs, key=pcs.get) for u, pcs in primary_pc.items()}
    city, country, lat, lon = OFFICE
    out, attacks = [], 0
    for (user, date), d in day.items():
        if d["first"] is None:
            continue
        pc = main_pc.get(user) or (sorted(d["pcs"])[0] if d["pcs"] else "unknown-PC")
        used = sorted(d["pcs"])
        other_pcs = [p for p in used if p != main_pc.get(user)]
        label = "cert_insider" if (user, date) in bad_days else ""
        attacks += bool(label)
        resources = (["USB drive"] if d["usb"] else []) + (["Other employee's PC"] if other_pcs else [])
        actions = (["usb_file_copy"] if d["files"] else []) + (["external_attachment"] if d["ext_attach"] else [])
        pc_num = sum(ord(c) for c in (other_pcs[0] if other_pcs else pc))
        out.append({
            "user_id": user, "timestamp": d["first"].isoformat(), "city": city, "country": country,
            "lat": lat, "lon": lon, "ip": f"10.{pc_num % 250}.{len(pc) % 250}.{pc_num % 199 + 1}",
            "os": other_pcs[0] if other_pcs else pc, "browser": "Workstation",
            "failed_attempts": 0, "files_downloaded": d["files"], "mb_downloaded": round(d["ext_mb"], 2),
            "api_calls": d["emails"], "sensitive_access": d["usb"],
            "session_minutes": max(1, min(24 * 60, int((d["last"] - d["first"]).total_seconds() // 60))),
            "resources": "|".join(resources), "actions": "|".join(actions), "scenario": label,
        })
    write_directory(root, keep, args.out.parent / "cert_employees.csv")
    out.sort(key=lambda e: e["timestamp"])
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=OUT_FIELDS)
        w.writeheader()
        w.writerows(out)
    print(f"Wrote {len(out)} user-day sessions ({attacks} insider days) to {args.out}")


if __name__ == "__main__":
    main()
