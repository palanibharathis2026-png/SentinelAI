"""Which data SentinelAI runs on.

SENTINEL_MODE=demo (default)  the synthetic demo company: 15 employees, staff portal, live traffic,
                              attack simulator. This is what GitHub and the judges run.
SENTINEL_MODE=cert            the real CMU CERT r4.2 insider-threat data (200 employees, 70 insiders):
                              the model is trained on it and the dashboard shows those people.
                              Needs data/cert_sessions.csv from cert_to_sentinel.py. Its licence forbids
                              publishing the data or anything derived from it, so this mode uses its own
                              database (sentinel_cert.db) and model folder (model/cert/), both git-ignored.
"""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODE = os.getenv("SENTINEL_MODE", "demo").strip().lower()
CERT = MODE == "cert"
CERT_SESSIONS = ROOT / "data" / "cert_sessions.csv"
CERT_EMPLOYEES = ROOT / "data" / "cert_employees.csv"
PUBLISHED_MODEL_DIR = ROOT / "model"

if CERT and not CERT_SESSIONS.exists():
    raise SystemExit(f"SENTINEL_MODE=cert needs {CERT_SESSIONS}. Run: python backend/cert_to_sentinel.py --cert C:\\cert")

DEMO_ONLY = "Not available on real CERT data: this feature uses the demo company. Set SENTINEL_MODE=demo in .env."
