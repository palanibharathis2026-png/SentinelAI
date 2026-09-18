# 🛡️ SentinelAI: Behavioral Security for Detecting Compromised Users

**Code Cortex 3.0 · Security track (Cyber & Defense)**

Passwords, OTPs and session tokens get stolen. Once an attacker has them, they *are* the user as far as authentication is concerned. SentinelAI asks a different question: **does this session behave like the real person?**

Each employee gets a **Digital Behavioral Twin** learned from their history: when they log in, from where, on which device, how many files and API calls they make, and how often they touch sensitive data. Every new session is compared with that twin, scored **0-100** by an ML + rules hybrid, and handled automatically:

| Risk | Tier | Action |
|---|---|---|
| 0-29 | ALLOW | Allow |
| 30-59 | MONITOR | Allow and monitor |
| 60-79 | MFA | Challenge with MFA |
| 80-100 | BLOCK | Block session, auto-lock the account, alert the SOC |

An **AI Security Analyst** (Claude, with an offline fallback) explains each incident in plain English.

![SOC dashboard](docs/screenshots/dashboard.png)

---

## Architecture

```
User activity
     ↓
Login / API / file / device logs
     ↓
Feature extraction (session vs. Digital Twin, 11 features)
     ↓
ML anomaly detection (Isolation Forest + robust distance, from scratch in numpy)
     ↓
Risk engine (ML score ⊕ explainable security signals)
     ↓
Allow · Monitor · MFA · Block + Alert
     ↓
LLM security analyst
     ↓
SOC dashboard (React)
```

| Layer | Tech |
|---|---|
| Backend API | Python, FastAPI, SQLAlchemy |
| Database | PostgreSQL (Docker) / SQLite (local) |
| ML | Isolation Forest + RobustDistance, **implemented from scratch with numpy** |
| AI analyst | Claude via the Anthropic SDK, with a built-in template fallback |
| Frontend | React, Vite, Tailwind CSS, Recharts |
| Deployment | Docker Compose |

## How detection works

1. **Digital twin.** From each employee's past sessions: usual login hours, known devices, known cities and countries, and average files, data volume, API calls and sensitive-resource access.
2. **Features.** Each session becomes 11 numbers that measure drift from the twin, e.g. hours outside the usual window, new device or country, travel speed from the last trusted session, failed logins, and log-ratios of downloads, data volume, API calls and sensitive access.
3. **ML (unsupervised, trained only on normal behavior).**
   - *Isolation Forest* spots unusual **combinations** of features.
   - *Robust distance* (median/MAD) spots extreme **magnitudes**, which a forest cannot score beyond its most extreme training point.
   - ML risk = the higher of the two, calibrated so a typical session is 0 and the 95th-percentile normal session is 25.
4. **Signals.** Readable evidence with points: impossible travel, new country, unrecognized device, automation client, mass download, sensitive data access, machine-speed API usage, brute-force pattern and more.
5. **Fusion.** ML and signals are treated as independent evidence: `risk = 1 − (1 − ML)(1 − signals)`.
6. **Response.** The risk tier decides the action. A BLOCK verdict auto-locks the account.

**Last trusted session.** Travel speed is measured from the user's last *non-blocked* session, so an attacker's login never becomes the reference point for the real user.

## Results

Evaluated on the most recent 10 days of the dataset (183 sessions containing 18 planted attacks the model never trained on). An alert means risk ≥ 60.

| Detector | Recall | Precision | False alarm rate |
|---|---|---|---|
| ML only | 94.4% | 100% | 0% |
| Rules only | 83.3% | 100% | 0% |
| **SentinelAI hybrid** | **100%** | **100%** | **0%** |

All 6 attack types were caught 3/3: account takeover, insider exfiltration, credential stuffing, impossible travel, rogue AI agent / API abuse, and **stealth (low-and-slow) exfiltration**. The stealth attack deliberately stays under every rule threshold. The rules score it around 8-18, and only the ML model catches it, which is why the system is hybrid.

Robustness check across 8 differently seeded datasets: hybrid recall was 100% on every one, precision was at least 95%, and about 3% of normal sessions landed in MONITOR.

> ⚠️ **Honest note:** the data is synthetic. The hackathon's security dataset has no login/file/device logs, so SentinelAI ships a realistic simulator (15 employees, shift patterns, business trips, 6 attack types). Numbers on real enterprise logs would be lower. The pipeline accepts any CSV with the same columns, so it can be retrained on real data (e.g. the CERT Insider Threat dataset).

![Model accuracy](docs/screenshots/model.png)

---

## Quick start

### Easiest (Windows): double-click `start.bat`

Needs only Python 3.11+. On the first run it installs everything. If Node.js is missing it downloads a portable copy, so nothing extra needs installing. Then it starts the API and dashboard and opens http://localhost:5173. To stop, close the two *SentinelAI* windows.

### Option A: Docker (everything in one command)

Needs [Docker Desktop](https://www.docker.com/products/docker-desktop/).

```bash
cp .env.example .env          # optional: add ANTHROPIC_API_KEY for Claude explanations
docker compose up --build
```

- Dashboard: http://localhost:3000
- API docs (Swagger): http://localhost:8000/docs

### Option B: Run locally (no Docker)

Needs Python 3.11+ and Node.js 20+.

**Backend** (terminal 1):

```bash
cd backend
python -m venv .venv
# Windows:  .venv\Scripts\activate      macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Local runs use SQLite (`backend/sentinel.db`), created and seeded automatically on first start.

**Frontend** (terminal 2):

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173.

### Enable Claude explanations (optional)

Put `ANTHROPIC_API_KEY=...` in `.env` at the repo root. Without a key, or if the API is unreachable, the analyst uses a built-in template, so the demo never depends on the internet.

## Demo script (3-5 minutes)

1. **Dashboard.** Live traffic is on and normal sessions stream in green. *"Every dot is a login compared with that employee's digital twin."*
2. **Attack simulator → Account takeover** on *Pradish Kumar*. It appears as a red BLOCK and the account is auto-locked.
3. **Open the incident.** Show the risk gauge, the "why it was flagged" list and the **digital twin vs this session** table.
4. **Explain this session.** The AI analyst writes the incident summary.
5. **Stealth exfiltration.** *"Every signal is under the rule thresholds, so the rules score it about 13. The ML still flags it."* This is the reason for the hybrid.
6. **Model & Accuracy page.** ML only vs rules only vs hybrid, on data the model never saw.

![Incident view](docs/screenshots/incident.png)

## API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Status, AI analyst mode |
| GET | `/api/stats` | Dashboard KPIs |
| GET | `/api/events` | Sessions (filters: `limit`, `min_risk`, `user_id`, `tier`) |
| GET | `/api/alerts` | MFA/BLOCK incidents (`status=open\|resolved\|false_positive\|all`) |
| GET | `/api/events/{id}` | Incident detail + digital twin comparison |
| POST | `/api/events/{id}/explain` | AI analyst explanation (`?refresh=true` to regenerate) |
| PATCH | `/api/events/{id}/status` | Resolve / mark false positive |
| GET | `/api/users`, `/api/users/{id}` | Employees, twin and session history |
| POST | `/api/users/{id}/block`, `/unblock` | Manual account control |
| GET | `/api/timeline` | Risk over time |
| GET | `/api/scenarios` | Available attack simulations |
| POST | `/api/simulate` | Launch an attack `{scenario, user_id?}` |
| GET | `/api/model` | Evaluation metrics |
| GET/POST | `/api/live` | Toggle background traffic |
| POST | `/api/reset` | Reload the demo dataset |

Interactive docs: http://localhost:8000/docs

## Project structure

```
SentinelAI/
├── backend/
│   ├── main.py                 # FastAPI app and endpoints
│   ├── detection_service.py    # pipeline: seed, train, score, evaluate, simulate
│   ├── feature_engineering.py  # digital twin + 11 features
│   ├── ml_detector.py          # Isolation Forest + RobustDistance (numpy)
│   ├── risk_engine.py          # signals, fusion, risk tiers
│   ├── analyst.py              # Claude / template incident explanations
│   ├── simulator.py            # synthetic employees and 6 attack scenarios
│   ├── database.py, models.py  # SQLAlchemy
│   └── requirements.txt
├── frontend/src/
│   ├── pages/                  # Dashboard, Employees, EmployeeDetail, Incident, Model
│   ├── components/             # charts, gauge, alert feed, simulator, twin table
│   └── api.js
├── data/
│   ├── synthetic_security_events.csv
│   └── generate_dataset.py
├── docs/screenshots/
├── docker-compose.yml
└── .env.example
```

## Customising

- **Regenerate data:** `python data/generate_dataset.py --days 60 --seed 42`, then delete `backend/sentinel.db` (or click *Reset demo data*).
- **Use real logs:** replace `data/synthetic_security_events.csv` with a CSV that has the same columns (`scenario` can be empty).
- **Tune thresholds:** tiers and signal points are in `backend/risk_engine.py`; ML calibration is in `backend/ml_detector.py`.
- **Add employees or attacks:** `PROFILES` and `make_attack()` in `backend/simulator.py`.

## Future work

- Streaming ingestion from real identity providers (Azure AD / Okta sign-in logs, CloudTrail).
- Rolling twin updates with analyst feedback (false-positive labels fed back into training).
- Session-token fingerprinting to catch cookie theft.
- Detection of autonomous AI agents abusing internal APIs, using request-timing signatures.

## Team INNOVEX (Guild code CC-3048)

- **Palani Bharathi S** (26BCE2603), team leader
- _Add teammates' names and roles here_
