"""Regenerate the synthetic security dataset.

Usage (from the repo root):
    python data/generate_dataset.py                 # 45 days, seed 7
    python data/generate_dataset.py --days 60 --seed 42

The backend loads data/synthetic_security_events.csv on first start
(delete backend/sentinel.db or call POST /api/reset to reload it).
"""
import argparse
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "backend"))

import simulator  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--days", type=int, default=45)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--out", type=Path, default=HERE / "synthetic_security_events.csv")
    args = parser.parse_args()

    events = simulator.generate_history(days=args.days, seed=args.seed)
    simulator.save_csv(events, args.out)
    attacks = Counter(e["scenario"] for e in events if e["scenario"])
    print(f"Wrote {len(events)} sessions for {len({e['user_id'] for e in events})} employees to {args.out}")
    print("Planted attacks:", dict(attacks))


if __name__ == "__main__":
    main()
