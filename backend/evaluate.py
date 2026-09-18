"""Evaluate SentinelAI more honestly than a single train/test split.

Usage (from the backend folder):
    python evaluate.py                          # cross-validation over 8 independently generated datasets
    python evaluate.py --seeds 20               # more datasets
    python evaluate.py --data ../data/cert_sessions.csv --name "CERT r4.2"   # a real labelled dataset

Results are written to model/evaluation.json and shown on the Model & accuracy page.

Cross-validation here means: each seed generates a new company history (different people's
habits, different attack timings and sizes), the model is trained from scratch on its normal
days and tested on its held-out days. The spread across seeds shows how stable the result is.
"""
import argparse
import json
import statistics
import sys
import time
from pathlib import Path

import detection_service as ds
import simulator

OUT = ds.MODEL_DIR / "evaluation.json"
METRICS = ("recall", "precision", "f1", "fp")


def run(events: list[dict]) -> dict:
    engine = ds.SentinelEngine()
    engine._fit(events, save=False)
    m = engine.metrics
    out = {"test_sessions": m["test_sessions"], "test_attacks": m["test_attacks"],
           "training_sessions": engine.detector.trained_on, "per_scenario": m["per_scenario"]}
    for k in ("ml_only", "rules_only", "hybrid"):
        out[k] = {**{x: m[k][x] for x in METRICS},
                  "auc": m["curves"][k]["auc"], "average_precision": m["curves"][k]["average_precision"]}
    out["curves"] = m["curves"]
    return out


def summarise(runs: list[dict]) -> dict:
    summary = {}
    for k in ("ml_only", "rules_only", "hybrid"):
        summary[k] = {}
        for x in (*METRICS, "auc", "average_precision"):
            vals = [r[k][x] for r in runs]
            summary[k][x] = {"mean": round(statistics.mean(vals), 4),
                             "std": round(statistics.pstdev(vals), 4),
                             "min": round(min(vals), 4), "max": round(max(vals), 4)}
    return summary


def load_existing() -> dict:
    try:
        return json.loads(OUT.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seeds", type=int, default=8, help="number of generated datasets for cross-validation")
    parser.add_argument("--data", type=Path, help="evaluate one labelled CSV (same columns as the demo data)")
    parser.add_argument("--name", default=None, help="display name for --data")
    args = parser.parse_args()
    result = load_existing()
    started = time.time()

    if args.data:
        name = args.name or args.data.stem
        events = simulator.load_csv(args.data)
        print(f"Evaluating {name}: {len(events)} sessions, {len({e['user_id'] for e in events})} users, "
              f"{sum(1 for e in events if e['scenario'])} labelled attack sessions")
        r = run(events)
        result.setdefault("external", {})[name] = {"file": args.data.name, "evaluated_at": simulator.now_ist().isoformat(),
                                                   "sessions": len(events), **r}
        for k in ("ml_only", "rules_only", "hybrid"):
            h = r[k]
            print(f"  {k:10s} recall {h['recall']:.1%}  precision {h['precision']:.1%}  "
                  f"AUC {h['auc']:.3f}  false alarms {h['fp']}")
    else:
        runs = []
        for seed in range(1, args.seeds + 1):
            events = simulator.generate_history(seed=seed * 101)
            r = run(events)
            r.pop("curves")
            runs.append({"seed": seed * 101, **r})
            h = r["hybrid"]
            print(f"  seed {seed * 101:4d}: {r['test_attacks']:2d} attacks  hybrid recall {h['recall']:.1%}  "
                  f"precision {h['precision']:.1%}  false alarms {h['fp']}")
        summary = summarise(runs)
        result["cross_validation"] = {
            "evaluated_at": simulator.now_ist().isoformat(),
            "method": f"{args.seeds} independently generated 45-day company histories; the model is trained from "
                      f"scratch on each and tested on its held-out days",
            "runs": runs, "summary": summary,
        }
        for k in ("ml_only", "rules_only", "hybrid"):
            s = summary[k]
            print(f"{k:10s} recall {s['recall']['mean']:.1%} ± {s['recall']['std']:.1%}   "
                  f"precision {s['precision']['mean']:.1%} ± {s['precision']['std']:.1%}   "
                  f"AUC {s['auc']['mean']:.3f}")

    ds.MODEL_DIR.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=1), encoding="utf-8")
    print(f"Saved {OUT} ({time.time() - started:.0f}s)")


if __name__ == "__main__":
    sys.exit(main())
