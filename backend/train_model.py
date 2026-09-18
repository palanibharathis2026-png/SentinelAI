"""Train the SentinelAI model from the dataset and save it to model/.

Usage (from the backend folder):
    python train_model.py                       # train on data/synthetic_security_events.csv
    python train_model.py --data my_logs.csv    # train on your own logs (same columns)
    python train_model.py --check               # also reload the saved file and verify it scores identically

Outputs:
    model/sentinel_model.npz   every learned parameter (200 trees, medians, spreads, calibration)
    model/model_card.json      what the model is, what it learned, training data and test results
"""
import argparse
import os
import sys
from pathlib import Path

import numpy as np


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data", type=Path, help="CSV with the same columns as data/synthetic_security_events.csv")
    parser.add_argument("--check", action="store_true", help="reload the saved model and compare scores")
    args = parser.parse_args()
    if args.data:
        os.environ["SENTINEL_DATA"] = str(args.data.resolve())

    import detection_service as ds  # after SENTINEL_DATA is set
    import simulator
    from ml_detector import load_detector

    events = simulator.load_csv(ds.DATA_PATH)
    engine = ds.SentinelEngine()
    engine._fit(events)
    card = engine.card
    ev = card["evaluation"]

    print(f"Trained on {card['training_data']['training_sessions']} normal sessions "
          f"from {card['training_data']['employees']} employees ({ds.DATA_PATH.name})")
    print(f"Test set: {ev['test_sessions']} unseen sessions, {ev['test_attacks']} attacks (alert = risk >= {ev['alert_threshold']})")
    for name in ("rules_only", "ml_only", "hybrid"):
        r = ev[name]
        print(f"  {name:10s} recall {r['recall']:.1%}  precision {r['precision']:.1%}  false alarms {r['fp']}")
    print("Feature share of forest splits:")
    for f in sorted(card["features"], key=lambda f: -f["split_share"]):
        print(f"  {f['name']:28s} {f['split_share']:.1%}")
    print(f"Saved {ds.MODEL_DIR / ds.MODEL_FILE} and {ds.MODEL_DIR / ds.CARD_FILE}")

    if args.check:
        reloaded = load_detector(ds.MODEL_DIR / ds.MODEL_FILE)
        X = np.random.default_rng(0).gamma(1.0, 1.0, (200, len(card["features"])))
        same = np.allclose(engine.detector.risk(X), reloaded.risk(X))
        print("Reload check:", "identical scores" if same else "MISMATCH")
        sys.exit(0 if same else 1)


if __name__ == "__main__":
    main()
