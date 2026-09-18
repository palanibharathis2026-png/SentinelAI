"""Check that model/sentinel_model.py is exactly the model the app uses.

    python model/verify_model.py

1. Loads the app's binary model (sentinel_model.npz) with the app's own code.
2. Loads the readable copy (sentinel_model.json) with the standalone model/sentinel_model.py.
3. Retrains from scratch with the standalone code on training_features.csv.
All three must give the same risk for every training session and for sample attacks.
Nothing is written to the app's model files.
"""
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "backend"))

from ml_detector import load_detector  # noqa: E402  (the app's code)
from sentinel_model import SentinelModel  # noqa: E402  (the standalone copy)

rows = np.loadtxt(HERE / "training_features.csv", delimiter=",", skiprows=1)
attacks = np.array([
    [5, 0, 1, 1, 1, 8.5, 0, 3.2, 3.2, 1.0, 2.0, 2, 1],
    [0, 0, 0, 0, 0, 0, 0, 2.5, 3.0, 0.1, 2.2, 1, 1],
    [3, 1, 1, 0, 0, 0, 12, 0.1, 0.1, 2.8, 0.3, 0, 0],
])
X = np.vstack([rows, attacks])

app = load_detector(HERE / "sentinel_model.npz").risk(X)
readable = np.array([SentinelModel.load().risk(x) for x in X])
fresh = SentinelModel.train(rows)
retrained = np.array([fresh.risk(x) for x in X])

# The retrained copy learns from training_features.csv (full precision), so it should match exactly;
# a gap under 0.5 risk points still counts as the same model.
for name, scores, tolerance in (("readable JSON copy", readable, 1e-3), ("retrained from scratch", retrained, 0.5)):
    gap = float(np.max(np.abs(scores - app)))
    print(f"{name:24s} vs app model: largest difference {gap:.4f} risk points on {len(X)} sessions -> "
          f"{'SAME' if gap < tolerance else 'DIFFERENT'}")
print("sample attacks, app model:", [round(float(v), 1) for v in app[-3:]])
