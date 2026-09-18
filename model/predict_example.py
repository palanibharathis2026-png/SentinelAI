"""Score a session with the SentinelAI model using only sentinel_model.json and NumPy.

    python model/predict_example.py

No SentinelAI code is imported: this is the whole model, applied by hand, so anyone can see
exactly how a risk number is produced from the saved file.
"""
import json
import math
from pathlib import Path

import numpy as np

model = json.loads((Path(__file__).parent / "sentinel_model.json").read_text(encoding="utf-8"))
FEATURES = model["features"]


def c(n: int) -> float:
    """Average path length of an unsuccessful binary-search-tree search over n points."""
    return 2 * (math.log(n - 1) + 0.5772156649) - 2 * (n - 1) / n if n > 2 else (1.0 if n == 2 else 0.0)


def path_length(tree: list, x: list) -> float:
    i, depth = 0, 0
    while tree[i][0] != -1:  # [feature, threshold, left, right, size]
        feature, threshold, left, right, _ = tree[i]
        i = left if x[feature] < threshold else right
        depth += 1
    return depth + c(tree[i][4])


def ml_risk(x: list) -> float:
    forest, dist, cal = model["isolation_forest"], model["robust_distance"], model["calibration"]
    mean_path = sum(path_length(t, x) for t in forest["trees"]) / forest["n_trees"]
    forest_score = 2 ** (-mean_path / forest["c_sample_size"])
    median = np.array([dist["median"][f] for f in FEATURES])
    scale = np.array([dist["scale"][f] for f in FEATURES])
    z = np.clip((np.array(x) - median) / scale, 0, None)
    distance_score = float(np.sqrt(np.mean(z ** 2)))

    def to_risk(score, p50, p95):
        return float(np.clip((score - p50) / max(p95 - p50, 1e-6) * cal["risk_at_p95"], 0, 100))

    return max(to_risk(forest_score, cal["forest_p50"], cal["forest_p95"]),
               to_risk(distance_score, cal["distance_p50"], cal["distance_p95"]))


sessions = {
    "Normal working day": [0, 0, 0, 0, 0, 0, 0, 0.05, 0.1, -0.02, 0.0, 0, 0],
    "Login 4h early, on a new laptop": [4, 0, 1, 0, 0, 0, 0, 0.1, 0.1, 0, 0, 0, 0],
    "Account takeover (abroad, 25x downloads)": [5, 0, 1, 1, 1, 8.5, 0, 3.2, 3.2, 1.0, 2.0, 2, 1],
}
for name, x in sessions.items():
    print(f"{name:45s} ML risk {ml_risk(x):5.1f} / 100")
print("\n0 = a typical normal session, 25 = the top 5% of normal sessions, 100 = extreme.")
print("The full system adds security rules on top (noisy-OR) to reach the final Allow / Monitor / MFA / Block.")
