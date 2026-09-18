"""SentinelAI anomaly model: the complete model code in one self-contained file.

This file needs only NumPy. It does not import anything from backend/ and nothing in backend/
imports it, so using it can never change how the running app scores sessions.

    python model/sentinel_model.py info                       # what the saved model contains
    python model/sentinel_model.py score 5 0 1 1 1 8.5 0 3.2 3.2 1 2 2 1
    python model/sentinel_model.py explain 5 0 1 1 1 8.5 0 3.2 3.2 1 2 2 1
    python model/sentinel_model.py retrain                    # train a fresh copy into model/retrained/
    python model/verify_model.py                              # proves this file = the app's model

The model
    1. Isolation Forest (200 trees, 256 samples each): unusual sessions are isolated by random
       splits in fewer steps. Short average path = anomaly.  (Liu, Ting & Zhou, ICDM 2008)
    2. Robust Distance: how many "normal spreads" (median / MAD) each feature sits above normal.
    3. Calibration: each score -> 0-100 where the median normal session = 0 and the top 5% = 25.
    4. ML risk = the higher of the two. (The app then adds security rules: noisy-OR.)
"""
import json
import math
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
EULER_GAMMA = 0.5772156649
FEATURES = [
    "hours_outside_usual_window", "unusual_weekend_login", "new_device", "new_country", "new_city",
    "travel_speed_log", "failed_logins", "download_ratio_log", "data_volume_ratio_log", "api_ratio_log",
    "sensitive_ratio_log", "new_sensitive_systems", "unfamiliar_admin_actions",
]


def c(n: int) -> float:
    """Average path length of an unsuccessful search in a binary search tree of n points."""
    if n > 2:
        return 2.0 * (math.log(n - 1) + EULER_GAMMA) - 2.0 * (n - 1) / n
    return 1.0 if n == 2 else 0.0


# ------------------------------------------------------------------ training
def _grow(X: np.ndarray, depth: int, max_depth: int, rng, nodes: list) -> int:
    """Add one isolation tree (or subtree) to `nodes` as [feature, threshold, left, right, size]."""
    i = len(nodes)
    nodes.append(None)
    spread = X.max(axis=0) - X.min(axis=0) if len(X) else np.zeros(X.shape[1])
    candidates = np.flatnonzero(spread > 0)
    if depth >= max_depth or len(X) <= 1 or len(candidates) == 0:
        nodes[i] = [-1, 0.0, -1, -1, len(X)]
        return i
    f = rng.choice(candidates)
    split = rng.uniform(X[:, f].min(), X[:, f].max())
    left = X[:, f] < split
    li = _grow(X[left], depth + 1, max_depth, rng, nodes)
    ri = _grow(X[~left], depth + 1, max_depth, rng, nodes)
    nodes[i] = [int(f), float(split), li, ri, 0]
    return i


class SentinelModel:
    def __init__(self, data: dict):
        self.data = data
        forest, dist, cal = data["isolation_forest"], data["robust_distance"], data["calibration"]
        self.trees = forest["trees"]
        self.c_psi = forest["c_sample_size"]
        self.median = np.array([dist["median"][f] for f in FEATURES])
        self.scale = np.array([dist["scale"][f] for f in FEATURES])
        self.cal = cal

    # ---------------------------------------------------------- load / train
    @classmethod
    def load(cls, path=HERE / "sentinel_model.json") -> "SentinelModel":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    @classmethod
    def train(cls, X: np.ndarray, n_trees: int = 200, sample_size: int = 256, random_state: int = 42,
              percentile: float = 95, at_risk: float = 25) -> "SentinelModel":
        """Train on normal sessions only (rows of the 13 features). Same algorithm and seed as the app."""
        X = np.asarray(X, dtype=float)
        rng = np.random.default_rng(random_state)
        n = len(X)
        psi = min(sample_size, n)
        max_depth = int(np.ceil(np.log2(max(psi, 2))))
        trees = []
        for _ in range(n_trees):
            nodes: list = []
            _grow(X[rng.choice(n, psi, replace=False)], 0, max_depth, rng, nodes)
            trees.append(nodes)
        median = np.median(X, axis=0)
        mad = 1.4826 * np.median(np.abs(X - median), axis=0)
        scale = np.maximum(np.maximum(mad, X.std(axis=0)), 0.25)
        model = cls({
            "features": FEATURES,
            "isolation_forest": {"n_trees": n_trees, "sample_size": sample_size, "max_depth": max_depth,
                                 "c_sample_size": c(psi), "trees": trees},
            "robust_distance": {"median": dict(zip(FEATURES, median.tolist())),
                                "scale": dict(zip(FEATURES, scale.tolist()))},
            "calibration": {"risk_at_p95": at_risk},
            "trained_on_sessions": n,
        })
        forest_scores = np.array([model.forest_score(x) for x in X])
        distance_scores = np.array([model.distance_score(x) for x in X])
        model.cal.update(forest_p50=float(np.percentile(forest_scores, 50)),
                         forest_p95=float(np.percentile(forest_scores, percentile)),
                         distance_p50=float(np.percentile(distance_scores, 50)),
                         distance_p95=float(np.percentile(distance_scores, percentile)))
        return model

    def save(self, path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(self.data, separators=(",", ":")), encoding="utf-8")

    # --------------------------------------------------------------- scoring
    def path_length(self, tree: list, x) -> float:
        i, depth = 0, 0
        while tree[i][0] != -1:
            f, threshold, left, right, _ = tree[i]
            i = left if x[f] < threshold else right
            depth += 1
        return depth + c(tree[i][4])

    def forest_score(self, x) -> float:
        """Isolation Forest anomaly score in (0, 1): about 0.5 is ordinary, near 1 is very unusual."""
        x = list(map(float, x))
        mean_path = sum(self.path_length(t, x) for t in self.trees) / len(self.trees)
        return 2.0 ** (-mean_path / self.c_psi)

    def distance_score(self, x) -> float:
        z = np.clip((np.asarray(x, dtype=float) - self.median) / self.scale, 0.0, None)
        return float(np.sqrt(np.mean(z ** 2)))

    def _risk(self, score: float, p50: float, p95: float) -> float:
        return float(np.clip((score - p50) / max(p95 - p50, 1e-6) * self.cal["risk_at_p95"], 0.0, 100.0))

    def risk(self, x) -> float:
        """ML risk 0-100 for one session (13 features)."""
        return max(self._risk(self.forest_score(x), self.cal["forest_p50"], self.cal["forest_p95"]),
                   self._risk(self.distance_score(x), self.cal["distance_p50"], self.cal["distance_p95"]))

    def explain(self, x) -> list[tuple[str, float, float]]:
        """Features ranked by how far above normal they are: (name, value, spreads above normal)."""
        z = np.clip((np.asarray(x, dtype=float) - self.median) / self.scale, 0.0, None)
        order = np.argsort(z)[::-1]
        return [(FEATURES[i], float(x[i]), round(float(z[i]), 2)) for i in order if z[i] > 0]


def _session(args: list[str]) -> list[float]:
    if len(args) != len(FEATURES):
        sys.exit(f"Give {len(FEATURES)} numbers in this order:\n  " + "\n  ".join(FEATURES))
    return [float(a) for a in args]


def main(argv: list[str]) -> None:
    command = argv[0] if argv else "info"
    if command == "retrain":
        rows = np.loadtxt(HERE / "training_features.csv", delimiter=",", skiprows=1)
        model = SentinelModel.train(rows)
        out = HERE / "retrained" / "sentinel_model.json"
        model.save(out)
        print(f"Trained on {len(rows)} normal sessions -> {out}")
        print("(The app's own model files are untouched.)")
        return
    model = SentinelModel.load()
    if command == "info":
        f = model.data["isolation_forest"]
        nodes = sum(len(t) for t in f["trees"])
        print(f"Isolation Forest: {f['n_trees']} trees, {nodes} nodes, max depth {f['max_depth']}")
        print(f"Trained on {model.data['trained_on_sessions']} normal sessions")
        print("What normal looks like (median ± spread):")
        for name, m, s in zip(FEATURES, model.median, model.scale):
            print(f"  {name:28s} {m:7.3f} ± {s:.3f}")
    elif command == "score":
        print(f"ML risk: {model.risk(_session(argv[1:])):.1f} / 100")
    elif command == "explain":
        x = _session(argv[1:])
        print(f"ML risk: {model.risk(x):.1f} / 100. Most unusual features:")
        for name, value, z in model.explain(x)[:6]:
            print(f"  {name:28s} value {value:6.2f}  = {z:5.1f} normal spreads above usual")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
