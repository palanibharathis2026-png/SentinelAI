"""Anomaly detection models, implemented from scratch with numpy (no scikit-learn needed).

Isolation Forest: anomalies are "few and different", so random splits isolate them in
far fewer steps than normal points. Short average path length = anomaly.
Reference: Liu, Ting & Zhou, "Isolation Forest" (ICDM 2008).
"""
import math

import numpy as np

EULER_GAMMA = 0.5772156649


def _avg_path(n: int) -> float:
    """Average path length of an unsuccessful search in a binary search tree of n points."""
    if n > 2:
        return 2.0 * (math.log(n - 1) + EULER_GAMMA) - 2.0 * (n - 1) / n
    return 1.0 if n == 2 else 0.0


class IsolationForest:
    def __init__(self, n_trees: int = 200, sample_size: int = 256, random_state: int = 42):
        self.n_trees = n_trees
        self.sample_size = sample_size
        self.random_state = random_state
        self.trees = []

    def fit(self, X: np.ndarray) -> "IsolationForest":
        rng = np.random.default_rng(self.random_state)
        n = len(X)
        psi = min(self.sample_size, n)
        self.max_depth = int(np.ceil(np.log2(max(psi, 2))))
        self._c = _avg_path(psi)
        self.trees = [self._build(X[rng.choice(n, psi, replace=False)], 0, rng) for _ in range(self.n_trees)]
        return self

    def _build(self, X: np.ndarray, depth: int, rng) -> tuple:
        n = len(X)
        if depth >= self.max_depth or n <= 1:
            return ("leaf", n)
        spread = X.max(axis=0) - X.min(axis=0)
        candidates = np.flatnonzero(spread > 0)
        if len(candidates) == 0:
            return ("leaf", n)
        f = rng.choice(candidates)
        split = rng.uniform(X[:, f].min(), X[:, f].max())
        left = X[:, f] < split
        return ("node", f, split, self._build(X[left], depth + 1, rng), self._build(X[~left], depth + 1, rng))

    def _path_lengths(self, node, X, idx, depth, out):
        if node[0] == "leaf":
            out[idx] = depth + _avg_path(node[1])
            return
        _, f, split, left, right = node
        go_left = X[idx, f] < split
        self._path_lengths(left, X, idx[go_left], depth + 1, out)
        self._path_lengths(right, X, idx[~go_left], depth + 1, out)

    def _path_length_one(self, node, x) -> float:
        depth = 0
        while node[0] == "node":
            _, f, split, left, right = node
            node = left if x[f] < split else right
            depth += 1
        return depth + _avg_path(node[1])

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """Anomaly score in (0, 1): ~0.5 is ordinary, close to 1 is highly anomalous."""
        X = np.atleast_2d(X)
        if len(X) <= 8:  # live scoring of a few sessions: a plain loop is fastest
            total = np.array([sum(self._path_length_one(t, x.tolist()) for t in self.trees) for x in X])
        else:
            total = np.zeros(len(X))
            for tree in self.trees:
                out = np.zeros(len(X))
                self._path_lengths(tree, X, np.arange(len(X)), 0, out)
                total += out
        return 2.0 ** (-(total / len(self.trees)) / self._c)


class RobustDistance:
    """How many 'normal spreads' a session sits above the typical session, across all features.

    Uses median/MAD so a few odd training sessions don't distort the baseline. Only upward
    deviations count, because every feature is oriented so that higher = more suspicious.
    """

    def fit(self, X: np.ndarray) -> "RobustDistance":
        self.median = np.median(X, axis=0)
        mad = 1.4826 * np.median(np.abs(X - self.median), axis=0)
        self.scale = np.maximum(np.maximum(mad, X.std(axis=0)), 0.25)
        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        z = np.clip((np.atleast_2d(X) - self.median) / self.scale, 0.0, None)
        return np.sqrt(np.mean(z ** 2, axis=1))


class _Calibrated:
    """Maps raw model scores to 0-100: median normal session -> 0, 95th percentile -> 25."""

    def __init__(self, model, scores: np.ndarray, percentile: float = 95, at_risk: float = 25):
        self.model = model
        self.lo = float(np.percentile(scores, 50))
        self.hi = float(np.percentile(scores, percentile))
        self.at_risk = at_risk

    def risk(self, X: np.ndarray) -> np.ndarray:
        scaled = (self.model.score_samples(X) - self.lo) / max(self.hi - self.lo, 1e-6) * self.at_risk
        return np.clip(scaled, 0.0, 100.0)


class AnomalyDetector:
    """Ensemble of two unsupervised models, trained only on normal behaviour.

    Isolation Forest spots unusual *combinations*; RobustDistance spots extreme *magnitudes*
    (which a forest cannot score beyond the most extreme training point). ML risk = the higher of the two.
    """

    def __init__(self, mode: str = "max", percentile: float = 95, at_risk: float = 25):
        self.mode, self.percentile, self.at_risk = mode, percentile, at_risk
        self.trained_on = 0

    def fit(self, X: np.ndarray) -> "AnomalyDetector":
        forest = IsolationForest().fit(X)
        distance = RobustDistance().fit(X)
        self.forest = _Calibrated(forest, forest.score_samples(X), self.percentile, self.at_risk)
        self.distance = _Calibrated(distance, distance.score_samples(X), self.percentile, self.at_risk)
        self.trained_on = len(X)
        return self

    def risk(self, X: np.ndarray) -> np.ndarray:
        if self.mode == "forest":
            return self.forest.risk(X)
        if self.mode == "distance":
            return self.distance.risk(X)
        if self.mode == "mean":
            return (self.forest.risk(X) + self.distance.risk(X)) / 2
        return np.maximum(self.forest.risk(X), self.distance.risk(X))
