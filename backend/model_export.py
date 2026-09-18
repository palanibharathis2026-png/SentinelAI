"""Write the trained model in forms a person can open and read (on GitHub or in any editor).

model/sentinel_model.json      every learned number: 200 trees, medians, spreads, calibration (plain JSON)
model/feature_statistics.csv   per feature: what normal looks like and how much the forest relies on it
model/training_features.csv    the exact feature rows the model was trained on
model/tree_000.txt             the first isolation tree written out as if/else rules
model/charts/*.svg             ROC curve, feature importance, cross-validation and real-data results
The .npz file stays the fast binary copy; these are the same model, readable.
"""
import csv
import json
from pathlib import Path

import numpy as np

from ml_detector import _flatten

COLORS = {"hybrid": "#0891b2", "ml_only": "#c026d3", "rules_only": "#d97706"}
LABELS = {"hybrid": "SentinelAI hybrid", "ml_only": "ML only", "rules_only": "Rules only"}


def _model_json(det, features: list[str]) -> dict:
    forest = det.forest.model
    return {
        "format": "SentinelAI anomaly detector v1 (readable copy of sentinel_model.npz)",
        "features": features,
        "how_to_score": [
            "1. Build the 13 features of a session in the order above (see feature_statistics.csv).",
            "2. Isolation Forest: walk each tree (node = [feature, threshold, left, right, size]; feature -1 = leaf). "
            "Go left when value < threshold. Path length = depth + c(size) at the leaf. "
            "Score = 2 ** (-(mean path length) / c(sample_size)).",
            "3. Robust distance: z = max(0, (x - median) / scale) per feature; score = sqrt(mean(z^2)).",
            "4. Each score -> risk: (score - p50) / (p95 - p50) * 25, clipped to 0-100.",
            "5. ML risk = max(forest risk, distance risk). predict_example.py does all of this in 40 lines.",
        ],
        "isolation_forest": {
            "n_trees": forest.n_trees, "sample_size": forest.sample_size, "max_depth": forest.max_depth,
            "c_sample_size": round(forest._c, 6),
            "trees": [[[int(f), round(float(t), 6), int(l), int(r), int(s)] for f, t, l, r, s in _flatten(tree)]
                      for tree in forest.trees],
        },
        "robust_distance": {
            "median": {f: round(float(v), 6) for f, v in zip(features, det.distance.model.median)},
            "scale": {f: round(float(v), 6) for f, v in zip(features, det.distance.model.scale)},
        },
        "calibration": {
            "forest_p50": det.forest.lo, "forest_p95": det.forest.hi,
            "distance_p50": det.distance.lo, "distance_p95": det.distance.hi, "risk_at_p95": det.at_risk,
        },
        "trained_on_sessions": det.trained_on,
    }


def _tree_text(tree, features: list[str], max_depth: int = 8) -> str:
    lines = ["Isolation tree #0 of 200. Each path ends in a leaf holding some training sessions.",
             "Anomalies are isolated in few steps: a short path means 'unusual'.", ""]

    def visit(node, depth, prefix):
        pad = "    " * depth
        if node[0] == "leaf":
            lines.append(f"{pad}{prefix}leaf: {node[1]} training session(s), path length {depth}")
            return
        _, f, split, left, right = node
        if depth >= max_depth:
            lines.append(f"{pad}{prefix}...")
            return
        lines.append(f"{pad}{prefix}if {features[f]} < {split:.3f}:")
        visit(left, depth + 1, "")
        lines.append(f"{pad}else:  # {features[f]} >= {split:.3f}")
        visit(right, depth + 1, "")

    visit(tree, 0, "")
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------- SVG charts
def _svg(width: int, height: int, body: list[str], title: str) -> str:
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
            f'font-family="Segoe UI, Helvetica, Arial, sans-serif" font-size="12">'
            f'<rect width="100%" height="100%" fill="#ffffff"/>'
            f'<text x="16" y="24" font-size="15" font-weight="600" fill="#0f172a">{title}</text>'
            + "".join(body) + "</svg>\n")


def roc_svg(curves: dict, title: str) -> str:
    w, h, left, top, size = 560, 440, 60, 50, 320
    body = [f'<rect x="{left}" y="{top}" width="{size}" height="{size}" fill="none" stroke="#cbd5e1"/>',
            f'<line x1="{left}" y1="{top + size}" x2="{left + size}" y2="{top}" stroke="#cbd5e1" stroke-dasharray="4 4"/>']
    for i in range(0, 11, 2):
        v = i / 10
        body.append(f'<text x="{left + v * size}" y="{top + size + 16}" text-anchor="middle" fill="#475569">{int(v * 100)}%</text>')
        body.append(f'<text x="{left - 8}" y="{top + size - v * size + 4}" text-anchor="end" fill="#475569">{int(v * 100)}%</text>')
    body.append(f'<text x="{left + size / 2}" y="{top + size + 36}" text-anchor="middle" fill="#0f172a">False alarm rate</text>')
    body.append(f'<text x="18" y="{top + size / 2}" transform="rotate(-90 18 {top + size / 2})" text-anchor="middle" '
                f'fill="#0f172a">Attacks caught (recall)</text>')
    for j, key in enumerate(("rules_only", "ml_only", "hybrid")):
        if key not in curves:
            continue
        pts = " ".join(f"{left + x * size:.1f},{top + size - y * size:.1f}" for x, y in curves[key]["roc"])
        body.append(f'<polyline points="{pts}" fill="none" stroke="{COLORS[key]}" stroke-width="{3 if key == "hybrid" else 2}"/>')
        y = top + 20 + j * 40
        body.append(f'<rect x="{left + size + 16}" y="{y - 9}" width="14" height="4" fill="{COLORS[key]}"/>')
        body.append(f'<text x="{left + size + 36}" y="{y - 3}" fill="#0f172a">{LABELS[key]}</text>')
        body.append(f'<text x="{left + size + 36}" y="{y + 11}" fill="#475569">AUC {curves[key]["auc"]:.3f}</text>')
    return _svg(w, h, body, title)


def importance_svg(features: list[str], shares, medians, scales) -> str:
    order = np.argsort(shares)[::-1]
    w, row, left = 800, 26, 230
    h = 60 + row * len(features)
    top = max(float(np.max(shares)), 0.01)
    body = [f'<text x="{left}" y="44" fill="#475569">Share of all Isolation Forest splits that use the feature</text>']
    for k, i in enumerate(order):
        y = 56 + k * row
        bar = shares[i] / top * 300
        body.append(f'<text x="{left - 8}" y="{y + 13}" text-anchor="end" fill="#0f172a">{features[i]}</text>')
        body.append(f'<rect x="{left}" y="{y + 2}" width="{bar:.1f}" height="16" rx="3" fill="#0891b2"/>')
        body.append(f'<text x="{left + bar + 6}" y="{y + 14}" fill="#475569">{shares[i] * 100:.1f}%  '
                    f'(normal ~ {medians[i]:.2f} ± {scales[i]:.2f})</text>')
    return _svg(w, h, body, "What the forest learned to look at")


def cross_validation_svg(cv: dict) -> str:
    runs = cv["runs"]
    w, h, left, top, plot_h = 600, 300, 60, 50, 190
    step = (w - left - 40) / max(len(runs), 1)
    body = [f'<line x1="{left}" y1="{top + plot_h}" x2="{w - 30}" y2="{top + plot_h}" stroke="#cbd5e1"/>']
    for v in (0.8, 0.9, 1.0):
        y = top + plot_h - (v - 0.7) / 0.3 * plot_h
        body.append(f'<line x1="{left}" y1="{y:.1f}" x2="{w - 30}" y2="{y:.1f}" stroke="#e2e8f0"/>')
        body.append(f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end" fill="#475569">{int(v * 100)}%</text>')
    for i, r in enumerate(runs):
        x = left + step * (i + 0.5)
        for key, dx in (("rules_only", -10), ("ml_only", 0), ("hybrid", 10)):
            v = max(r[key]["recall"], 0.7)
            y = top + plot_h - (v - 0.7) / 0.3 * plot_h
            body.append(f'<circle cx="{x + dx:.1f}" cy="{y:.1f}" r="5" fill="{COLORS[key]}"/>')
        body.append(f'<text x="{x:.1f}" y="{top + plot_h + 16}" text-anchor="middle" fill="#475569">#{i + 1}</text>')
    s = cv["summary"]
    for j, key in enumerate(("hybrid", "ml_only", "rules_only")):
        x = left + j * 180
        body.append(f'<circle cx="{x + 5}" cy="{h - 22}" r="5" fill="{COLORS[key]}"/>')
        body.append(f'<text x="{x + 16}" y="{h - 18}" fill="#0f172a">{LABELS[key]} {s[key]["recall"]["mean"] * 100:.1f}% '
                    f'± {s[key]["recall"]["std"] * 100:.1f}</text>')
    return _svg(w, h, body, f"Recall on {len(runs)} independently generated datasets (cross-validation)")


# --------------------------------------------------------------------- main
def export_readable(engine, model_dir: Path, features: list[str], descriptions: dict) -> None:
    det = engine.detector
    model_dir.mkdir(parents=True, exist_ok=True)
    charts = model_dir / "charts"
    charts.mkdir(exist_ok=True)
    (model_dir / "sentinel_model.json").write_text(json.dumps(_model_json(det, features), separators=(",", ":")),
                                                   encoding="utf-8")
    shares = np.array([f["split_share"] for f in engine.card["features"]])
    medians, scales = det.distance.model.median, det.distance.model.scale
    with open(model_dir / "feature_statistics.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["feature", "description", "normal_median", "normal_spread", "forest_split_share"])
        for i, name in enumerate(features):
            w.writerow([name, descriptions[name], round(float(medians[i]), 4), round(float(scales[i]), 4),
                        round(float(shares[i]), 4)])
    with open(model_dir / "training_features.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(features)
        for row in engine._train_X:
            w.writerow([round(float(v), 4) for v in row])
    (model_dir / "tree_000.txt").write_text(_tree_text(det.forest.model.trees[0], features), encoding="utf-8")
    (charts / "roc_curve.svg").write_text(
        roc_svg(engine.metrics["curves"], "ROC curve on held-out test sessions"), encoding="utf-8")
    (charts / "feature_importance.svg").write_text(importance_svg(features, shares, medians, scales), encoding="utf-8")
    try:
        ev = json.loads((model_dir / "evaluation.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        ev = {}
    if ev.get("cross_validation"):
        (charts / "cross_validation.svg").write_text(cross_validation_svg(ev["cross_validation"]), encoding="utf-8")
    for name, r in (ev.get("external") or {}).items():
        slug = "".join(c if c.isalnum() else "_" for c in name.lower()).strip("_")
        if r.get("curves"):
            (charts / f"{slug}_roc_curve.svg").write_text(roc_svg(r["curves"], f"ROC curve on {name} (real labelled data)"),
                                                          encoding="utf-8")
