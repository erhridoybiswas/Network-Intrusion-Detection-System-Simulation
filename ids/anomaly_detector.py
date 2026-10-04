"""
anomaly_detector.py
-------------------
Anomaly-based detection using statistical deviation from a learned baseline.

Concept:
    Normal Baseline  ->  Observe New Flow  ->  Compare Against Baseline
        ->  Calculate Deviation  ->  Generate Anomaly Score (0-100)

Methods used:
    * Robust Z-score : |x - median| / (IQR / 1.349)
    * Standard Z-score: |x - mean| / std  (fallback when IQR == 0)

Why anomaly detection matters:
    It can catch behaviour nobody has written a signature for yet.
Why it is risky:
    It also flags legitimate-but-rare behaviour (backups, month-end batch jobs,
    software updates) -> more false positives than signature detection.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

from config import ANOMALY_FEATURES, ANOMALY_Z_CAP, BASELINE_PATH


# --------------------------------------------------------------------------
# Baseline construction
# --------------------------------------------------------------------------

def build_baseline(feature_rows: list[dict],
                   features: list[str] | None = None) -> dict:
    """
    Compute per-feature baseline statistics from a list of NORMAL feature dicts.

    Args:
        feature_rows: list of engineered feature dicts (normal traffic only)
        features: feature names to baseline (defaults to config.ANOMALY_FEATURES)

    Returns:
        {feature: {"mean":..., "std":..., "median":..., "q1":..., "q3":..., "iqr":...}}
    """
    features = features or ANOMALY_FEATURES
    baseline: dict[str, dict] = {}

    for name in features:
        values = sorted(float(r.get(name, 0.0)) for r in feature_rows)
        n = len(values)
        if n == 0:
            baseline[name] = {"mean": 0.0, "std": 0.0, "median": 0.0,
                              "q1": 0.0, "q3": 0.0, "iqr": 0.0}
            continue

        mean = sum(values) / n
        variance = sum((v - mean) ** 2 for v in values) / n
        std = math.sqrt(variance)

        median = _percentile(values, 50)
        q1 = _percentile(values, 25)
        q3 = _percentile(values, 75)

        baseline[name] = {
            "mean": round(mean, 6),
            "std": round(std, 6),
            "median": round(median, 6),
            "q1": round(q1, 6),
            "q3": round(q3, 6),
            "iqr": round(q3 - q1, 6),
        }
    return baseline


def _percentile(sorted_values: list[float], pct: float) -> float:
    """Linear-interpolation percentile on an already-sorted list."""
    if not sorted_values:
        return 0.0
    k = (len(sorted_values) - 1) * (pct / 100.0)
    lower = math.floor(k)
    upper = math.ceil(k)
    if lower == upper:
        return sorted_values[int(k)]
    return (sorted_values[lower] * (upper - k)
            + sorted_values[upper] * (k - lower))


def save_baseline(baseline: dict, path: Path | str = BASELINE_PATH) -> None:
    Path(path).write_text(json.dumps(baseline, indent=2), encoding="utf-8")


def load_baseline(path: Path | str = BASELINE_PATH) -> dict | None:
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------

def _robust_z(value: float, stats: dict) -> float:
    """
    Robust Z-score using the IQR. Falls back to standard Z-score when
    the IQR is zero (e.g. a feature that is constant in the baseline).
    """
    median = stats.get("median", 0.0)
    iqr = stats.get("iqr", 0.0)
    std = stats.get("std", 0.0)

    if iqr > 0:
        scale = iqr / 1.349          # IQR -> approx sigma for normal data
        return abs(value - median) / scale

    if std > 0:
        return abs(value - stats.get("mean", 0.0)) / std

    return 0.0                        # perfectly constant feature


def calculate_anomaly_score(features: dict, baseline: dict | None) -> dict:
    """
    Compute an anomaly score between 0 and 100.

    Args:
        features: engineered feature dict
        baseline: baseline produced by build_baseline()

    Returns:
        {
          "anomaly_score": 0-100,
          "components": {feature: {"value":..., "z":..., "contribution":...}},
          "top_feature": name,
          "method": "zscore+iqr" | "none"
        }
    """
    if not baseline:
        return {"anomaly_score": 0.0, "components": {},
                "top_feature": None, "method": "none"}

    components: dict[str, dict] = {}
    contributions: list[float] = []

    for name in ANOMALY_FEATURES:
        stats = baseline.get(name)
        if not stats:
            continue

        value = float(features.get(name, 0.0) or 0.0)
        z = _robust_z(value, stats)

        # Scale z into 0-100, saturating at ANOMALY_Z_CAP
        component = min(z / ANOMALY_Z_CAP, 1.0) * 100.0

        components[name] = {
            "value": round(value, 4),
            "z": round(z, 4),
            "contribution": round(component, 2),
        }
        contributions.append(component)

    if not contributions:
        return {"anomaly_score": 0.0, "components": {},
                "top_feature": None, "method": "none"}

    mean_component = sum(contributions) / len(contributions)
    max_component = max(contributions)

    # Blend: average catches broad drift, max catches a single stark outlier
    score = 0.60 * mean_component + 0.40 * max_component

    top_feature = max(components.items(), key=lambda kv: kv[1]["contribution"])[0]

    return {
        "anomaly_score": round(min(score, 100.0), 2),
        "components": components,
        "top_feature": top_feature,
        "method": "zscore+iqr",
    }