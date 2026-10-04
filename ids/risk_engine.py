"""
risk_engine.py
--------------
Combines the three detection signals into a single 0-100 risk score.

    Signature Risk  (from rule_engine)
  + Anomaly Risk    (from anomaly_detector)
  + ML Probability  (optional, from ml/predict.py)
  = Hybrid Risk Score

Weights (configurable in config.py):
    With ML    : Rule 0.40 | Anomaly 0.30 | ML 0.30
    Without ML : Rule 0.60 | Anomaly 0.40

Why hybrid?
    Signature detection is precise but blind to novelty.
    Anomaly detection is broad but noisy.
    ML can generalise across both, but needs data.
    Blending them gives stronger coverage than any single method.
"""

from __future__ import annotations

from config import (
    RISK_BANDS,
    RISK_WEIGHTS_NO_ML,
    RISK_WEIGHTS_WITH_ML,
)


def classify_risk(score: float) -> str:
    """Map a 0-100 risk score to a classification band."""
    score = max(0.0, min(float(score), 100.0))
    for low, high, label in RISK_BANDS:
        if low <= score <= high:
            return label
    return "NORMAL"


def score_to_severity(score: float) -> str:
    """Map a 0-100 risk score to an alert severity label."""
    score = max(0.0, min(float(score), 100.0))
    if score >= 81:
        return "CRITICAL"
    if score >= 61:
        return "HIGH"
    if score >= 41:
        return "MEDIUM"
    if score >= 21:
        return "LOW"
    return "INFO"


def calculate_risk_score(rule_result: dict,
                         anomaly_result: dict,
                         ml_probability: float | None = None) -> dict:
    """
    Compute the hybrid risk score.

    Args:
        rule_result: output of rule_engine.analyze_flow()
        anomaly_result: output of anomaly_detector.calculate_anomaly_score()
        ml_probability: 0.0-1.0 suspicious probability, or None if ML disabled

    Returns:
        {
          "risk_score": 0-100,
          "classification": "...",
          "severity": "...",
          "weights": {...},
          "components": {"rule": .., "anomaly": .., "ml": ..}
        }
    """
    rule_score = float(rule_result.get("rule_score", 0.0))
    anomaly_score = float(anomaly_result.get("anomaly_score", 0.0))

    ml_enabled = ml_probability is not None
    weights = RISK_WEIGHTS_WITH_ML if ml_enabled else RISK_WEIGHTS_NO_ML

    ml_score = round(float(ml_probability) * 100.0, 2) if ml_enabled else 0.0

    risk = (weights["rule"] * rule_score
            + weights["anomaly"] * anomaly_score
            + weights["ml"] * ml_score)

    risk = round(max(0.0, min(risk, 100.0)), 2)

    return {
        "risk_score": risk,
        "classification": classify_risk(risk),
        "severity": score_to_severity(risk),
        "weights": weights,
        "components": {
            "rule": round(rule_score, 2),
            "anomaly": round(anomaly_score, 2),
            "ml": ml_score,
            "ml_enabled": ml_enabled,
        },
    }