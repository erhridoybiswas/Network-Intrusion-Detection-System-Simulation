"""
pipeline.py
-----------
The end-to-end detection pipeline. One function call processes one flow.

    raw flow
      -> extract_network_features()
      -> analyze_flow()                (signature)
      -> calculate_anomaly_score()     (statistical)
      -> predict_probability()         (ML, optional)
      -> calculate_risk_score()        (hybrid)
      -> generate_alert()
"""

from __future__ import annotations

from ids.alert_engine import generate_alert
from ids.anomaly_detector import calculate_anomaly_score
from ids.feature_extractor import extract_network_features
from ids.risk_engine import calculate_risk_score
from ids.rule_engine import analyze_flow


def process_flow(raw_flow: dict,
                 baseline: dict | None = None,
                 ml_model=None) -> dict:
    """
    Run the full detection pipeline on one raw flow record.

    Args:
        raw_flow: raw flow dict (from simulator or API)
        baseline: anomaly baseline dict (optional)
        ml_model: object with .predict_probability(features) -> float (optional)

    Returns:
        {
          "flow_id": ...,
          "features": {...},
          "rules": {...},
          "anomaly": {...},
          "ml_probability": float|None,
          "risk": {...},
          "alert": dict|None
        }
    """
    flow_id = raw_flow.get("flow_id") or "FLW-UNKNOWN"

    features = extract_network_features(raw_flow)
    features["flow_id"] = flow_id
    features["timestamp"] = raw_flow.get("timestamp")

    rule_result = analyze_flow(features)
    anomaly_result = calculate_anomaly_score(features, baseline)

    ml_probability = None
    if ml_model is not None:
        try:
            ml_probability = float(ml_model.predict_probability(features))
        except Exception:
            ml_probability = None

    risk_result = calculate_risk_score(rule_result, anomaly_result, ml_probability)

    alert = generate_alert(flow_id, features, rule_result,
                           anomaly_result, risk_result, ml_probability)

    return {
        "flow_id": flow_id,
        "features": features,
        "rules": rule_result,
        "anomaly": anomaly_result,
        "ml_probability": ml_probability,
        "risk": risk_result,
        "alert": alert,
    }