"""
alert_engine.py
---------------
Converts a detection result into a structured, SOC-ready alert.

Alert lifecycle statuses:
    NEW -> INVESTIGATING -> RESOLVED
                        \\-> FALSE_POSITIVE
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone


def _new_alert_id() -> str:
    return f"ALT-{uuid.uuid4().hex[:8].upper()}"


def _primary_rule(rule_result: dict) -> dict | None:
    """Return the highest-severity matched rule."""
    matches = rule_result.get("matches") or []
    if not matches:
        return None
    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    return max(matches, key=lambda m: order.index(m["severity"]))


def generate_alert(flow_id: str,
                   features: dict,
                   rule_result: dict,
                   anomaly_result: dict,
                   risk_result: dict,
                   ml_probability: float | None = None) -> dict | None:
    """
    Build an alert dict.

    Returns None when the flow is classified NORMAL and no rule matched —
    we do not want to flood the SOC queue with non-events.
    """
    matches = rule_result.get("matches") or []
    classification = risk_result["classification"]

    if not matches and classification == "NORMAL":
        return None

    primary = _primary_rule(rule_result)

    if primary:
        alert_type = primary["name"]
        rule_id = primary["rule_id"]
        reason = primary["reason"]
    else:
        alert_type = "Statistical Anomaly"
        rule_id = "ANOM-000"
        top = anomaly_result.get("top_feature")
        if top:
            reason = (f"Flow deviated from baseline — largest deviation in "
                      f"'{top}'. No signature rule matched.")
        else:
            reason = "Flow deviated from the learned normal baseline."

    if ml_probability is not None:
        reason += f" ML suspicious probability: {ml_probability*100:.1f}%."

    return {
        "alert_id": _new_alert_id(),
        "flow_id": flow_id,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_ip": features.get("source_ip"),
        "destination_ip": features.get("destination_ip"),
        "protocol": features.get("protocol"),
        "source_port": features.get("source_port"),
        "destination_port": features.get("destination_port"),
        "rule_id": rule_id,
        "alert_type": alert_type,
        "severity": risk_result["severity"],
        "risk_score": risk_result["risk_score"],
        "classification": classification,
        "description": reason,
        "matched_rules": [m["rule_id"] for m in matches],
        "anomaly_score": anomaly_result.get("anomaly_score", 0.0),
        "ml_score": round(ml_probability * 100, 2) if ml_probability is not None else None,
        "status": "NEW",
    }


def format_alert_text(alert: dict) -> str:
    """Human-readable alert block for CLI / reports."""
    return (
        f"ALERT ID   : {alert['alert_id']}\n"
        f"TYPE       : {alert['alert_type']}\n"
        f"SEVERITY   : {alert['severity']}\n"
        f"SOURCE     : {alert['source_ip']}:{alert['source_port']}\n"
        f"DESTINATION: {alert['destination_ip']}:{alert['destination_port']}\n"
        f"PROTOCOL   : {alert['protocol']}\n"
        f"RISK       : {alert['risk_score']}/100 ({alert['classification']})\n"
        f"STATUS     : {alert['status']}\n"
        f"REASON     : {alert['description']}\n"
    )