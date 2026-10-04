"""
correlation.py
--------------
Alert correlation: groups related alerts into incidents.

Definitions (memorise these for interviews):
    EVENT    - A single observation. "Flow X happened."
    ALERT    - A detection that requires attention. "Flow X matched rule Y."
    INCIDENT - A collection of related alerts requiring investigation.
               "Source Z triggered 40 alerts in 60 seconds."

Without correlation, a single noisy source can generate hundreds of rows in
the analyst queue and cause alert fatigue.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from config import CORRELATION_MIN_ALERTS, CORRELATION_WINDOW_SECONDS


def _parse_ts(value: str) -> datetime:
    """Parse an ISO timestamp, tolerating a trailing 'Z'."""
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)


def correlate_alerts(alerts: list[dict],
                     window_seconds: int = CORRELATION_WINDOW_SECONDS,
                     min_alerts: int = CORRELATION_MIN_ALERTS) -> list[dict]:
    """
    Group alerts by (source_ip, alert_type) inside a sliding time window.

    Args:
        alerts: list of alert dicts
        window_seconds: grouping window length
        min_alerts: minimum group size to be promoted to an incident

    Returns:
        List of incident dicts. Alerts that do not meet the threshold are
        returned inside `standalone_alerts`.
    """
    if not alerts:
        return []

    ordered = sorted(alerts, key=lambda a: _parse_ts(a["timestamp"]))
    buckets: dict[tuple, list[dict]] = defaultdict(list)

    for alert in ordered:
        buckets[(alert.get("source_ip"), alert.get("alert_type"))].append(alert)

    incidents: list[dict] = []
    standalone: list[dict] = []

    for (source_ip, alert_type), group in buckets.items():
        group.sort(key=lambda a: _parse_ts(a["timestamp"]))

        current: list[dict] = [group[0]]
        for alert in group[1:]:
            delta = (_parse_ts(alert["timestamp"])
                     - _parse_ts(current[-1]["timestamp"])).total_seconds()
            if delta <= window_seconds:
                current.append(alert)
            else:
                _flush(current, source_ip, alert_type, min_alerts,
                       incidents, standalone)
                current = [alert]
        _flush(current, source_ip, alert_type, min_alerts,
               incidents, standalone)

    return {"incidents": incidents, "standalone_alerts": standalone}


def _flush(group: list[dict], source_ip: str, alert_type: str,
           min_alerts: int, incidents: list, standalone: list) -> None:
    if not group:
        return
    if len(group) < min_alerts:
        standalone.extend(group)
        return

    severities = [a.get("severity", "INFO") for a in group]
    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    max_sev = max(severities, key=lambda s: order.index(s) if s in order else 0)

    incidents.append({
        "incident_id": f"INC-{abs(hash((source_ip, alert_type, group[0]['alert_id']))) % 10**8:08d}",
        "source_ip": source_ip,
        "alert_type": alert_type,
        "alert_count": len(group),
        "first_seen": group[0]["timestamp"],
        "last_seen": group[-1]["timestamp"],
        "max_severity": max_sev,
        "max_risk_score": max(a.get("risk_score", 0) for a in group),
        "alert_ids": [a["alert_id"] for a in group],
        "summary": (f"{len(group)} '{alert_type}' alerts from {source_ip} "
                    f"within a {CORRELATION_WINDOW_SECONDS}s window."),
    })