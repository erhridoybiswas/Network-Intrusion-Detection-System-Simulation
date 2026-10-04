"""
routes.py
---------
REST API for the IDS simulation.

Endpoints:
    POST   /api/flows                    ingest + analyse one flow
    GET    /api/flows                    list flows (paginated + filtered)
    GET    /api/flows/<flow_id>          flow detail
    GET    /api/alerts                   list alerts (paginated + filtered)
    GET    /api/alerts/<alert_id>        alert detail + notes
    PUT    /api/alerts/<alert_id>/status update status
    POST   /api/alerts/<alert_id>/notes  add an analyst note
    GET    /api/dashboard/stats          top cards
    GET    /api/dashboard/traffic        time-series for charts
    GET    /api/dashboard/alerts         alert breakdowns for charts
    GET    /api/rules                    list detection rules
    PUT    /api/rules/<rule_id>          enable/disable a rule
    GET    /api/incidents                correlated incidents
    POST   /api/simulate/tick            generate N synthetic flows server-side
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime

from flask import Blueprint, jsonify, request

from backend.database import db
from backend.models import Alert, IncidentNote, NetworkFlow, Rule
from config import ALERT_STATUSES, RULES
from ids.anomaly_detector import load_baseline
from ids.correlation import correlate_alerts
from ids.pipeline import process_flow
from ids.rule_engine import get_rules, set_rule_enabled
from ml.predict import load_model

api = Blueprint("api", __name__, url_prefix="/api")

# Loaded lazily on first request
_STATE: dict = {"baseline": None, "model": None, "loaded": False}


def _ensure_state() -> None:
    if _STATE["loaded"]:
        return
    _STATE["baseline"] = load_baseline()
    _STATE["model"] = load_model()
    _STATE["loaded"] = True


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _error(message: str, code: int = 400):
    return jsonify({"error": message, "status": code}), code


def _paginate(query, default_limit: int = 100, max_limit: int = 1000):
    try:
        limit = min(int(request.args.get("limit", default_limit)), max_limit)
        offset = max(int(request.args.get("offset", 0)), 0)
    except (TypeError, ValueError):
        limit, offset = default_limit, 0
    return query.limit(limit).offset(offset), limit, offset


def _persist_flow(result: dict, raw_flow: dict) -> NetworkFlow:
    f = result["features"]
    flow = NetworkFlow(
        flow_id=result["flow_id"],
        timestamp=f.get("timestamp") or datetime.utcnow().isoformat(),
        source_ip=f["source_ip"],
        destination_ip=f["destination_ip"],
        source_port=f["source_port"],
        destination_port=f["destination_port"],
        protocol=f["protocol"],
        packet_count=f["packet_count"],
        byte_count=f["byte_count"],
        duration_seconds=f["duration"],
        connection_count=f["connection_count"],
        failed_connection_count=f["failed_connection_count"],
        syn_count=f["syn_count"],
        rst_count=f["rst_count"],
        average_packet_size=f["average_packet_size"],
        unique_destination_ports=f["unique_destination_ports"],
        unique_destination_ips=f["unique_destination_ips"],
        bytes_per_second=f["bytes_per_second"],
        packets_per_second=f["packets_per_second"],
        failure_ratio=f["failure_ratio"],
        syn_ratio=f["syn_ratio"],
        connection_rate=f["connection_rate"],
        anomaly_score=result["anomaly"]["anomaly_score"],
        ml_score=round(result["ml_probability"] * 100, 2)
        if result["ml_probability"] is not None else None,
        risk_score=result["risk"]["risk_score"],
        classification=result["risk"]["classification"],
    )
    db.session.merge(flow)
    return flow


def _persist_alert(alert: dict) -> Alert:
    row = Alert(
        alert_id=alert["alert_id"],
        flow_id=alert["flow_id"],
        timestamp=alert["timestamp"],
        source_ip=alert["source_ip"],
        destination_ip=alert["destination_ip"],
        protocol=alert["protocol"],
        source_port=alert["source_port"],
        destination_port=alert["destination_port"],
        rule_id=alert["rule_id"],
        alert_type=alert["alert_type"],
        severity=alert["severity"],
        risk_score=alert["risk_score"],
        classification=alert["classification"],
        description=alert["description"],
        matched_rules=",".join(alert.get("matched_rules", [])),
        anomaly_score=alert.get("anomaly_score", 0.0),
        ml_score=alert.get("ml_score"),
        status=alert["status"],
    )
    db.session.merge(row)
    return row


# --------------------------------------------------------------------------
# Flows
# --------------------------------------------------------------------------

@api.post("/flows")
def ingest_flow():
    """Ingest one synthetic flow, run the full IDS pipeline, store results."""
    _ensure_state()

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _error("Request body must be a JSON object.", 400)

    if not payload.get("flow_id"):
        payload["flow_id"] = f"FLW-{datetime.utcnow().strftime('%H%M%S%f')}"

    if not payload.get("timestamp"):
        payload["timestamp"] = datetime.utcnow().isoformat(timespec="seconds")

    result = process_flow(payload, baseline=_STATE["baseline"],
                          ml_model=_STATE["model"])

    _persist_flow(result, payload)
    if result["alert"]:
        _persist_alert(result["alert"])
    db.session.commit()

    return jsonify({
        "flow_id": result["flow_id"],
        "risk_score": result["risk"]["risk_score"],
        "classification": result["risk"]["classification"],
        "severity": result["risk"]["severity"],
        "anomaly_score": result["anomaly"]["anomaly_score"],
        "ml_score": round(result["ml_probability"] * 100, 2)
        if result["ml_probability"] is not None else None,
        "matched_rules": [m["rule_id"] for m in result["rules"]["matches"]],
        "alert_id": result["alert"]["alert_id"] if result["alert"] else None,
        "validation_issues": result["features"]["validation_issues"],
    }), 201


@api.get("/flows")
def list_flows():
    query = NetworkFlow.query
    if request.args.get("classification"):
        query = query.filter_by(classification=request.args["classification"])
    if request.args.get("protocol"):
        query = query.filter_by(protocol=request.args["protocol"].upper())
    if request.args.get("source_ip"):
        query = query.filter_by(source_ip=request.args["source_ip"])

    query = query.order_by(NetworkFlow.created_at.desc())
    page, limit, offset = _paginate(query)
    items = [f.to_dict() for f in page.all()]
    return jsonify({"count": len(items), "limit": limit,
                    "offset": offset, "flows": items})


@api.get("/flows/<flow_id>")
def get_flow(flow_id: str):
    flow = db.session.get(NetworkFlow, flow_id)
    if not flow:
        return _error(f"Flow '{flow_id}' not found.", 404)
    data = flow.to_dict()
    data["alerts"] = [a.to_dict() for a in flow.alerts]
    return jsonify(data)


# --------------------------------------------------------------------------
# Alerts
# --------------------------------------------------------------------------

@api.get("/alerts")
def list_alerts():
    query = Alert.query
    if request.args.get("severity"):
        query = query.filter_by(severity=request.args["severity"].upper())
    if request.args.get("status"):
        query = query.filter_by(status=request.args["status"].upper())
    if request.args.get("alert_type"):
        query = query.filter_by(alert_type=request.args["alert_type"])
    if request.args.get("protocol"):
        query = query.filter_by(protocol=request.args["protocol"].upper())
    if request.args.get("source_ip"):
        query = query.filter_by(source_ip=request.args["source_ip"])

    query = query.order_by(Alert.created_at.desc())
    page, limit, offset = _paginate(query)
    items = [a.to_dict() for a in page.all()]
    return jsonify({"count": len(items), "limit": limit,
                    "offset": offset, "alerts": items})


@api.get("/alerts/<alert_id>")
def get_alert(alert_id: str):
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return _error(f"Alert '{alert_id}' not found.", 404)

    data = alert.to_dict()
    data["notes"] = [n.to_dict() for n in alert.notes]
    data["flow"] = alert.flow.to_dict() if alert.flow else None
    data["recommended_investigation_steps"] = [
        "Confirm whether the source IP is a known/approved internal asset.",
        "Compare the flow against the historical baseline for this source.",
        "Review authentication logs for the targeted service.",
        "Review firewall and proxy records for related activity.",
        "Check endpoint telemetry (EDR) for the destination host, if authorised.",
        "Determine whether a scheduled job, backup, or scanner explains the pattern.",
        "If unexplained, escalate and document findings in the incident notes.",
    ]
    return jsonify(data)


@api.put("/alerts/<alert_id>/status")
def update_alert_status(alert_id: str):
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return _error(f"Alert '{alert_id}' not found.", 404)

    body = request.get_json(silent=True) or {}
    new_status = str(body.get("status", "")).upper()

    if new_status not in ALERT_STATUSES:
        return _error(f"Invalid status. Allowed: {', '.join(ALERT_STATUSES)}", 422)

    alert.status = new_status

    if body.get("note"):
        db.session.add(IncidentNote(alert_id=alert_id,
                                    analyst=body.get("analyst", "analyst"),
                                    note=str(body["note"])[:4000]))
    db.session.commit()
    return jsonify({"alert_id": alert_id, "status": alert.status})


@api.post("/alerts/<alert_id>/notes")
def add_note(alert_id: str):
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return _error(f"Alert '{alert_id}' not found.", 404)

    body = request.get_json(silent=True) or {}
    text = str(body.get("note", "")).strip()
    if not text:
        return _error("Field 'note' is required and cannot be empty.", 422)

    note = IncidentNote(alert_id=alert_id,
                        analyst=str(body.get("analyst", "analyst"))[:80],
                        note=text[:4000])
    db.session.add(note)
    db.session.commit()
    return jsonify(note.to_dict()), 201


# --------------------------------------------------------------------------
# Dashboard
# --------------------------------------------------------------------------

@api.get("/dashboard/stats")
def dashboard_stats():
    total_flows = db.session.query(NetworkFlow).count()
    normal = db.session.query(NetworkFlow).filter_by(classification="NORMAL").count()
    suspicious = total_flows - normal
    open_alerts = db.session.query(Alert).filter(
        Alert.status.in_(["NEW", "INVESTIGATING"])).count()
    critical = db.session.query(Alert).filter_by(severity="CRITICAL").count()

    avg_risk = db.session.query(db.func.avg(NetworkFlow.risk_score)).scalar() or 0.0

    return jsonify({
        "total_flows": total_flows,
        "normal_traffic": normal,
        "suspicious_traffic": suspicious,
        "open_alerts": open_alerts,
        "critical_alerts": critical,
        "average_risk_score": round(float(avg_risk), 2),
    })


@api.get("/dashboard/traffic")
def dashboard_traffic():
    """Bucketed time series for the traffic-over-time chart."""
    flows = (NetworkFlow.query
             .order_by(NetworkFlow.created_at.asc())
             .limit(2000).all())

    buckets: dict[str, dict] = defaultdict(
        lambda: {"total": 0, "suspicious": 0, "risk_sum": 0.0})

    for f in flows:
        ts = f.timestamp or ""
        key = ts[:16] if len(ts) >= 16 else ts[:13]   # minute or hour bucket
        buckets[key]["total"] += 1
        if f.classification != "NORMAL":
            buckets[key]["suspicious"] += 1
        buckets[key]["risk_sum"] += float(f.risk_score or 0)

    series = [
        {
            "time": k,
            "total": v["total"],
            "suspicious": v["suspicious"],
            "avg_risk": round(v["risk_sum"] / v["total"], 2) if v["total"] else 0,
        }
        for k, v in sorted(buckets.items())
    ]
    return jsonify({"series": series[-60:]})


@api.get("/dashboard/alerts")
def dashboard_alerts():
    alerts = Alert.query.all()

    severity_counts = Counter(a.severity for a in alerts)
    type_counts = Counter(a.alert_type for a in alerts)
    protocol_counts = Counter(a.protocol for a in alerts)
    port_counts = Counter(str(a.destination_port) for a in alerts)
    source_counts = Counter(a.source_ip for a in alerts)
    status_counts = Counter(a.status for a in alerts)

    risk_hist = {"0-20": 0, "21-40": 0, "41-60": 0, "61-80": 0, "81-100": 0}
    for a in alerts:
        r = float(a.risk_score or 0)
        if r <= 20:
            risk_hist["0-20"] += 1
        elif r <= 40:
            risk_hist["21-40"] += 1
        elif r <= 60:
            risk_hist["41-60"] += 1
        elif r <= 80:
            risk_hist["61-80"] += 1
        else:
            risk_hist["81-100"] += 1

    return jsonify({
        "by_severity": dict(severity_counts),
        "by_type": dict(type_counts.most_common(8)),
        "by_protocol": dict(protocol_counts),
        "by_port": dict(port_counts.most_common(10)),
        "by_source_ip": dict(source_counts.most_common(10)),
        "by_status": dict(status_counts),
        "risk_histogram": risk_hist,
        "recent_alerts": [a.to_dict() for a in
                          sorted(alerts, key=lambda x: x.created_at or datetime.min,
                                 reverse=True)[:25]],
    })


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------

@api.get("/rules")
def list_rules():
    rules = Rule.query.all()
    if not rules:
        return jsonify({"rules": get_rules()})
    return jsonify({"rules": [r.to_dict() for r in rules]})


@api.put("/rules/<rule_id>")
def update_rule(rule_id: str):
    body = request.get_json(silent=True) or {}
    if "enabled" not in body:
        return _error("Field 'enabled' (boolean) is required.", 422)

    enabled = bool(body["enabled"])
    if not set_rule_enabled(rule_id, enabled):
        return _error(f"Rule '{rule_id}' not found.", 404)

    row = db.session.get(Rule, rule_id)
    if row:
        row.enabled = enabled
        db.session.commit()

    return jsonify({"rule_id": rule_id, "enabled": enabled})


# --------------------------------------------------------------------------
# Incidents
# --------------------------------------------------------------------------

@api.get("/incidents")
def list_incidents():
    alerts = [a.to_dict() for a in Alert.query.all()]
    result = correlate_alerts(alerts)
    return jsonify(result)


# --------------------------------------------------------------------------
# Server-side simulation tick (convenient for demos)
# --------------------------------------------------------------------------

@api.post("/simulate/tick")
def simulate_tick():
    _ensure_state()
    from simulator.traffic_simulator import build_flow

    body = request.get_json(silent=True) or {}
    count = min(int(body.get("count", 10)), 200)
    mode = body.get("mode", "mixed")

    created_alerts = []
    for _ in range(count):
        flow = build_flow(mode)
        result = process_flow(flow, baseline=_STATE["baseline"],
                              model_or_none=None) if False else \
            process_flow(flow, baseline=_STATE["baseline"], ml_model=_STATE["model"])
        _persist_flow(result, flow)
        if result["alert"]:
            _persist_alert(result["alert"])
            created_alerts.append(result["alert"]["alert_id"])
    db.session.commit()

    return jsonify({"processed": count, "alerts_created": len(created_alerts),
                    "alert_ids": created_alerts})


# --------------------------------------------------------------------------
# Rule seeding helper (called once at startup)
# --------------------------------------------------------------------------

def seed_rules() -> None:
    """Insert the default rules into the database if they are missing."""
    for rid, rule in RULES.items():
        if not db.session.get(Rule, rid):
            db.session.add(Rule(
                rule_id=rid,
                rule_name=rule["name"],
                description=rule["description"],
                severity=rule["severity"],
                threshold=json.dumps(rule["threshold"]),
                enabled=rule["enabled"],
            ))
    db.session.commit()