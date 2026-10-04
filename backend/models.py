"""
models.py
---------
Database schema for the IDS.

Relationships:
    NETWORK_FLOWS 1 --- N ALERTS        (one flow can raise several alerts)
    ALERTS        1 --- N INCIDENT_NOTES
    NETWORK_FLOWS 1 --- N MODEL_RESULTS

Indexes are placed on the columns analysts filter by most often:
    timestamp, severity, status, source_ip.
"""

from __future__ import annotations

from datetime import datetime, timezone

from backend.database import db


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class NetworkFlow(db.Model):
    __tablename__ = "network_flows"

    flow_id = db.Column(db.String(32), primary_key=True)
    timestamp = db.Column(db.String(40), index=True)
    source_ip = db.Column(db.String(45), index=True)
    destination_ip = db.Column(db.String(45))
    source_port = db.Column(db.Integer)
    destination_port = db.Column(db.Integer, index=True)
    protocol = db.Column(db.String(10), index=True)

    packet_count = db.Column(db.Integer)
    byte_count = db.Column(db.BigInteger)
    duration_seconds = db.Column(db.Float)
    connection_count = db.Column(db.Integer)
    failed_connection_count = db.Column(db.Integer)
    syn_count = db.Column(db.Integer)
    rst_count = db.Column(db.Integer)
    average_packet_size = db.Column(db.Float)
    unique_destination_ports = db.Column(db.Integer)
    unique_destination_ips = db.Column(db.Integer)

    bytes_per_second = db.Column(db.Float)
    packets_per_second = db.Column(db.Float)
    failure_ratio = db.Column(db.Float)
    syn_ratio = db.Column(db.Float)
    connection_rate = db.Column(db.Float)

    anomaly_score = db.Column(db.Float, default=0.0)
    ml_score = db.Column(db.Float, nullable=True)
    risk_score = db.Column(db.Float, index=True, default=0.0)
    classification = db.Column(db.String(32), index=True, default="NORMAL")

    created_at = db.Column(db.DateTime, default=_utcnow)

    alerts = db.relationship("Alert", backref="flow", lazy=True)

    def to_dict(self) -> dict:
        return {
            "flow_id": self.flow_id,
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "duration_seconds": self.duration_seconds,
            "connection_count": self.connection_count,
            "failed_connection_count": self.failed_connection_count,
            "syn_count": self.syn_count,
            "rst_count": self.rst_count,
            "average_packet_size": self.average_packet_size,
            "unique_destination_ports": self.unique_destination_ports,
            "unique_destination_ips": self.unique_destination_ips,
            "bytes_per_second": self.bytes_per_second,
            "packets_per_second": self.packets_per_second,
            "failure_ratio": self.failure_ratio,
            "syn_ratio": self.syn_ratio,
            "connection_rate": self.connection_rate,
            "anomaly_score": self.anomaly_score,
            "ml_score": self.ml_score,
            "risk_score": self.risk_score,
            "classification": self.classification,
        }


class Alert(db.Model):
    __tablename__ = "alerts"

    alert_id = db.Column(db.String(32), primary_key=True)
    flow_id = db.Column(db.String(32), db.ForeignKey("network_flows.flow_id"),
                        index=True)
    timestamp = db.Column(db.String(40), index=True)
    source_ip = db.Column(db.String(45), index=True)
    destination_ip = db.Column(db.String(45))
    protocol = db.Column(db.String(10))
    source_port = db.Column(db.Integer)
    destination_port = db.Column(db.Integer)

    rule_id = db.Column(db.String(16), index=True)
    alert_type = db.Column(db.String(80), index=True)
    severity = db.Column(db.String(16), index=True)
    risk_score = db.Column(db.Float, index=True)
    classification = db.Column(db.String(32))
    description = db.Column(db.Text)
    matched_rules = db.Column(db.String(255))
    anomaly_score = db.Column(db.Float)
    ml_score = db.Column(db.Float, nullable=True)

    status = db.Column(db.String(20), index=True, default="NEW")
    created_at = db.Column(db.DateTime, default=_utcnow)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow)

    notes = db.relationship("IncidentNote", backref="alert", lazy=True,
                            cascade="all, delete-orphan")

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "flow_id": self.flow_id,
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "protocol": self.protocol,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "rule_id": self.rule_id,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "classification": self.classification,
            "description": self.description,
            "matched_rules": (self.matched_rules or "").split(",") if self.matched_rules else [],
            "anomaly_score": self.anomaly_score,
            "ml_score": self.ml_score,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Rule(db.Model):
    __tablename__ = "rules"

    rule_id = db.Column(db.String(16), primary_key=True)
    rule_name = db.Column(db.String(80))
    description = db.Column(db.Text)
    severity = db.Column(db.String(16))
    threshold = db.Column(db.Text)          # JSON string
    enabled = db.Column(db.Boolean, default=True)

    def to_dict(self) -> dict:
        import json
        return {
            "rule_id": self.rule_id,
            "name": self.rule_name,
            "description": self.description,
            "severity": self.severity,
            "threshold": json.loads(self.threshold) if self.threshold else {},
            "enabled": self.enabled,
        }


class IncidentNote(db.Model):
    __tablename__ = "incident_notes"

    note_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    alert_id = db.Column(db.String(32), db.ForeignKey("alerts.alert_id"),
                         index=True)
    analyst = db.Column(db.String(80), default="analyst")
    note = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=_utcnow)

    def to_dict(self) -> dict:
        return {
            "note_id": self.note_id,
            "alert_id": self.alert_id,
            "analyst": self.analyst,
            "note": self.note,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ModelResult(db.Model):
    __tablename__ = "model_results"

    result_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    flow_id = db.Column(db.String(32), db.ForeignKey("network_flows.flow_id"),
                        index=True)
    model_name = db.Column(db.String(64))
    prediction = db.Column(db.Integer)
    score = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=_utcnow)