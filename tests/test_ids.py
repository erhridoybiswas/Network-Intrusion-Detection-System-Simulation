"""
test_ids.py
-----------
Automated test suite for the Network IDS Simulation.

Run:
    pytest -v
"""

from __future__ import annotations

import pytest

from config import RULES
from ids.alert_engine import generate_alert
from ids.anomaly_detector import build_baseline, calculate_anomaly_score
from ids.correlation import correlate_alerts
from ids.feature_extractor import (extract_network_features, is_valid_ip,
                                   is_valid_port)
from ids.pipeline import process_flow
from ids.risk_engine import calculate_risk_score, classify_risk
from ids.rule_engine import analyze_flow, set_rule_enabled


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

def make_flow(**overrides) -> dict:
    base = {
        "flow_id": "FLW-TEST0001",
        "timestamp": "2025-01-15T10:00:00",
        "source_ip": "192.0.2.15",
        "destination_ip": "198.51.100.20",
        "source_port": 49152,
        "destination_port": 443,
        "protocol": "TCP",
        "packet_count": 18,
        "byte_count": 12400,
        "duration_seconds": 2.8,
        "connection_count": 3,
        "failed_connection_count": 0,
        "syn_count": 2,
        "rst_count": 0,
        "unique_destination_ports": 1,
        "unique_destination_ips": 1,
    }
    base.update(overrides)
    return base


@pytest.fixture(scope="module")
def baseline():
    normal = [
        extract_network_features(make_flow(
            packet_count=20, byte_count=15000, duration_seconds=3.0,
            connection_count=3, failed_connection_count=0,
            syn_count=3, unique_destination_ports=1))
        for _ in range(200)
    ]
    return build_baseline(normal)


# ==========================================================================
# 1-4: Normal traffic
# ==========================================================================

def test_01_normal_tcp_flow():
    f = extract_network_features(make_flow())
    assert f["protocol"] == "TCP"
    assert f["is_valid"] is True


def test_02_normal_udp_flow():
    f = extract_network_features(make_flow(protocol="UDP", destination_port=53,
                                           packet_count=4, byte_count=300))
    assert f["protocol"] == "UDP"
    assert f["is_valid"] is True


def test_03_normal_dns_flow():
    f = extract_network_features(make_flow(protocol="UDP", destination_port=53,
                                           packet_count=2, byte_count=120,
                                           duration_seconds=0.05))
    assert f["destination_port"] == 53
    assert f["packets_per_second"] > 0


def test_04_normal_https_flow_not_flagged():
    result = process_flow(make_flow())
    assert result["risk"]["classification"] == "NORMAL"
    assert result["alert"] is None


# ==========================================================================
# 5-9: Suspicious patterns
# ==========================================================================

def test_05_high_connection_rate_triggers_rule():
    f = extract_network_features(make_flow(
        connection_count=300, duration_seconds=2.0, syn_count=300))
    result = analyze_flow(f)
    assert "IDS-001" in [m["rule_id"] for m in result["matches"]]


def test_06_repeated_failed_connections_triggers_rule():
    f = extract_network_features(make_flow(
        connection_count=100, failed_connection_count=90,
        duration_seconds=10.0))
    result = analyze_flow(f)
    assert "IDS-002" in [m["rule_id"] for m in result["matches"]]


def test_07_multi_port_pattern_triggers_rule():
    f = extract_network_features(make_flow(
        unique_destination_ports=120, connection_count=120,
        duration_seconds=5.0))
    result = analyze_flow(f)
    assert "IDS-003" in [m["rule_id"] for m in result["matches"]]


def test_08_syn_heavy_pattern_triggers_rule():
    f = extract_network_features(make_flow(
        connection_count=200, syn_count=200, failed_connection_count=100,
        duration_seconds=2.0))
    result = analyze_flow(f)
    assert "IDS-004" in [m["rule_id"] for m in result["matches"]]


def test_09_high_traffic_volume_triggers_rule():
    f = extract_network_features(make_flow(
        byte_count=50_000_000, packet_count=100_000, duration_seconds=60))
    result = analyze_flow(f)
    assert "IDS-006" in [m["rule_id"] for m in result["matches"]]


# ==========================================================================
# 10-14: Input validation
# ==========================================================================

def test_10_invalid_source_ip():
    assert is_valid_ip("999.999.999.999") is False
    f = extract_network_features(make_flow(source_ip="999.1.1.1"))
    assert "invalid_source_ip" in f["validation_issues"]


def test_11_invalid_destination_ip():
    f = extract_network_features(make_flow(destination_ip="not-an-ip"))
    assert "invalid_destination_ip" in f["validation_issues"]


def test_12_invalid_source_port():
    assert is_valid_port(70000) is False
    f = extract_network_features(make_flow(source_port=70000))
    assert "invalid_source_port" in f["validation_issues"]


def test_13_invalid_destination_port():
    f = extract_network_features(make_flow(destination_port=-5))
    assert "invalid_destination_port" in f["validation_issues"]


def test_14_unsupported_protocol():
    f = extract_network_features(make_flow(protocol="SCTP"))
    assert f["protocol"] == "OTHER"
    assert "unsupported_protocol" in f["validation_issues"]


# ==========================================================================
# 15-20: Feature engineering
# ==========================================================================

def test_15_missing_packet_count():
    f = extract_network_features(make_flow(packet_count=None))
    assert f["packet_count"] == 0
    assert "missing_packet_count" in f["validation_issues"]


def test_16_zero_duration_no_crash():
    f = extract_network_features(make_flow(duration_seconds=0))
    assert f["duration"] == 0.0
    assert f["bytes_per_second"] > 0          # epsilon denominator
    assert f["bytes_per_second"] < float("inf")


def test_17_feature_extraction_math():
    f = extract_network_features(make_flow(
        byte_count=1000, packet_count=10, duration_seconds=2.0,
        connection_count=4, failed_connection_count=2, syn_count=2))
    assert f["bytes_per_second"] == 500.0
    assert f["packets_per_second"] == 5.0
    assert f["average_packet_size"] == 100.0
    assert f["failure_ratio"] == 0.5
    assert f["syn_ratio"] == 0.5
    assert f["connection_rate"] == 2.0


def test_18_no_rule_match_on_normal_flow():
    f = extract_network_features(make_flow())
    result = analyze_flow(f)
    assert result["matches"] == []
    assert result["rule_score"] == 0.0


def test_19_anomaly_score_in_range(baseline):
    f = extract_network_features(make_flow())
    result = calculate_anomaly_score(f, baseline)
    assert 0.0 <= result["anomaly_score"] <= 100.0


def test_20_anomaly_flags_extreme_flow(baseline):
    normal = extract_network_features(make_flow())
    extreme = extract_network_features(make_flow(
        connection_count=500, packet_count=5000, byte_count=9_000_000,
        duration_seconds=1.0, unique_destination_ports=500))
    assert (calculate_anomaly_score(extreme, baseline)["anomaly_score"]
            > calculate_anomaly_score(normal, baseline)["anomaly_score"])


# ==========================================================================
# 21-24: Risk, alerts, correlation, status
# ==========================================================================

def test_21_risk_score_bounds(baseline):
    f = extract_network_features(make_flow(
        connection_count=400, failed_connection_count=380,
        duration_seconds=2.0, syn_count=400))
    rules = analyze_flow(f)
    anom = calculate_anomaly_score(f, baseline)
    risk = calculate_risk_score(rules, anom, ml_probability=0.9)
    assert 0.0 <= risk["risk_score"] <= 100.0


def test_22_classification_bands():
    assert classify_risk(10) == "NORMAL"
    assert classify_risk(30) == "LOW RISK"
    assert classify_risk(50) == "SUSPICIOUS"
    assert classify_risk(70) == "HIGH RISK"
    assert classify_risk(95) == "CRITICAL INVESTIGATION"


def test_23_alert_generation():
    f = extract_network_features(make_flow(
        connection_count=300, syn_count=300, duration_seconds=1.0))
    rules = analyze_flow(f)
    anom = {"anomaly_score": 60.0, "components": {}, "top_feature": "connection_rate"}
    risk = calculate_risk_score(rules, anom, None)
    alert = generate_alert("FLW-X", f, rules, anom, risk, None)
    assert alert is not None
    assert alert["status"] == "NEW"
    assert alert["risk_score"] > 0


def test_24_no_alert_for_normal_flow():
    f = extract_network_features(make_flow())
    rules = analyze_flow(f)
    anom = {"anomaly_score": 5.0, "components": {}, "top_feature": None}
    risk = calculate_risk_score(rules, anom, None)
    assert generate_alert("FLW-Y", f, rules, anom, risk, None) is None


# ==========================================================================
# 25-27: Correlation
# ==========================================================================

def test_25_correlation_groups_alerts():
    alerts = [
        {"alert_id": f"A{i}", "source_ip": "192.0.2.15",
         "alert_type": "High Connection Rate", "timestamp": f"2025-01-15T10:00:{i:02d}",
         "severity": "HIGH", "risk_score": 75}
        for i in range(5)
    ]
    result = correlate_alerts(alerts, window_seconds=60, min_alerts=3)
    assert len(result["incidents"]) == 1
    assert result["incidents"][0]["alert_count"] == 5


def test_26_correlation_keeps_singletons_separate():
    alerts = [
        {"alert_id": "A1", "source_ip": "192.0.2.1",
         "alert_type": "High Connection Rate", "timestamp": "2025-01-15T10:00:00",
         "severity": "HIGH", "risk_score": 75},
        {"alert_id": "A2", "source_ip": "192.0.2.2",
         "alert_type": "High Connection Rate", "timestamp": "2025-01-15T10:00:30",
         "severity": "HIGH", "risk_score": 75},
    ]
    result = correlate_alerts(alerts, window_seconds=60, min_alerts=3)
    assert len(result["incidents"]) == 0
    assert len(result["standalone_alerts"]) == 2


def test_27_correlation_empty_input():
    result = correlate_alerts([])
    assert result == []


# ==========================================================================
# 28-30: Rules configuration
# ==========================================================================

def test_28_all_rules_registered():
    assert len(RULES) == 6
    for rid in ["IDS-001", "IDS-002", "IDS-003",
                "IDS-004", "IDS-005", "IDS-006"]:
        assert rid in RULES


def test_29_rule_can_be_disabled():
    set_rule_enabled("IDS-005", False)
    f = extract_network_features(make_flow(destination_port=4444))
    result = analyze_flow(f)
    assert "IDS-005" not in [m["rule_id"] for m in result["matches"]]
    set_rule_enabled("IDS-005", True)   # restore


def test_30_rule_reenabled_works():
    set_rule_enabled("IDS-005", True)
    f = extract_network_features(make_flow(destination_port=4444))
    result = analyze_flow(f)
    assert "IDS-005" in [m["rule_id"] for m in result["matches"]]


# ==========================================================================
# 31-35: Pipeline integration
# ==========================================================================

def test_31_pipeline_normal_flow(baseline):
    result = process_flow(make_flow(), baseline=baseline)
    assert result["risk"]["classification"] == "NORMAL"


def test_32_pipeline_suspicious_flow(baseline):
    flow = make_flow(connection_count=400, failed_connection_count=380,
                     syn_count=400, duration_seconds=2.0,
                     unique_destination_ports=300, packet_count=2000,
                     byte_count=8_000_000, destination_port=445)
    result = process_flow(flow, baseline=baseline)
    assert result["risk"]["risk_score"] > 40
    assert result["alert"] is not None


def test_33_pipeline_handles_garbage_input(baseline):
    result = process_flow({"flow_id": "BAD", "source_ip": "xxx",
                           "packet_count": "abc"}, baseline=baseline)
    assert result["features"]["validation_issues"]
    assert 0.0 <= result["risk"]["risk_score"] <= 100.0


def test_34_pipeline_with_ml_probability(baseline):
    class FakeModel:
        def predict_probability(self, features):
            return 0.85
    flow = make_flow(connection_count=100, failed_connection_count=90,
                     duration_seconds=5.0)
    result = process_flow(flow, baseline=baseline, ml_model=FakeModel())
    assert result["ml_probability"] == 0.85
    assert result["risk"]["components"]["ml_enabled"] is True


def test_35_risk_weights_switch_without_ml(baseline):
    f = extract_network_features(make_flow(connection_count=300,
                                           syn_count=300, duration_seconds=1.0))
    rules = analyze_flow(f)
    anom = calculate_anomaly_score(f, baseline)
    with_ml = calculate_risk_score(rules, anom, ml_probability=0.5)
    without_ml = calculate_risk_score(rules, anom, ml_probability=None)
    assert with_ml["weights"]["ml"] == 0.30
    assert without_ml["weights"]["ml"] == 0.0
    assert without_ml["weights"]["rule"] == 0.60