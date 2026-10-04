"""
feature_extractor.py
--------------------
Turns a raw network-flow record into a validated, engineered feature vector.

Feature engineering is where raw telemetry becomes *security-meaningful*.
Each feature below has a direct investigative purpose.

Cybersecurity relevance of each feature:
  packet_count            - Volume indicator; huge values can indicate bulk transfer/exfil.
  byte_count              - Same, weighted by size; useful for data-transfer anomalies.
  duration                - Long flows can indicate tunnelling or bulk transfer.
  bytes_per_second        - Rate feature; normalises volume across flow durations.
  packets_per_second      - Rate feature; sharp spikes suggest automated tooling.
  average_packet_size     - Unusually small = likely control/scan traffic.
                            Unusually large = possible bulk transfer.
  connection_count        - Core volume metric; drives connection-rate rules.
  failed_connection_count - Strong signal of brute force / misconfiguration.
  failure_ratio           - Normalised failure metric; robust across environments.
  syn_count               - Connection-initiation count.
  rst_count               - Abrupt resets; can indicate refused/rejected connections.
  syn_ratio               - High ratio = handshakes started but not completed.
  unique_destination_ports- Port diversity; high value suggests service discovery.
  unique_destination_ips  - Fan-out indicator; high value suggests sweep behaviour.
  connection_rate         - Connections per second; core rate-based detection metric.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from config import MAX_REASONABLE_PORT, VALID_PROTOCOLS

# --------------------------------------------------------------------------
# Safe coercion helpers
# --------------------------------------------------------------------------

def _safe_float(value: Any, default: float = 0.0) -> float:
    """Convert to float, returning `default` on any failure."""
    if value is None:
        return default
    try:
        result = float(value)
    except (TypeError, ValueError):
        return default
    if result != result or result in (float("inf"), float("-inf")):  # NaN/inf
        return default
    return result


def _safe_int(value: Any, default: int = 0) -> int:
    """Convert to int, returning `default` on any failure."""
    if value is None:
        return default
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def is_valid_ip(value: Any) -> bool:
    """True if `value` is a syntactically valid IPv4/IPv6 address."""
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def is_valid_port(value: Any) -> bool:
    """True if `value` is a valid TCP/UDP port number."""
    port = _safe_int(value, default=-1)
    return 0 <= port <= MAX_REASONABLE_PORT


def _normalise_protocol(value: Any) -> str:
    """Uppercase and validate the protocol field."""
    proto = str(value or "").strip().upper()
    if proto not in VALID_PROTOCOLS:
        return "OTHER"
    return proto


def _safe_divide(numerator: float, denominator: float,
                 default: float = 0.0) -> float:
    """Division that never raises ZeroDivisionError."""
    if denominator == 0:
        return default
    try:
        result = numerator / denominator
    except (ZeroDivisionError, TypeError):
        return default
    if result != result or result in (float("inf"), float("-inf")):
        return default
    return result


# --------------------------------------------------------------------------
# Main extractor
# --------------------------------------------------------------------------

def extract_network_features(flow: dict) -> dict:
    """
    Convert a raw flow dict into an engineered feature dict.

    Always returns a complete dict. Invalid inputs are recorded in
    `validation_issues` rather than raising exceptions, so the pipeline
    keeps running (important for a monitoring system).

    Args:
        flow: raw flow record

    Returns:
        dict containing cleaned raw fields, engineered features,
        validation flags and the derived `connection_rate`.
    """
    if not isinstance(flow, dict):
        flow = {}

    issues: list[str] = []

    # ---------------- Raw / cleaned fields ----------------
    source_ip = str(flow.get("source_ip", "")).strip()
    destination_ip = str(flow.get("destination_ip", "")).strip()

    if not is_valid_ip(source_ip):
        issues.append("invalid_source_ip")
        source_ip = "0.0.0.0"
    if not is_valid_ip(destination_ip):
        issues.append("invalid_destination_ip")
        destination_ip = "0.0.0.0"

    source_port = _safe_int(flow.get("source_port"), 0)
    destination_port = _safe_int(flow.get("destination_port"), 0)

    if not is_valid_port(source_port):
        issues.append("invalid_source_port")
        source_port = 0
    if not is_valid_port(destination_port):
        issues.append("invalid_destination_port")
        destination_port = 0

    protocol_raw = flow.get("protocol")
    protocol = _normalise_protocol(protocol_raw)
    if protocol == "OTHER" and str(protocol_raw or "").upper() not in VALID_PROTOCOLS:
        issues.append("unsupported_protocol")

    if flow.get("packet_count") is None:
        issues.append("missing_packet_count")
    if flow.get("byte_count") is None:
        issues.append("missing_byte_count")

    packet_count = max(_safe_int(flow.get("packet_count"), 0), 0)
    byte_count = max(_safe_int(flow.get("byte_count"), 0), 0)
    duration = _safe_float(flow.get("duration_seconds"), 0.0)
    if duration <= 0:
        issues.append("non_positive_duration")
        duration = 0.0

    connection_count = max(_safe_int(flow.get("connection_count"), 0), 0)
    failed_connection_count = max(
        _safe_int(flow.get("failed_connection_count"), 0), 0)
    syn_count = max(_safe_int(flow.get("syn_count"), 0), 0)
    rst_count = max(_safe_int(flow.get("rst_count"), 0), 0)

    unique_destination_ports = max(
        _safe_int(flow.get("unique_destination_ports"), 1), 0)
    unique_destination_ips = max(
        _safe_int(flow.get("unique_destination_ips"), 1), 0)

    # failed connections can never exceed total connections
    if connection_count and failed_connection_count > connection_count:
        failed_connection_count = connection_count
        issues.append("failed_exceeds_total_connections")

    # ---------------- Derived features ----------------
    # Use a tiny epsilon denominator so that zero-duration flows produce
    # large-but-finite rates instead of Infinity (which breaks models).
    rate_denominator = duration if duration > 0 else 0.001

    bytes_per_second = _safe_divide(byte_count, rate_denominator)
    packets_per_second = _safe_divide(packet_count, rate_denominator)
    average_packet_size = _safe_divide(byte_count, packet_count, 0.0)
    failure_ratio = _safe_divide(failed_connection_count, connection_count, 0.0)
    syn_ratio = _safe_divide(syn_count, connection_count, 0.0)
    connection_rate = _safe_divide(connection_count, rate_denominator)

    features = {
        # --- cleaned raw ---
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": protocol,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration": duration,
        "connection_count": connection_count,
        "failed_connection_count": failed_connection_count,
        "syn_count": syn_count,
        "rst_count": rst_count,
        "unique_destination_ports": unique_destination_ports,
        "unique_destination_ips": unique_destination_ips,

        # --- engineered ---
        "bytes_per_second": round(bytes_per_second, 4),
        "packets_per_second": round(packets_per_second, 4),
        "average_packet_size": round(average_packet_size, 4),
        "failure_ratio": round(failure_ratio, 4),
        "syn_ratio": round(syn_ratio, 4),
        "connection_rate": round(connection_rate, 4),

        # --- metadata ---
        "validation_issues": issues,
        "is_valid": len(issues) == 0,
    }
    return features


# Feature columns used by the ML models
ML_FEATURE_COLUMNS = [
    "packet_count",
    "byte_count",
    "duration",
    "bytes_per_second",
    "packets_per_second",
    "connection_count",
    "failed_connection_count",
    "syn_count",
    "rst_count",
    "average_packet_size",
]