"""
generate_dataset.py
-------------------
Creates a synthetic network-flow dataset for defensive IDS development.

Every record represents a *summary* of a network conversation (a "flow").
No packets are generated, sent, captured, or replayed.

Scenario types (all represented purely as data):
    NORMAL_WEB, NORMAL_DNS, NORMAL_SSH, NORMAL_EMAIL, NORMAL_DATABASE
    HIGH_CONNECTION_RATE, REPEATED_FAILED_CONNECTIONS,
    MULTI_PORT_PROBING_PATTERN, SYN_HEAVY_PATTERN,
    UNUSUAL_PORT_ACTIVITY, HIGH_TRAFFIC_VOLUME

Usage:
    python -m simulator.generate_dataset
    python -m simulator.generate_dataset --count 20000
"""

from __future__ import annotations

import argparse
import ipaddress
import random
import uuid
from datetime import datetime, timedelta

import pandas as pd

from config import (
    CLIENT_NETS,
    DEFAULT_RECORD_COUNT,
    RANDOM_SEED,
    SERVER_NETS,
    DATASET_PATH,
)

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _random_ip(net_cidr: str) -> str:
    """Return a random usable host address inside a documentation CIDR range."""
    net = ipaddress.ip_network(net_cidr)
    offset = random.randint(1, net.num_addresses - 2)
    return str(net.network_address + offset)


def _client_ip() -> str:
    return _random_ip(random.choice(CLIENT_NETS))


def _server_ip() -> str:
    return _random_ip(random.choice(SERVER_NETS))


def _base_record(ts: datetime) -> dict:
    """Return a record pre-filled with sane defaults."""
    return {
        "flow_id": f"FLW-{uuid.uuid4().hex[:10].upper()}",
        "timestamp": ts.isoformat(timespec="seconds"),
        "source_ip": _client_ip(),
        "destination_ip": _server_ip(),
        "source_port": random.randint(49152, 65535),  # ephemeral
        "destination_port": 443,
        "protocol": "TCP",
        "packet_count": 10,
        "byte_count": 2000,
        "duration_seconds": 1.0,
        "connection_count": 1,
        "failed_connection_count": 0,
        "syn_count": 1,
        "rst_count": 0,
        "average_packet_size": 200.0,
        "unique_destination_ports": 1,
        "unique_destination_ips": 1,
        "label": "NORMAL",
        "scenario_type": "NORMAL_WEB",
    }


def _finalize(rec: dict) -> dict:
    """Recompute derived fields and clamp to valid ranges."""
    packets = max(int(rec["packet_count"]), 1)
    rec["average_packet_size"] = round(rec["byte_count"] / packets, 2)
    rec["duration_seconds"] = round(max(float(rec["duration_seconds"]), 0.001), 3)
    rec["source_port"] = int(rec["source_port"])
    rec["destination_port"] = int(rec["destination_port"])
    return rec


# --------------------------------------------------------------------------
# NORMAL scenarios
# --------------------------------------------------------------------------

def normal_web(ts: datetime) -> dict:
    r = _base_record(ts)
    r["scenario_type"] = "NORMAL_WEB"
    r["destination_port"] = random.choice([80, 443, 8080, 8443])
    r["packet_count"] = random.randint(12, 60)
    r["byte_count"] = r["packet_count"] * random.randint(200, 1400)
    r["duration_seconds"] = random.uniform(0.5, 6.0)
    r["connection_count"] = random.randint(1, 4)
    r["syn_count"] = r["connection_count"]
    r["unique_destination_ports"] = 1
    return _finalize(r)


def normal_dns(ts: datetime) -> dict:
    r = _base_record(ts)
    r["scenario_type"] = "NORMAL_DNS"
    r["protocol"] = "UDP"
    r["destination_port"] = 53
    r["packet_count"] = random.randint(2, 6)
    r["byte_count"] = r["packet_count"] * random.randint(60, 220)
    r["duration_seconds"] = random.uniform(0.01, 0.4)
    r["connection_count"] = 1
    r["syn_count"] = 0
    return _finalize(r)


def normal_ssh(ts: datetime) -> dict:
    r = _base_record(ts)
    r["scenario_type"] = "NORMAL_SSH"
    r["destination_port"] = 22
    r["packet_count"] = random.randint(40, 300)
    r["byte_count"] = r["packet_count"] * random.randint(80, 300)
    r["duration_seconds"] = random.uniform(10, 900)
    r["connection_count"] = random.randint(1, 3)
    r["syn_count"] = r["connection_count"]
    return _finalize(r)


def normal_email(ts: datetime) -> dict:
    r = _base_record(ts)
    r["scenario_type"] = "NORMAL_EMAIL"
    r["destination_port"] = random.choice([25, 465, 587, 993])
    r["packet_count"] = random.randint(20, 150)
    r["byte_count"] = r["packet_count"] * random.randint(200, 900)
    r["duration_seconds"] = random.uniform(1.0, 20.0)
    r["connection_count"] = random.randint(1, 3)
    r["syn_count"] = r["connection_count"]
    return _finalize(r)


def normal_database(ts: datetime) -> dict:
    r = _base_record(ts)
    r["scenario_type"] = "NORMAL_DATABASE"
    r["destination_port"] = random.choice([3306, 5432, 1433, 27017])
    r["packet_count"] = random.randint(15, 200)
    r["byte_count"] = r["packet_count"] * random.randint(150, 1200)
    r["duration_seconds"] = random.uniform(0.5, 15.0)
    r["connection_count"] = random.randint(1, 5)
    r["syn_count"] = r["connection_count"]
    return _finalize(r)


# --------------------------------------------------------------------------
# SUSPICIOUS scenarios (statistical patterns represented as DATA only)
# --------------------------------------------------------------------------

def high_connection_rate(ts: datetime) -> dict:
    r = _base_record(ts)
    r["scenario_type"] = "HIGH_CONNECTION_RATE"
    r["label"] = "SUSPICIOUS"
    r["destination_port"] = random.choice([80, 443, 8080])
    r["connection_count"] = random.randint(60, 400)
    r["packet_count"] = r["connection_count"] * random.randint(2, 5)
    r["byte_count"] = r["packet_count"] * random.randint(60, 200)
    r["duration_seconds"] = random.uniform(1.0, 5.0)
    r["syn_count"] = r["connection_count"]
    r["failed_connection_count"] = random.randint(0, 5)
    return _finalize(r)


def repeated_failed_connections(ts: datetime) -> dict:
    r = _base_record(ts)
    r["scenario_type"] = "REPEATED_FAILED_CONNECTIONS"
    r["label"] = "SUSPICIOUS"
    r["destination_port"] = random.choice([22, 3389, 21, 23])
    r["connection_count"] = random.randint(25, 150)
    r["failed_connection_count"] = random.randint(20, 140)
    r["packet_count"] = r["connection_count"] * random.randint(3, 6)
    r["byte_count"] = r["packet_count"] * random.randint(50, 120)
    r["duration_seconds"] = random.uniform(2.0, 30.0)
    r["syn_count"] = r["connection_count"]
    r["rst_count"] = r["failed_connection_count"]
    return _finalize(r)


def multi_port_probing_pattern(ts: datetime) -> dict:
    r = _base_record(ts)
    r["scenario_type"] = "MULTI_PORT_PROBING_PATTERN"
    r["label"] = "SUSPICIOUS"
    r["destination_port"] = random.randint(1, 1024)
    r["unique_destination_ports"] = random.randint(20, 800)
    r["unique_destination_ips"] = random.randint(1, 5)
    r["connection_count"] = r["unique_destination_ports"]
    r["packet_count"] = r["connection_count"] * 2
    r["byte_count"] = r["packet_count"] * random.randint(40, 90)
    r["duration_seconds"] = random.uniform(1.0, 20.0)
    r["syn_count"] = r["connection_count"]
    r["failed_connection_count"] = int(r["connection_count"] * 0.7)
    return _finalize(r)


def syn_heavy_pattern(ts: datetime) -> dict:
    r = _base_record(ts)
    r["scenario_type"] = "SYN_HEAVY_PATTERN"
    r["label"] = "SUSPICIOUS"
    r["destination_port"] = random.choice([80, 443, 8080])
    r["connection_count"] = random.randint(80, 500)
    r["syn_count"] = int(r["connection_count"] * random.uniform(0.9, 1.0))
    r["packet_count"] = r["syn_count"] + random.randint(0, 5)
    r["byte_count"] = r["packet_count"] * 60
    r["duration_seconds"] = random.uniform(0.5, 4.0)
    r["failed_connection_count"] = r["syn_count"] // 2
    return _finalize(r)


def unusual_port_activity(ts: datetime) -> dict:
    r = _base_record(ts)
    r["scenario_type"] = "UNUSUAL_PORT_ACTIVITY"
    r["label"] = "SUSPICIOUS"
    r["destination_port"] = random.choice([23, 445, 3389, 1433, 5900, 4444, 6667, 31337])
    r["connection_count"] = random.randint(5, 40)
    r["packet_count"] = r["connection_count"] * random.randint(4, 12)
    r["byte_count"] = r["packet_count"] * random.randint(80, 400)
    r["duration_seconds"] = random.uniform(1.0, 25.0)
    r["syn_count"] = r["connection_count"]
    r["failed_connection_count"] = random.randint(0, 8)
    return _finalize(r)


def high_traffic_volume(ts: datetime) -> dict:
    r = _base_record(ts)
    r["scenario_type"] = "HIGH_TRAFFIC_VOLUME"
    r["label"] = "SUSPICIOUS"
    r["destination_port"] = random.choice([80, 443, 8080])
    r["packet_count"] = random.randint(40_000, 200_000)
    r["byte_count"] = random.randint(6_000_000, 80_000_000)
    r["duration_seconds"] = random.uniform(5.0, 120.0)
    r["connection_count"] = random.randint(1, 10)
    r["syn_count"] = r["connection_count"]
    return _finalize(r)


# --------------------------------------------------------------------------
# Distribution
# --------------------------------------------------------------------------
NORMAL_SCENARIOS = [
    (normal_web, 0.45),
    (normal_dns, 0.15),
    (normal_ssh, 0.12),
    (normal_email, 0.13),
    (normal_database, 0.15),
]

SUSPICIOUS_SCENARIOS = [
    (high_connection_rate, 0.20),
    (repeated_failed_connections, 0.20),
    (multi_port_probing_pattern, 0.15),
    (syn_heavy_pattern, 0.15),
    (unusual_port_activity, 0.15),
    (high_traffic_volume, 0.15),
]


def _weighted_choice(pairs):
    funcs = [p[0] for p in pairs]
    weights = [p[1] for p in pairs]
    return random.choices(funcs, weights=weights, k=1)[0]


def generate_dataset(count: int = DEFAULT_RECORD_COUNT,
                     suspicious_ratio: float = 0.30,
                     seed: int = RANDOM_SEED) -> pd.DataFrame:
    """
    Build a synthetic dataset of network-flow records.

    Args:
        count: total number of flow records
        suspicious_ratio: fraction of records labelled SUSPICIOUS
        seed: RNG seed for reproducibility

    Returns:
        pandas.DataFrame with the IDS schema.
    """
    random.seed(seed)

    n_suspicious = int(count * suspicious_ratio)
    n_normal = count - n_suspicious

    start = datetime.now() - timedelta(hours=6)
    records: list[dict] = []

    for i in range(n_normal):
        ts = start + timedelta(seconds=i * random.uniform(1, 8))
        records.append(_weighted_choice(NORMAL_SCENARIOS)(ts))

    for i in range(n_suspicious):
        ts = start + timedelta(seconds=i * random.uniform(1, 8))
        records.append(_weighted_choice(SUSPICIOUS_SCENARIOS)(ts))

    random.shuffle(records)
    df = pd.DataFrame(records)

    column_order = [
        "flow_id", "timestamp", "source_ip", "destination_ip",
        "source_port", "destination_port", "protocol",
        "packet_count", "byte_count", "duration_seconds",
        "connection_count", "failed_connection_count",
        "syn_count", "rst_count", "average_packet_size",
        "unique_destination_ports", "unique_destination_ips",
        "label", "scenario_type",
    ]
    return df[column_order]


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic IDS dataset.")
    parser.add_argument("--count", type=int, default=DEFAULT_RECORD_COUNT)
    parser.add_argument("--suspicious-ratio", type=float, default=0.30)
    parser.add_argument("--out", type=str, default=str(DATASET_PATH))
    args = parser.parse_args()

    df = generate_dataset(args.count, args.suspicious_ratio)
    df.to_csv(args.out, index=False)

    print(f"[+] Wrote {len(df):,} synthetic flow records -> {args.out}")
    print(f"[+] Label distribution:\n{df['label'].value_counts().to_string()}")
    print(f"[+] Scenario distribution:\n{df['scenario_type'].value_counts().to_string()}")


if __name__ == "__main__":
    main()