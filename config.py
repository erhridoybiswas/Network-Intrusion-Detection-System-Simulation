"""
config.py
---------
Central configuration for the Network IDS Simulation.

Everything tunable lives here so that detection thresholds can be adjusted
without touching detection logic (a core SOC/detection-engineering principle).

NOTE: All thresholds below are PROJECT ASSUMPTIONS. In a real SOC they would
be calibrated against weeks of baseline traffic and reviewed regularly.
"""

import os
from pathlib import Path

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "models"
REPORT_DIR = BASE_DIR / "reports"
FRONTEND_DIR = BASE_DIR / "frontend"

for _d in (DATA_DIR, MODEL_DIR, REPORT_DIR):
    _d.mkdir(parents=True, exist_ok=True)

DATASET_PATH = DATA_DIR / "network_traffic.csv"
BASELINE_PATH = DATA_DIR / "baseline.json"
DB_PATH = DATA_DIR / "ids.db"
ML_MODEL_PATH = MODEL_DIR / "ids_model.joblib"

# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------
DATABASE_URL = os.getenv("IDS_DATABASE_URL", f"sqlite:///{DB_PATH}")

# --------------------------------------------------------------------------
# Synthetic data generation
# --------------------------------------------------------------------------
DEFAULT_RECORD_COUNT = 5000
RANDOM_SEED = 42

# RFC 5737 documentation ranges - SAFE, never routable on the public internet
CLIENT_NETS = ["192.0.2.0/24", "198.51.100.0/24"]
SERVER_NETS = ["203.0.113.0/24"]

# --------------------------------------------------------------------------
# Feature engineering
# --------------------------------------------------------------------------
MAX_REASONABLE_PORT = 65535
VALID_PROTOCOLS = {"TCP", "UDP", "ICMP", "OTHER"}

# --------------------------------------------------------------------------
# Rule-based (signature) detection thresholds
# --------------------------------------------------------------------------
RULE_THRESHOLDS = {
    "IDS-001": {"connection_rate": 20.0},      # connections per second
    "IDS-002": {"failed_connections": 10, "failure_ratio": 0.60},
    "IDS-003": {"unique_destination_ports": 15},
    "IDS-004": {"syn_ratio": 0.80, "syn_count": 20},
    "IDS-005": {"unusual_ports": [23, 445, 3389, 1433, 5900, 4444, 6667, 31337]},
    "IDS-006": {"byte_count": 5_000_000},      # ~5 MB in a single flow record
}

# Rule registry. `enabled` can be toggled at runtime via the REST API.
RULES = {
    "IDS-001": {
        "rule_id": "IDS-001",
        "name": "High Connection Rate",
        "severity": "HIGH",
        "threshold": RULE_THRESHOLDS["IDS-001"],
        "description": "Connection rate significantly exceeded the configured baseline.",
        "enabled": True,
    },
    "IDS-002": {
        "rule_id": "IDS-002",
        "name": "Repeated Failed Connections",
        "severity": "HIGH",
        "threshold": RULE_THRESHOLDS["IDS-002"],
        "description": "Many failed connections from the same source, consistent with repeated authentication attempts.",
        "enabled": True,
    },
    "IDS-003": {
        "rule_id": "IDS-003",
        "name": "Multi-Port Access Pattern",
        "severity": "MEDIUM",
        "threshold": RULE_THRESHOLDS["IDS-003"],
        "description": "Single source contacted an unusually large number of destination ports.",
        "enabled": True,
    },
    "IDS-004": {
        "rule_id": "IDS-004",
        "name": "SYN-Heavy Connection Behaviour",
        "severity": "HIGH",
        "threshold": RULE_THRESHOLDS["IDS-004"],
        "description": "Predominance of SYN flags with no completed handshake pattern.",
        "enabled": True,
    },
    "IDS-005": {
        "rule_id": "IDS-005",
        "name": "Unusual Service-Port Activity",
        "severity": "MEDIUM",
        "threshold": RULE_THRESHOLDS["IDS-005"],
        "description": "Traffic directed at a service port that is not expected in this environment.",
        "enabled": True,
    },
    "IDS-006": {
        "rule_id": "IDS-006",
        "name": "Abnormally High Traffic Volume",
        "severity": "MEDIUM",
        "threshold": RULE_THRESHOLDS["IDS-006"],
        "description": "Byte volume in a single flow far exceeded the normal baseline.",
        "enabled": True,
    },
}

# Severity -> numeric contribution used by the risk engine
SEVERITY_SCORE = {
    "INFO": 20,
    "LOW": 40,
    "MEDIUM": 60,
    "HIGH": 80,
    "CRITICAL": 100,
}

# --------------------------------------------------------------------------
# Anomaly detection
# --------------------------------------------------------------------------
ANOMALY_FEATURES = [
    "packets_per_second",
    "bytes_per_second",
    "connection_rate",
    "failure_ratio",
    "unique_destination_ports",
    "syn_ratio",
]

# Z-score at or above this is treated as a full-strength anomaly (score 100)
ANOMALY_Z_CAP = 5.0

# --------------------------------------------------------------------------
# Hybrid risk engine
# --------------------------------------------------------------------------
# Weights must sum to 1.0
RISK_WEIGHTS_WITH_ML = {"rule": 0.40, "anomaly": 0.30, "ml": 0.30}
RISK_WEIGHTS_NO_ML = {"rule": 0.60, "anomaly": 0.40, "ml": 0.00}

# Risk score -> classification bands (PROJECT ASSUMPTIONS - calibrate in real SOC)
RISK_BANDS = [
    (0, 20, "NORMAL"),
    (21, 40, "LOW RISK"),
    (41, 60, "SUSPICIOUS"),
    (61, 80, "HIGH RISK"),
    (81, 100, "CRITICAL INVESTIGATION"),
]

# --------------------------------------------------------------------------
# Alerting / correlation
# --------------------------------------------------------------------------
CORRELATION_WINDOW_SECONDS = 60     # group alerts within this window
CORRELATION_MIN_ALERTS = 3          # >= this many -> becomes an incident

ALERT_STATUSES = ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]

# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------
API_HOST = os.getenv("IDS_API_HOST", "127.0.0.1")
API_PORT = int(os.getenv("IDS_API_PORT", "5000"))
API_DEBUG = os.getenv("IDS_API_DEBUG", "true").lower() == "true"