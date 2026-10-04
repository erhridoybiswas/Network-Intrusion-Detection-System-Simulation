# Network Intrusion Detection System (IDS) Simulation

> A defensive, industry-oriented IDS simulation built with Python, Flask,
> SQLite and Chart.js. Generates synthetic network-flow records, applies
> signature + anomaly + optional ML detection, produces risk-scored alerts,
> correlates them into incidents, and presents everything on a SOC dashboard.

---

## ⚠️ Ethical Disclaimer

This project is designed **exclusively for defensive cybersecurity education**.
All suspicious network behavior is represented using **synthetic data** or
**authorized isolated lab environments**. It does **not** scan, probe,
exploit, disrupt, or attack any system. No packets are ever transmitted.

---

## Overview

Traditional IDS education often requires a lab with real network traffic.
This project removes that barrier: it **simulates** network flows as data
records and runs a complete detection pipeline against them, so a student
can learn and demonstrate real IDS engineering without touching any network.

## Problem Statement

Security Operations Centers receive enormous volumes of network telemetry.
Distinguishing normal from suspicious activity requires:

- Feature engineering from raw flow data
- Multiple complementary detection methods
- Risk prioritisation so analysts focus on what matters
- Correlation to avoid alert fatigue
- Investigation workflow and documentation

This project implements all of the above in a safe, reproducible way.

## Objectives

1. Generate realistic synthetic network-flow data
2. Extract security-relevant features
3. Apply signature-based detection (6 configurable rules)
4. Apply statistical anomaly detection (Z-score + IQR)
5. Optionally apply machine learning (Logistic Regression, Random Forest, Isolation Forest)
6. Combine signals into a hybrid 0–100 risk score
7. Generate severity-classified alerts
8. Correlate alerts into incidents
9. Persist everything in a database
10. Provide a SOC dashboard for triage and investigation

## Cybersecurity Relevance

Demonstrates: network security · intrusion detection · traffic analysis ·
security monitoring · signature detection · anomaly detection · feature
engineering · security analytics · alert management · SOC concepts ·
machine learning · secure coding.

## IDS Concepts

| Term | Meaning |
|---|---|
| IDS | Detects and alerts; does not block |
| IPS | Detects and can block inline |
| NIDS | Monitors network traffic |
| HIDS | Monitors a single host |
| Signature detection | Matches known patterns |
| Anomaly detection | Flags deviations from baseline |
| Hybrid | Combines both (+ ML) |

## Architecture
Synthetic Traffic Generator
↓
Flow Collector (POST /api/flows)
↓
Feature Extractor
↓
┌────────┼─────────┐
↓ ↓ ↓
Rules Anomaly ML
Engine Detector Model
└────────┼─────────┘
↓
Risk Engine
↓
Alert Engine
↓
Security Database
↓
SOC Dashboard
↓
Analyst

## Technology Stack

| Layer | Technology |
|---|---|
| Language | Python 3.10+ |
| Backend | Flask, SQLAlchemy |
| Database | SQLite |
| Data | pandas, NumPy |
| ML | scikit-learn, joblib |
| Frontend | HTML, CSS, vanilla JS, Chart.js |
| Testing | pytest |

## Synthetic Dataset

- 5,000+ records by default
- RFC 5737 documentation IP ranges only
- Columns: `flow_id, timestamp, source_ip, destination_ip, source_port, destination_port, protocol, packet_count, byte_count, duration_seconds, connection_count, failed_connection_count, syn_count, rst_count, average_packet_size, unique_destination_ports, unique_destination_ips, label, scenario_type`
- Labels: `NORMAL`, `SUSPICIOUS`
- Scenarios: `NORMAL_WEB`, `NORMAL_DNS`, `NORMAL_SSH`, `NORMAL_EMAIL`, `NORMAL_DATABASE`, `HIGH_CONNECTION_RATE`, `REPEATED_FAILED_CONNECTIONS`, `MULTI_PORT_PROBING_PATTERN`, `SYN_HEAVY_PATTERN`, `UNUSUAL_PORT_ACTIVITY`, `HIGH_TRAFFIC_VOLUME`

## Traffic Simulator

```bash
python -m simulator.traffic_simulator --mode mixed --speed fast --sink api
Emits synthetic flow dictionaries. Never sends packets.

Feature Engineering
Feature	Security Relevance
packet_count	Volume indicator
byte_count	Data transfer volume
duration	Long flows → tunnelling/bulk transfer
bytes_per_second	Rate normalisation
packets_per_second	Spikes → automation
average_packet_size	Small → scanning; large → bulk transfer
connection_count	Volume of connections
failed_connection_count	Brute force / misconfiguration
failure_ratio	Environment-normalised failure metric
syn_count / rst_count	Handshake behaviour
syn_ratio	Incomplete handshake indicator
unique_destination_ports	Service-discovery indicator
unique_destination_ips	Fan-out indicator
connection_rate	Connections per second
Signature-Based Detection
Rule	Name	Severity
IDS-001	High Connection Rate	HIGH
IDS-002	Repeated Failed Connections	HIGH
IDS-003	Multi-Port Access Pattern	MEDIUM
IDS-004	SYN-Heavy Connection Behaviour	HIGH
IDS-005	Unusual Service-Port Activity	MEDIUM
IDS-006	Abnormally High Traffic Volume	MEDIUM
A rule match means the pattern is worth investigating — it does not prove malicious activity.

Anomaly Detection
Baseline statistics (mean, std, median, IQR) are computed per feature from normal
traffic. New flows are scored with a robust Z-score (|x − median| / (IQR/1.349))
and combined into a 0–100 anomaly score.

Trade-off: catches unknown behaviour, but produces more false positives.

Machine Learning
Model	Type	Notes
Logistic Regression	Supervised	Fast, interpretable
Random Forest	Supervised	Non-linear, feature importances
Isolation Forest	Unsupervised	Trained on normal traffic only
Metrics actually computed from the generated dataset: accuracy, precision,
recall, F1, ROC-AUC, confusion matrix.

Hybrid Detection
text
Risk = w_rule · RuleScore + w_anomaly · AnomalyScore + w_ml · MLScore
Configuration	Rule	Anomaly	ML
With ML	0.40	0.30	0.30
Without ML	0.60	0.40	0.00
Risk Scoring
Range	Classification
0–20	NORMAL
21–40	LOW RISK
41–60	SUSPICIOUS
61–80	HIGH RISK
81–100	CRITICAL INVESTIGATION
These bands are project assumptions. A real SOC calibrates thresholds
against its own traffic profile and risk appetite.

Alert Generation
Field	Description
alert_id	Unique identifier
timestamp	UTC timestamp
source_ip / destination_ip	Endpoints
protocol, source_port, destination_port	5-tuple
rule_id, alert_type	Detection source
severity	INFO / LOW / MEDIUM / HIGH / CRITICAL
risk_score	0–100
description	Human-readable reason
status	NEW / INVESTIGATING / RESOLVED / FALSE_POSITIVE
Alert Correlation
Alerts sharing the same source IP and alert type within a
60-second window are grouped. Three or more become an incident.

SOC Dashboard
Cards: total flows · normal · suspicious · open alerts · critical alerts · average risk

Charts: traffic over time · alerts by severity · protocol distribution ·
top alert types · top destination ports · top source IPs · risk distribution · alert status

Features: alert table with severity/status/protocol filters, click-to-investigate
modal, status updates, analyst notes.

Incident Investigation
Clicking an alert reveals: 5-tuple, matched rules, anomaly score, ML score,
final risk score, reason, traffic statistics, recommended investigation steps,
and analyst notes.

API Documentation
Method	Endpoint	Purpose
POST	/api/flows	Ingest + analyse one flow (201)
GET	/api/flows	List flows (limit, offset, classification, protocol, source_ip)
GET	/api/flows/<id>	Flow detail + its alerts (404 if missing)
GET	/api/alerts	List alerts (severity, status, alert_type, protocol, source_ip)
GET	/api/alerts/<id>	Alert detail + notes + flow + investigation steps
PUT	/api/alerts/<id>/status	Update status (422 on invalid status)
POST	/api/alerts/<id>/notes	Add analyst note (422 if empty)
GET	/api/dashboard/stats	Dashboard cards
GET	/api/dashboard/traffic	Time-series traffic data
GET	/api/dashboard/alerts	Alert breakdowns + recent alerts
GET	/api/rules	List detection rules
PUT	/api/rules/<id>	Enable/disable a rule
GET	/api/incidents	Correlated incidents
POST	/api/simulate/tick	Server-side synthetic flow generation
Validation: all POST/PUT bodies are JSON-validated; invalid input returns
400/422 with an explanatory message.
Authentication: not enabled by default (localhost only). See Future Improvements.
Error handling: centralised handlers return {"error": ..., "status": ...}.

Installation
bash
git clone https://github.com/<your-username>/Network-Intrusion-Detection-System-Simulation.git
cd Network-Intrusion-Detection-System-Simulation

python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

pip install -r requirements.txt

# 1) Generate synthetic dataset
python -m simulator.generate_dataset --count 8000

# 2) (Optional) Train ML model
python -m ml.train_model
python -m ml.evaluate

# 3) Start backend + dashboard
python -m backend.app
Open http://127.0.0.1:5000

Usage
bash
# Stream synthetic flows into the API
python -m simulator.traffic_simulator --mode mixed --speed fast --sink api

# Or generate traffic directly from the dashboard
# Click "▶ Simulate 20 Flows"
Testing
bash
pytest -v
35 tests covering feature extraction, validation, all six rules, anomaly
scoring, risk banding, alert generation, correlation, rule toggling,
pipeline integration, and ML weight switching.

Security
Synthetic data only; no PII

No packet payloads stored

Dashboard bound to 127.0.0.1 by default

All input validated before processing

Output HTML-escaped to prevent XSS

Secrets via environment variables

Audit trail: every status change and note is timestamped

Results
Run pytest -v and python -m ml.evaluate to reproduce all metrics on your
machine. No results in this README are fabricated — every number is
computed from the generated dataset.

False Positives & False Negatives
Meaning	Impact
FP	Normal traffic flagged	Alert fatigue, wasted analyst time
FN	Suspicious traffic missed	Undetected incident, real damage
Security teams watch recall closely (missed detections are costly) while
actively managing FP volume. Hybrid detection, better baselines, tuned
thresholds and analyst feedback all improve the balance.

Limitations
Synthetic data cannot fully represent production traffic diversity

SQLite is not suitable for high-throughput production ingestion

No authentication/authorisation enabled by default

Thresholds are project assumptions, not calibrated production values

Alert correlation is time-window based, not entity-graph based

ML model is trained on synthetic distributions

Future Improvements
Authorized PCAP ingestion (offline analysis of your own captures)

Zeek / Suricata log ingestion

SIEM forwarding (Splunk HEC, Elastic, Wazuh)

Threat-intelligence enrichment

UEBA-style behavioural baselines

Detection-rule tuning workflow with analyst feedback

Model drift monitoring

Authentication + RBAC on the dashboard

Docker / docker-compose deployment

PostgreSQL for higher throughput

Screenshots
See the screenshots/ folder for:


Learning Outcomes
How a Network IDS actually works end to end

Feature engineering from flow telemetry

Writing explainable detection rules

Statistical anomaly detection and its trade-offs

Combining detection methods into a hybrid score

Alert lifecycle and SOC triage workflow

Building a REST API + dashboard for security data

Writing tests for security logic

#Author
#HRIDOY BISWAS
