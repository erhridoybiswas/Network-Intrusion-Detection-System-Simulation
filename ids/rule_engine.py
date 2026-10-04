"""
rule_engine.py
--------------
Signature-based (rule-based) detection.

IMPORTANT CONCEPT:
    A rule match means the traffic pattern is WORTH INVESTIGATING.
    It does NOT prove malicious activity. Rules produce indicators,
    not verdicts. Every match must be validated by an analyst.

Rules are defined in config.RULES and can be enabled/disabled at runtime.
"""

from __future__ import annotations

from config import RULES, RULE_THRESHOLDS, SEVERITY_SCORE

# Module-level registry so rules can be toggled via the API at runtime.
_RULE_STATE: dict[str, bool] = {rid: r["enabled"] for rid, r in RULES.items()}


def set_rule_enabled(rule_id: str, enabled: bool) -> bool:
    """Enable or disable a rule. Returns True if the rule exists."""
    if rule_id not in _RULE_STATE:
        return False
    _RULE_STATE[rule_id] = bool(enabled)
    return True


def get_rules() -> list[dict]:
    """Return the current rule registry with live enabled state."""
    out = []
    for rid, rule in RULES.items():
        item = dict(rule)
        item["enabled"] = _RULE_STATE.get(rid, rule["enabled"])
        out.append(item)
    return out


def is_rule_enabled(rule_id: str) -> bool:
    return _RULE_STATE.get(rule_id, False)


# --------------------------------------------------------------------------
# Individual rule checks
# --------------------------------------------------------------------------

def _rule_001(f: dict) -> dict | None:
    """IDS-001 High Connection Rate."""
    threshold = RULE_THRESHOLDS["IDS-001"]["connection_rate"]
    if f["connection_rate"] > threshold:
        return {
            "rule_id": "IDS-001",
            "name": "High Connection Rate",
            "severity": "HIGH",
            "reason": (f"Connection rate {f['connection_rate']:.2f}/s exceeded "
                       f"configured baseline of {threshold}/s."),
            "evidence": {"connection_rate": f["connection_rate"], "threshold": threshold},
        }
    return None


def _rule_002(f: dict) -> dict | None:
    """IDS-002 Repeated Failed Connections."""
    cfg = RULE_THRESHOLDS["IDS-002"]
    if (f["failed_connection_count"] >= cfg["failed_connections"]
            and f["failure_ratio"] >= cfg["failure_ratio"]):
        return {
            "rule_id": "IDS-002",
            "name": "Repeated Failed Connections",
            "severity": "HIGH",
            "reason": (f"{f['failed_connection_count']} failed connections "
                       f"({f['failure_ratio']*100:.1f}% failure ratio) from a "
                       f"single source — consistent with repeated connection attempts."),
            "evidence": {
                "failed_connection_count": f["failed_connection_count"],
                "failure_ratio": f["failure_ratio"],
            },
        }
    return None


def _rule_003(f: dict) -> dict | None:
    """IDS-003 Multi-Port Access Pattern."""
    threshold = RULE_THRESHOLDS["IDS-003"]["unique_destination_ports"]
    if f["unique_destination_ports"] >= threshold:
        return {
            "rule_id": "IDS-003",
            "name": "Multi-Port Access Pattern",
            "severity": "MEDIUM",
            "reason": (f"Source contacted {f['unique_destination_ports']} distinct "
                       f"destination ports (baseline threshold {threshold})."),
            "evidence": {"unique_destination_ports": f["unique_destination_ports"]},
        }
    return None


def _rule_004(f: dict) -> dict | None:
    """IDS-004 SYN-Heavy Connection Behaviour."""
    cfg = RULE_THRESHOLDS["IDS-004"]
    if f["syn_ratio"] >= cfg["syn_ratio"] and f["syn_count"] >= cfg["syn_count"]:
        return {
            "rule_id": "IDS-004",
            "name": "SYN-Heavy Connection Behaviour",
            "severity": "HIGH",
            "reason": (f"SYN ratio {f['syn_ratio']:.2f} with {f['syn_count']} SYN "
                       f"segments — handshakes initiated far outnumber completions."),
            "evidence": {"syn_ratio": f["syn_ratio"], "syn_count": f["syn_count"]},
        }
    return None


def _rule_005(f: dict) -> dict | None:
    """IDS-005 Unusual Service-Port Activity."""
    unusual = set(RULE_THRESHOLDS["IDS-005"]["unusual_ports"])
    if f["destination_port"] in unusual:
        return {
            "rule_id": "IDS-005",
            "name": "Unusual Service-Port Activity",
            "severity": "MEDIUM",
            "reason": (f"Traffic directed at port {f['destination_port']}, which is "
                       f"not expected in this environment's baseline."),
            "evidence": {"destination_port": f["destination_port"]},
        }
    return None


def _rule_006(f: dict) -> dict | None:
    """IDS-006 Abnormally High Traffic Volume."""
    threshold = RULE_THRESHOLDS["IDS-006"]["byte_count"]
    if f["byte_count"] > threshold:
        return {
            "rule_id": "IDS-006",
            "name": "Abnormally High Traffic Volume",
            "severity": "MEDIUM",
            "reason": (f"Flow transferred {f['byte_count']:,} bytes, exceeding the "
                       f"configured volume baseline of {threshold:,} bytes."),
            "evidence": {"byte_count": f["byte_count"], "threshold": threshold},
        }
    return None


_RULE_CHECKS = [_rule_001, _rule_002, _rule_003, _rule_004, _rule_005, _rule_006]


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def analyze_flow(features: dict) -> dict:
    """
    Run all enabled rules against an engineered feature dict.

    Returns:
        {
          "matches": [ {rule_id, name, severity, reason, evidence}, ... ],
          "rule_score": 0-100,
          "max_severity": "INFO"|"LOW"|"MEDIUM"|"HIGH"|"CRITICAL"|"NONE"
        }
    """
    matches: list[dict] = []

    for check in _RULE_CHECKS:
        # Determine the rule id from the function name mapping without calling twice
        try:
            result = check(features)
        except Exception:  # a broken rule must never crash the pipeline
            continue
        if result and is_rule_enabled(result["rule_id"]):
            matches.append(result)

    if not matches:
        return {"matches": [], "rule_score": 0.0, "max_severity": "NONE"}

    # Base score = highest severity matched
    base = max(SEVERITY_SCORE.get(m["severity"], 0) for m in matches)

    # Small uplift for multiple independent rule matches (capped at 100)
    uplift = min(5 * (len(matches) - 1), 20)
    rule_score = min(base + uplift, 100)

    severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    max_severity = max((m["severity"] for m in matches),
                       key=lambda s: severity_order.index(s))

    return {
        "matches": matches,
        "rule_score": float(rule_score),
        "max_severity": max_severity,
    }