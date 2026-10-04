"""
traffic_simulator.py
--------------------
Streams synthetic network-flow records in near-real-time.

IMPORTANT: This module produces Python dictionaries / JSON only.
It does NOT open sockets, send packets, scan hosts, or touch any network.

Usage:
    python -m simulator.traffic_simulator --mode mixed  --speed fast
    python -m simulator.traffic_simulator --mode normal --speed slow
    python -m simulator.traffic_simulator --mode mixed  --sink api --count 200
"""

from __future__ import annotations

import argparse
import json
import random
import time
import uuid
from datetime import datetime

import requests

from simulator.generate_dataset import (
    NORMAL_SCENARIOS,
    SUSPICIOUS_SCENARIOS,
    _weighted_choice,
)

SPEED_INTERVALS = {"slow": 3.0, "normal": 1.0, "fast": 0.15}


def build_flow(mode: str = "mixed") -> dict:
    """Create one synthetic flow record."""
    if mode == "normal":
        fn = _weighted_choice(NORMAL_SCENARIOS)
    else:
        # 70% normal / 30% suspicious in mixed mode
        fn = _weighted_choice(NORMAL_SCENARIOS) if random.random() < 0.70 \
            else _weighted_choice(SUSPICIOUS_SCENARIOS)

    record = fn(datetime.now())
    record["flow_id"] = f"FLW-{uuid.uuid4().hex[:10].upper()}"
    return record


def run(mode: str, speed: str, sink: str, api_url: str,
        count: int | None, quiet: bool) -> None:
    interval = SPEED_INTERVALS.get(speed, 1.0)
    emitted = 0
    session = requests.Session()

    print(f"[*] Simulator started | mode={mode} speed={speed} sink={sink}")
    print("[*] NOTE: generating synthetic DATA records only. No packets are sent.")

    try:
        while True:
            flow = build_flow(mode)
            emitted += 1

            if sink == "api":
                try:
                    resp = session.post(f"{api_url}/api/flows", json=flow, timeout=5)
                    if not quiet:
                        body = resp.json() if resp.ok else {"error": resp.text}
                        verdict = body.get("classification", "?")
                        risk = body.get("risk_score", "?")
                        print(f"[{emitted:05d}] {flow['scenario_type']:<32} "
                              f"-> {verdict} (risk={risk})")
                except requests.RequestException as exc:
                    print(f"[!] API unreachable ({exc}). Falling back to stdout.")
                    print(json.dumps(flow))
            else:
                if not quiet:
                    print(json.dumps(flow))

            if count and emitted >= count:
                break
            time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\n[*] Simulator stopped after {emitted} synthetic flows.")


def main() -> None:
    p = argparse.ArgumentParser(description="Synthetic network flow simulator.")
    p.add_argument("--mode", choices=["normal", "mixed"], default="mixed")
    p.add_argument("--speed", choices=["slow", "normal", "fast"], default="normal")
    p.add_argument("--sink", choices=["stdout", "api"], default="stdout")
    p.add_argument("--api-url", default="http://127.0.0.1:5000")
    p.add_argument("--count", type=int, default=None,
                   help="Stop after N flows (default: run forever)")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args()

    run(args.mode, args.speed, args.sink, args.api_url, args.count, args.quiet)


if __name__ == "__main__":
    main()