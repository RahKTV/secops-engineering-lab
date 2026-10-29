#!/usr/bin/env python3
"""
SSH Authentication Telemetry & Brute-Force Detection Engine
Parses Linux auth.log files to detect credential stuffing and brute-force anomalies.
Outputs structured JSON alerts mapped to MITRE ATT&CK (T1110.001).
"""

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Set

# Regex pattern to extract failed SSH login attempts from standard Debian/Ubuntu auth.log
FAILED_SSH_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?"
    r"(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+\d+"
)


def parse_auth_log(filepath: str, threshold: int) -> List[Dict]:
    """Parses auth.log and aggregates failed authentication attempts by source IP."""
    failed_attempts: Dict[str, int] = defaultdict(int)
    targeted_users: Dict[str, Set[str]] = defaultdict(set)

    try:
        with open(filepath, "r", encoding="utf-8") as log_file:
            for line in log_file:
                match = FAILED_SSH_PATTERN.search(line)
                if match:
                    ip = match.group("ip")
                    user = match.group("user")
                    failed_attempts[ip] += 1
                    targeted_users[ip].add(user)
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {filepath}")
        return []

    alerts = []
    for ip, count in failed_attempts.items():
        if count >= threshold:
            severity = "CRITICAL" if count >= (threshold * 2) else "HIGH"
            alert = {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "alert_type": "SSH_BRUTE_FORCE_DETECTED",
                "severity": severity,
                "source_ip": ip,
                "failed_attempts": count,
                "targeted_accounts": sorted(list(targeted_users[ip])),
                "recommended_action": "DENY_INGRESS_FIREWALL",
                "mitre_attack_id": "T1110.001",
            }
            alerts.append(alert)

    return alerts


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Linux auth.log for SSH brute-force anomalies."
    )
    parser.add_argument(
        "--logfile",
        required=True,
        help="Path to the Linux auth.log file to analyze.",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed login threshold to trigger a security alert (default: 5).",
    )
    args = parser.parse_args()

    alerts = parse_auth_log(args.logfile, args.threshold)

    if alerts:
        print(json.dumps(alerts, indent=2))
    else:
        print(json.dumps({"status": "CLEAN", "anomalies_detected": 0}, indent=2))


if __name__ == "__main__":
    main()
