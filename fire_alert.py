"""
fire_alert.py — Live Threat Injection Simulator
------------------------------------------------
Simulates a realistic, multi-stage hacker attack by appending a sequence
of escalating CRITICAL alert events to auth_alerts.json.

The soar_engine.py polling loop will detect each new event within its
next poll cycle and issue an automated incident response.

Run:  python fire_alert.py
"""

import json
import os
import time
import datetime
import random

ALERTS_FILE = "auth_alerts.json"

# ── Attack scenario definition ────────────────────────────────────────────────
# Each entry represents one stage of an adversary kill chain.

ATTACK_STAGES = [
    {
        "event_type" : "BRUTE_FORCE_AUTH",
        "description": (
            "Sustained brute-force login campaign detected against the VPN "
            "gateway. 847 failed authentication attempts in 90 seconds from "
            "a single foreign IP address."
        ),
        "asset"      : "VPN-GW-01 (203.0.113.45)",
        "username"   : "admin",
        "source_ip"  : "185.220.101.47",
        "delay"      : 0,
    },
    {
        "event_type" : "CREDENTIAL_STUFFING",
        "description": (
            "Credential-stuffing attack targeting the corporate SSO portal. "
            "Leaked credential pairs from a third-party breach are being "
            "replayed at high velocity."
        ),
        "asset"      : "SSO-PORTAL-PROD",
        "username"   : "j.harrison@corp.internal",
        "source_ip"  : "91.108.4.212",
        "delay"      : 4,
    },
    {
        "event_type" : "PRIVILEGE_ESCALATION",
        "description": (
            "Successful lateral movement observed. Attacker escalated from "
            "standard user to Domain Admin via unpatched CVE-2023-32315 "
            "on an internal Windows Server host."
        ),
        "asset"      : "WINSRV-DC-02 (10.10.5.22)",
        "username"   : "svc_backup",
        "source_ip"  : "10.10.5.101",
        "delay"      : 6,
    },
    {
        "event_type" : "DATA_EXFILTRATION_ATTEMPT",
        "description": (
            "Anomalous outbound data transfer detected. 4.7 GB staging to "
            "external C2 server over encrypted channel (HTTPS/443). "
            "Destination IP geo-locates to a known threat-actor region."
        ),
        "asset"      : "FILESERVER-01 (10.10.2.15)",
        "username"   : "svc_backup",
        "source_ip"  : "45.142.212.100",
        "delay"      : 5,
    },
    {
        "event_type" : "RANSOMWARE_PRECURSOR",
        "description": (
            "Endpoint Detection & Response agent flagged mass shadow-copy "
            "deletion (vssadmin delete shadows /all /quiet) and rapid "
            "file-rename activity consistent with ransomware staging. "
            "Immediate containment required."
        ),
        "asset"      : "ENDPOINT-ACCT-07 (10.10.1.88)",
        "username"   : "m.chen",
        "source_ip"  : "10.10.1.88",
        "delay"      : 7,
    },
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_existing() -> list[dict]:
    if not os.path.exists(ALERTS_FILE):
        return []
    try:
        with open(ALERTS_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []

def _save(alerts: list[dict]) -> None:
    with open(ALERTS_FILE, "w", encoding="utf-8") as fh:
        json.dump(alerts, fh, indent=2)

def _new_alert_id(existing: list[dict]) -> str:
    used = {a.get("id", "") for a in existing}
    while True:
        candidate = f"INC-{random.randint(10000, 99999)}"
        if candidate not in used:
            return candidate

def inject_alert(stage: dict, existing: list[dict]) -> dict:
    """Build and append a single CRITICAL alert record."""
    alert_id = _new_alert_id(existing)
    alert = {
        "id"         : alert_id,
        "severity"   : "CRITICAL",
        "event_type" : stage["event_type"],
        "description": stage["description"],
        "asset"      : stage["asset"],
        "username"   : stage["username"],
        "source_ip"  : stage["source_ip"],
        "timestamp"  : datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "mitigated"  : False,
    }
    existing.append(alert)
    _save(existing)
    return alert

# ── Main Simulation ───────────────────────────────────────────────────────────

def main() -> None:
    print("\n" + "=" * 60)
    print("  THREAT INJECTION SIMULATOR  —  fire_alert.py")
    print("  Target file :", ALERTS_FILE)
    print("=" * 60)
    print("  Simulating a multi-stage adversary kill chain …\n")

    alerts = _load_existing()

    for i, stage in enumerate(ATTACK_STAGES, start=1):
        delay = stage["delay"]
        if delay > 0:
            print(f"  [Stage {i}] Waiting {delay}s before next attack wave …")
            time.sleep(delay)

        alert = inject_alert(stage, alerts)

        print(f"  [Stage {i}] ► INJECTED  {alert['event_type']}")
        print(f"             Alert ID : {alert['id']}")
        print(f"             Source IP: {alert['source_ip']}")
        print(f"             Asset    : {alert['asset']}")
        print(f"             Time     : {alert['timestamp']}")
        print()

    print("=" * 60)
    print(f"  All {len(ATTACK_STAGES)} attack stages written to '{ALERTS_FILE}'.")
    print("  SOAR engine will respond within its next polling cycle.")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    main()
