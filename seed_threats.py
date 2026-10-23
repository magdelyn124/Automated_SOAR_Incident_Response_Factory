"""
seed_threats.py — Automated Testing Harness
--------------------------------------------
Writes three realistic enterprise cyberattack logs into auth_alerts.json
for use as a repeatable test fixture with the SOAR Incident Response Factory.

Run:  python seed_threats.py
"""

import json

ALERTS_FILE = "auth_alerts.json"

THREATS = [
    {
        "compromised_user": "corp_finance_root",
        "attacker_ip":      "203.0.113.111",
        "severity":         "CRITICAL",
        "vector":           "Ransomware Payload Access Blueprint",
        "mitigated":        False,
    },
    {
        "compromised_user": "cloud_db_operator",
        "attacker_ip":      "198.51.100.5",
        "severity":         "HIGH",
        "vector":           "Anomalous Off-Hours SQL Data Exfiltration",
        "mitigated":        True,
    },
    {
        "compromised_user": "c_suite_executive",
        "attacker_ip":      "192.0.2.77",
        "severity":         "CRITICAL",
        "vector":           "Session Token Hijacking & Authenication Bypass",
        "mitigated":        False,
    },
]

with open(ALERTS_FILE, "w", encoding="utf-8") as fh:
    json.dump(THREATS, fh, indent=2)

print(f"[seed_threats] Successfully wrote {len(THREATS)} threat profiles to '{ALERTS_FILE}'.")
print(f"               CRITICAL: {sum(1 for t in THREATS if t['severity'] == 'CRITICAL')}  "
      f"HIGH: {sum(1 for t in THREATS if t['severity'] == 'HIGH')}  "
      f"Pending: {sum(1 for t in THREATS if not t['mitigated'])}  "
      f"Mitigated: {sum(1 for t in THREATS if t['mitigated'])}")
