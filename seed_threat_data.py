"""
seed_threat_data.py — Threat Data Seeder
-----------------------------------------
Overwrites auth_alerts.json with five distinct, realistic enterprise
cyberattack logs covering a range of severity levels and attack profiles.

Run:  python seed_threat_data.py
"""

import json
import os

ALERTS_FILE = "auth_alerts.json"

ALERTS = [
    # ── 1. CRITICAL — Ransomware Initial Access (unmitigated) ────────────────
    {
        "id"          : "INC-88312",
        "severity"    : "CRITICAL",
        "event_type"  : "RANSOMWARE_INITIAL_ACCESS",
        "description" : (
            "Spear-phishing payload executed on endpoint ENDPOINT-FIN-03. "
            "A macro-enabled Office document dropped a Cobalt Strike beacon "
            "(SHA-256: 3d2a1f…e9c4b7) communicating with a known Ransomware-as-a-Service "
            "C2 infrastructure at 185.220.101.55 (flagged in 14 threat-intel feeds). "
            "Initial foothold established under user context 'p.wright'. "
            "Immediate isolation and IR escalation required."
        ),
        "asset"       : "ENDPOINT-FIN-03 (10.10.3.44)",
        "username"    : "p.wright",
        "source_ip"   : "185.220.101.55",
        "geo_location": "Minsk, Belarus",
        "timestamp"   : "2026-11-14T09:17:04Z",
        "mitigated"   : False,
        "rule_id"     : None,
    },

    # ── 2. HIGH — Database Anomaly / Unusual Data Extraction (mitigated) ─────
    {
        "id"          : "INC-71045",
        "severity"    : "HIGH",
        "event_type"  : "DB_ANOMALOUS_DATA_EXTRACTION",
        "description" : (
            "Database Activity Monitoring (DAM) raised an anomaly alert on DB-PROD-02. "
            "Service account 'svc_reporting' executed 47 sequential full-table SELECT "
            "statements across PII-classified tables (customers, payments, contracts) "
            "between 02:11 and 02:38 UTC, exporting an aggregate of 9.3 GB — "
            "22× the 30-day baseline for this account. Query patterns match known "
            "data-staging behaviour prior to exfiltration. Account suspended; "
            "DBA team notified."
        ),
        "asset"       : "DB-PROD-02 (10.10.8.11)",
        "username"    : "svc_reporting",
        "source_ip"   : "10.10.8.200",
        "geo_location": "Internal — DMZ Segment B",
        "timestamp"   : "2026-11-14T02:11:33Z",
        "mitigated"   : True,
        "mitigated_at": "2026-11-14T02:44:17Z",
        "rule_id"     : "DAM-BLOCK-INC-71045",
    },

    # ── 3. CRITICAL — Session Token Hijacking / MFA Bypass (unmitigated) ─────
    {
        "id"          : "INC-92657",
        "severity"    : "CRITICAL",
        "event_type"  : "SESSION_TOKEN_HIJACK_MFA_BYPASS",
        "description" : (
            "Adversary-in-the-Middle (AiTM) phishing kit captured a valid session "
            "cookie for executive account 'ceo@corp.internal' after the user completed "
            "a legitimate MFA prompt on a spoofed O365 login page. The harvested cookie "
            "was replayed from IP 91.108.56.179 (Tor exit node) within 4 minutes of "
            "issuance, bypassing all MFA controls. Attacker accessed Board-level "
            "SharePoint sites and initiated two external mail-forwarding rules. "
            "Session revocation and forensic preservation in progress."
        ),
        "asset"       : "O365-TENANT / SHAREPOINT-EXEC",
        "username"    : "ceo@corp.internal",
        "source_ip"   : "91.108.56.179",
        "geo_location": "Amsterdam, Netherlands (Tor exit)",
        "timestamp"   : "2026-11-14T11:03:52Z",
        "mitigated"   : False,
        "rule_id"     : None,
    },

    # ── 4. MEDIUM — Brute-Force Port Scan on External Assets (mitigated) ─────
    {
        "id"          : "INC-54490",
        "severity"    : "MEDIUM",
        "event_type"  : "EXTERNAL_PORT_BRUTE_FORCE_SCAN",
        "description" : (
            "Perimeter IDS detected a systematic TCP SYN scan originating from "
            "45.33.32.156 targeting the public-facing IP range 203.0.113.0/28. "
            "Scan swept 65 535 ports across 12 hosts in 8 minutes, with concentrated "
            "probing of RDP (3389), SSH (22), and SMB (445). 2 048 connection attempts "
            "logged; no successful authentication. Source IP geo-locates to a VPS "
            "provider with prior abuse reports. Inbound ACL rule applied; no internal "
            "compromise detected."
        ),
        "asset"       : "PERIMETER-FW-01 (203.0.113.1)",
        "username"    : "N/A",
        "source_ip"   : "45.33.32.156",
        "geo_location": "Fremont, CA, USA (VPS — OVH)",
        "timestamp"   : "2026-11-14T06:45:09Z",
        "mitigated"   : True,
        "mitigated_at": "2026-11-14T06:52:44Z",
        "rule_id"     : "ACL-DENY-INC-54490",
    },

    # ── 5. CRITICAL — Impossible Travel Anomaly / Admin Account (unmitigated) ─
    {
        "id"          : "INC-39871",
        "severity"    : "CRITICAL",
        "event_type"  : "IMPOSSIBLE_TRAVEL_ANOMALY",
        "description" : (
            "Identity Protection engine flagged a physical impossibility for admin "
            "account 'r.torres@corp.internal'. Successful authentication recorded from "
            "London, UK (IP 82.132.224.10) at 14:22 UTC, followed by a second "
            "successful authentication from São Paulo, Brazil (IP 177.75.40.88) at "
            "14:31 UTC — a 9-minute gap across an 18-hour flight route. Both sessions "
            "remain active. High probability of credential compromise or account "
            "sharing. VPN split-tunnel and geo-velocity policies bypassed. Immediate "
            "global session revocation and password reset enforced pending investigation."
        ),
        "asset"       : "AZURE-AD / CORP-IDENTITY-PLATFORM",
        "username"    : "r.torres@corp.internal",
        "source_ip"   : "177.75.40.88",
        "geo_location": "São Paulo, Brazil (prev: London, UK — 9 min delta)",
        "timestamp"   : "2026-11-14T14:31:07Z",
        "mitigated"   : False,
        "rule_id"     : None,
    },
]


def main() -> None:
    with open(ALERTS_FILE, "w", encoding="utf-8") as fh:
        json.dump(ALERTS, fh, indent=2)

    total     = len(ALERTS)
    critical  = sum(1 for a in ALERTS if a["severity"] == "CRITICAL")
    high      = sum(1 for a in ALERTS if a["severity"] == "HIGH")
    medium    = sum(1 for a in ALERTS if a["severity"] == "MEDIUM")
    pending   = sum(1 for a in ALERTS if not a["mitigated"])
    mitigated = sum(1 for a in ALERTS if a["mitigated"])

    print(f"[seed] Wrote {total} alerts to '{ALERTS_FILE}'")
    print(f"       Severity breakdown  →  CRITICAL: {critical}  HIGH: {high}  MEDIUM: {medium}")
    print(f"       Mitigation status   →  Pending: {pending}  Mitigated: {mitigated}")
    print(f"[seed] Streamlit app will reflect changes on next page load or refresh.")


if __name__ == "__main__":
    main()
