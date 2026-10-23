"""
soar_engine.py — Automated SOAR Incident Response Engine
---------------------------------------------------------
Continuously polls auth_alerts.json for CRITICAL, unmitigated events.
On detection:
  1. Simulates a network firewall IP block (ACL rule injection).
  2. Prints a structured Executive Incident Brief to the console.
  3. Stamps the alert as mitigated so it is not re-processed.

Run:  python soar_engine.py
Stop: Ctrl-C
"""

import json
import os
import time
import datetime
import textwrap

# ── Configuration ──────────────────────────────────────────────────────────────
ALERTS_FILE   = "auth_alerts.json"
POLL_INTERVAL = 5          # seconds between file checks
SEVERITY_GATE = "CRITICAL" # only act on this severity level

# ── Simulated Firewall Controller ─────────────────────────────────────────────

_blocked_ips: set[str] = set()

def firewall_block_ip(ip: str, alert_id: str) -> dict:
    """
    Simulate pushing a DENY ACL rule to the perimeter firewall.
    In a live deployment replace this body with an API call to your
    firewall management platform (Palo Alto, Cisco FMC, Fortinet, etc.).
    """
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    if ip in _blocked_ips:
        return {
            "status"    : "ALREADY_BLOCKED",
            "ip"        : ip,
            "timestamp" : timestamp,
            "rule_id"   : f"ACL-DUP-{alert_id}",
        }

    # ── Simulated ACL push ─────────────────────────────────────────────────
    time.sleep(0.3)          # simulate network round-trip latency
    _blocked_ips.add(ip)
    # ── End simulation ─────────────────────────────────────────────────────

    return {
        "status"    : "BLOCKED",
        "ip"        : ip,
        "timestamp" : timestamp,
        "rule_id"   : f"ACL-DENY-{alert_id}",
        "action"    : f"DROP all inbound/outbound traffic from/to {ip}",
    }

# ── Executive Incident Brief Renderer ─────────────────────────────────────────

_DIVIDER = "=" * 72

def _wrap(label: str, value: str, width: int = 72, indent: int = 22) -> str:
    """Left-align a labelled field, wrapping long values."""
    prefix  = f"  {label:<{indent - 2}}: "
    wrapped = textwrap.fill(
        str(value),
        width          = width,
        initial_indent = prefix,
        subsequent_indent = " " * indent,
    )
    return wrapped

def print_executive_brief(alert: dict, fw_result: dict) -> None:
    """Render a clean, scannable Executive Incident Brief to stdout."""
    now   = datetime.datetime.utcnow().strftime("%Y-%m-%d  %H:%M:%S UTC")
    brief = f"""
{_DIVIDER}
  EXECUTIVE INCIDENT BRIEF                          {now}
{_DIVIDER}
  CLASSIFICATION : CONFIDENTIAL — INTERNAL USE ONLY
{_DIVIDER}

  INCIDENT SUMMARY
{_wrap("Alert ID",        alert.get("id",          "N/A"))}
{_wrap("Severity",        alert.get("severity",    "N/A"))}
{_wrap("Event Type",      alert.get("event_type",  "N/A"))}
{_wrap("Description",     alert.get("description", "N/A"))}
{_wrap("Affected Asset",  alert.get("asset",       "N/A"))}
{_wrap("Source IP",       alert.get("source_ip",   "N/A"))}
{_wrap("Target User",     alert.get("username",    "N/A"))}
{_wrap("Detection Time",  alert.get("timestamp",   "N/A"))}

  AUTOMATED RESPONSE  (SOAR Engine v1.0)
{_wrap("Action Taken",    "Firewall IP Block — ACL rule injected")}
{_wrap("Rule ID",         fw_result.get("rule_id",   "N/A"))}
{_wrap("Block Status",    fw_result.get("status",    "N/A"))}
{_wrap("Rule Applied",    fw_result.get("action",    "N/A"))}
{_wrap("Enforced At",     fw_result.get("timestamp", "N/A"))}

  RECOMMENDED NEXT STEPS
  1. Security Operations — validate block rule is propagated to all edge nodes.
  2. Identity & Access   — suspend or reset credentials for affected user.
  3. Threat Intel        — correlate source IP against external threat feeds.
  4. Incident Manager    — open formal IR ticket and notify stakeholders.
  5. Forensics           — preserve endpoint logs for post-incident review.

{_DIVIDER}
  STATUS: MITIGATED (automated containment applied)
{_DIVIDER}
"""
    print(brief)

# ── Alert Processor ───────────────────────────────────────────────────────────

def load_alerts() -> list[dict]:
    """Read and return the alerts list from disk; return [] on any error."""
    if not os.path.exists(ALERTS_FILE):
        return []
    try:
        with open(ALERTS_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []

def save_alerts(alerts: list[dict]) -> None:
    """Persist the (mutated) alerts list back to disk."""
    with open(ALERTS_FILE, "w", encoding="utf-8") as fh:
        json.dump(alerts, fh, indent=2)

def process_alerts() -> int:
    """Scan for unmitigated CRITICAL alerts, respond, and return count handled."""
    alerts  = load_alerts()
    handled = 0

    for alert in alerts:
        if (
            alert.get("severity",   "").upper() == SEVERITY_GATE
            and not alert.get("mitigated", False)
        ):
            src_ip = alert.get("source_ip", "0.0.0.0")
            fw     = firewall_block_ip(src_ip, alert["id"])

            print_executive_brief(alert, fw)

            alert["mitigated"]    = True
            alert["mitigated_at"] = fw["timestamp"]
            alert["rule_id"]      = fw.get("rule_id", "N/A")
            handled += 1

    if handled:
        save_alerts(alerts)

    return handled

# ── Main Loop ─────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"\n[SOAR] Engine started. Polling '{ALERTS_FILE}' every {POLL_INTERVAL}s …")
    print("[SOAR] Watching for CRITICAL unmitigated events.  Press Ctrl-C to stop.\n")

    try:
        while True:
            count = process_alerts()
            if count == 0:
                ts = datetime.datetime.utcnow().strftime("%H:%M:%S")
                print(f"[{ts}] No new CRITICAL alerts detected.", end="\r", flush=True)
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print("\n\n[SOAR] Engine stopped by operator.  Goodbye.\n")

if __name__ == "__main__":
    main()
