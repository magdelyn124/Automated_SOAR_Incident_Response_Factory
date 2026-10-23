"""
app.py — Automated SOAR Incident Response Factory
--------------------------------------------------
Enterprise-grade Streamlit dashboard for real-time incident management.

Run:  streamlit run app.py
Deps: pip install streamlit plyer pandas
"""

import json
import os
import random
import datetime
import pandas as pd
import streamlit as st

# ── Optional desktop notifications (plyer) ────────────────────────────────────
try:
    from plyer import notification as _plyer_notification
    PLYER_AVAILABLE = True
except ImportError:
    PLYER_AVAILABLE = False

# ── File paths ─────────────────────────────────────────────────────────────────
ALERTS_FILE  = "auth_alerts.json"
HISTORY_FILE = "incident_history.log"

# ── Severity / event-type catalogues for mock threat injection ─────────────────
_MOCK_EVENT_TYPES = [
    "BRUTE_FORCE_AUTH",
    "CREDENTIAL_STUFFING",
    "PRIVILEGE_ESCALATION",
    "DATA_EXFILTRATION_ATTEMPT",
    "RANSOMWARE_PRECURSOR",
    "LATERAL_MOVEMENT",
    "SQL_INJECTION_ATTEMPT",
    "PHISHING_PAYLOAD_EXECUTION",
]

_MOCK_ASSETS = [
    "VPN-GW-01",
    "SSO-PORTAL-PROD",
    "WINSRV-DC-02",
    "FILESERVER-01",
    "ENDPOINT-ACCT-07",
    "DB-PROD-03",
    "WEBAPP-EXT-01",
]

# ── I/O helpers ────────────────────────────────────────────────────────────────

def load_alerts() -> list[dict]:
    if not os.path.exists(ALERTS_FILE):
        return []
    try:
        with open(ALERTS_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def save_alerts(alerts: list[dict]) -> None:
    with open(ALERTS_FILE, "w", encoding="utf-8") as fh:
        json.dump(alerts, fh, indent=2)


def load_history() -> str:
    if not os.path.exists(HISTORY_FILE):
        return "_No incident history recorded yet._"
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as fh:
            content = fh.read().strip()
        return content if content else "_No incident history recorded yet._"
    except OSError:
        return "_Unable to read incident history log._"


def append_history(entry: str) -> None:
    with open(HISTORY_FILE, "a", encoding="utf-8") as fh:
        fh.write(entry + "\n\n")

# ── Metric calculators ─────────────────────────────────────────────────────────

def compute_metrics(alerts: list[dict]) -> tuple[int, int, int]:
    total     = len(alerts)
    critical  = sum(
        1 for a in alerts
        if a.get("severity", "").upper() == "CRITICAL" and not a.get("mitigated", False)
    )
    contained = sum(1 for a in alerts if a.get("mitigated", False))
    return total, critical, contained

# ── Mock threat injector ───────────────────────────────────────────────────────

def inject_mock_threat(identifier: str) -> dict:
    """Build and persist a new unmitigated CRITICAL alert for `identifier`."""
    inc_id     = f"INC-{random.randint(10000, 99999)}"
    event_type = random.choice(_MOCK_EVENT_TYPES)
    asset      = random.choice(_MOCK_ASSETS)
    timestamp  = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    # Decide whether the identifier looks like an IP or a username
    import re
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", identifier.strip()))
    source_ip = identifier.strip() if is_ip else f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"
    username  = "unknown" if is_ip else identifier.strip()

    new_alert = {
        "id"          : inc_id,
        "severity"    : "CRITICAL",
        "event_type"  : event_type,
        "description" : (
            f"Manually injected mock threat: {event_type.replace('_', ' ').title()} "
            f"detected on {asset}. Source identifier: {identifier}."
        ),
        "asset"       : asset,
        "username"    : username,
        "source_ip"   : source_ip,
        "timestamp"   : timestamp,
        "mitigated"   : False,
    }

    alerts = load_alerts()
    alerts.append(new_alert)
    save_alerts(alerts)
    return new_alert

# ── Threat processor ───────────────────────────────────────────────────────────

def process_pending_threats() -> list[dict]:
    """
    Mark all unmitigated CRITICAL alerts as contained, write history entries,
    fire a desktop notification, and return the list of handled alerts.
    """
    alerts  = load_alerts()
    handled = []
    now_ts  = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    now_hr  = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    for alert in alerts:
        if (
            alert.get("severity", "").upper() == "CRITICAL"
            and not alert.get("mitigated", False)
        ):
            rule_id = f"ACL-DENY-{alert['id']}"
            alert["mitigated"]    = True
            alert["mitigated_at"] = now_ts
            alert["rule_id"]      = rule_id
            handled.append(alert)

            # ── Append markdown report to incident_history.log ────────────────
            report = f"""---
## {alert['id']} — {alert['event_type']}
| Field | Value |
|---|---|
| **Severity** | {alert.get('severity', 'N/A')} |
| **Asset** | {alert.get('asset', 'N/A')} |
| **Source IP** | {alert.get('source_ip', 'N/A')} |
| **Username** | {alert.get('username', 'N/A')} |
| **Detection Time** | {alert.get('timestamp', 'N/A')} |
| **Contained At** | {now_ts} |
| **Rule Applied** | `{rule_id}` |

> **Description:** {alert.get('description', 'N/A')}

**Status:** ✅ MITIGATED — Automated containment applied at {now_hr}"""
            append_history(report)

    if handled:
        save_alerts(alerts)

        # ── Desktop notification via plyer ────────────────────────────────────
        if PLYER_AVAILABLE:
            try:
                _plyer_notification.notify(
                    title   = f"SOAR — {len(handled)} Threat(s) Contained",
                    message = (
                        f"{len(handled)} critical incident(s) automatically mitigated.\n"
                        "Full report appended to incident_history.log."
                    ),
                    app_name = "SOAR Incident Response Factory",
                    timeout  = 8,
                )
            except Exception:
                pass  # Notification failure is non-fatal

    return handled

# ── Page configuration ─────────────────────────────────────────────────────────

st.set_page_config(
    page_title = "SOAR Incident Response Factory",
    page_icon  = "🛡️",
    layout     = "wide",
)

# ── Custom CSS — cybersecurity dark theme ──────────────────────────────────────

st.markdown("""
<style>
    /* ── Google Font import ───────────────────────────────────────────────── */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');

    /* ── Base & global reset ──────────────────────────────────────────────── */
    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif !important;
    }

    /* Dark green base */
    .stApp {
        background-color: #050f07 !important;
        background-image:
            radial-gradient(ellipse 80% 50% at 50% -20%, rgba(0,255,65,0.07) 0%, transparent 60%),
            radial-gradient(ellipse 60% 40% at 80% 100%, rgba(0,255,65,0.04) 0%, transparent 55%);
    }

    /* Hide Streamlit default menu chrome */
    #MainMenu, footer { visibility: hidden; }
    header[data-testid="stHeader"] { background: transparent !important; }

    /* ── Scrollbar ────────────────────────────────────────────────────────── */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: #050f07; }
    ::-webkit-scrollbar-thumb { background: #00ff4144; border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: #00ff41aa; }

    /* ── Metric cards — glassmorphism ─────────────────────────────────────── */
    div[data-testid="metric-container"] {
        background: rgba(255,255,255,0.03) !important;
        backdrop-filter: blur(12px) !important;
        -webkit-backdrop-filter: blur(12px) !important;
        border: 1px solid rgba(0,255,65,0.25) !important;
        border-radius: 12px !important;
        padding: 20px 22px !important;
        box-shadow:
            0 0 0 1px rgba(0,255,65,0.08),
            0 4px 24px rgba(0,0,0,0.45),
            inset 0 1px 0 rgba(255,255,255,0.05) !important;
        transition: border-color 0.2s ease, box-shadow 0.2s ease !important;
    }
    div[data-testid="metric-container"]:hover {
        border-color: rgba(0,255,65,0.55) !important;
        box-shadow:
            0 0 0 1px rgba(0,255,65,0.20),
            0 0 18px rgba(0,255,65,0.12),
            0 4px 24px rgba(0,0,0,0.55),
            inset 0 1px 0 rgba(255,255,255,0.07) !important;
    }
    div[data-testid="metric-container"] label {
        color: #00ff41 !important;
        font-size: 0.70rem !important;
        font-weight: 700 !important;
        letter-spacing: 0.13em !important;
        text-transform: uppercase !important;
        font-family: 'Inter', sans-serif !important;
    }
    div[data-testid="metric-container"] [data-testid="stMetricValue"] {
        color: #e6f4f8 !important;
        font-size: 2.1rem !important;
        font-weight: 800 !important;
        letter-spacing: -0.02em !important;
        font-family: 'Inter', sans-serif !important;
    }
    /* Delta values */
    div[data-testid="metric-container"] [data-testid="stMetricDelta"] {
        font-size: 0.75rem !important;
        font-weight: 600 !important;
        letter-spacing: 0.03em !important;
    }

    /* ── Section headers ──────────────────────────────────────────────────── */
    .section-header {
        color: #00ff41;
        font-size: 0.68rem;
        font-weight: 700;
        letter-spacing: 0.16em;
        text-transform: uppercase;
        border-bottom: 1px solid rgba(0,255,65,0.20);
        padding-bottom: 7px;
        margin-bottom: 14px;
        margin-top: 6px;
        font-family: 'Inter', sans-serif;
    }

    /* ── Horizontal rule ──────────────────────────────────────────────────── */
    hr {
        border: none !important;
        border-top: 1px solid rgba(0,255,65,0.12) !important;
        margin: 1.4rem 0 !important;
    }

    /* ── Status indicator pills ───────────────────────────────────────────── */

    /* CRITICAL — soft glowing red */
    .pill-critical {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        background: rgba(255, 56, 56, 0.10);
        border: 1px solid rgba(255, 56, 56, 0.55);
        border-radius: 20px;
        padding: 3px 11px 3px 8px;
        font-size: 0.70rem;
        font-weight: 700;
        color: #ff6b6b;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        box-shadow: 0 0 8px rgba(255,56,56,0.22), inset 0 0 6px rgba(255,56,56,0.07);
        font-family: 'Inter', sans-serif;
        white-space: nowrap;
    }
    .pill-critical::before {
        content: '';
        display: inline-block;
        width: 6px;
        height: 6px;
        background: #ff4444;
        border-radius: 50%;
        box-shadow: 0 0 5px #ff4444, 0 0 10px #ff4444;
        animation: pulse-red 1.6s ease-in-out infinite;
    }
    @keyframes pulse-red {
        0%, 100% { opacity: 1; box-shadow: 0 0 5px #ff4444, 0 0 10px #ff4444; }
        50%       { opacity: 0.5; box-shadow: 0 0 2px #ff4444; }
    }

    /* HIGH — amber */
    .pill-high {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        background: rgba(255,166,0,0.10);
        border: 1px solid rgba(255,166,0,0.50);
        border-radius: 20px;
        padding: 3px 11px 3px 8px;
        font-size: 0.70rem;
        font-weight: 700;
        color: #ffb347;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        box-shadow: 0 0 6px rgba(255,166,0,0.15);
        font-family: 'Inter', sans-serif;
        white-space: nowrap;
    }
    .pill-high::before {
        content: '';
        display: inline-block;
        width: 6px;
        height: 6px;
        background: #ffa600;
        border-radius: 50%;
        box-shadow: 0 0 4px #ffa600;
    }

    /* MEDIUM — soft yellow */
    .pill-medium {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        background: rgba(255,214,0,0.09);
        border: 1px solid rgba(255,214,0,0.40);
        border-radius: 20px;
        padding: 3px 11px 3px 8px;
        font-size: 0.70rem;
        font-weight: 700;
        color: #ffe566;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        box-shadow: 0 0 5px rgba(255,214,0,0.10);
        font-family: 'Inter', sans-serif;
        white-space: nowrap;
    }
    .pill-medium::before {
        content: '';
        display: inline-block;
        width: 6px;
        height: 6px;
        background: #ffd700;
        border-radius: 50%;
    }

    /* CONTAINED — neon green badge */
    .pill-contained {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        background: rgba(0, 255, 136, 0.08);
        border: 1px solid rgba(0, 255, 136, 0.45);
        border-radius: 20px;
        padding: 3px 11px 3px 8px;
        font-size: 0.70rem;
        font-weight: 700;
        color: #00ff88;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        box-shadow: 0 0 8px rgba(0,255,136,0.15), inset 0 0 5px rgba(0,255,136,0.05);
        font-family: 'Inter', sans-serif;
        white-space: nowrap;
    }
    .pill-contained::before {
        content: '';
        display: inline-block;
        width: 6px;
        height: 6px;
        background: #00ff88;
        border-radius: 50%;
        box-shadow: 0 0 5px #00ff88, 0 0 10px #00ff8866;
    }

    /* PENDING — muted red */
    .pill-pending {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        background: rgba(218,54,51,0.10);
        border: 1px solid rgba(218,54,51,0.45);
        border-radius: 20px;
        padding: 3px 11px 3px 8px;
        font-size: 0.70rem;
        font-weight: 700;
        color: #f47067;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        box-shadow: 0 0 6px rgba(218,54,51,0.12);
        font-family: 'Inter', sans-serif;
        white-space: nowrap;
    }
    .pill-pending::before {
        content: '';
        display: inline-block;
        width: 6px;
        height: 6px;
        background: #da3633;
        border-radius: 50%;
        animation: pulse-red 1.6s ease-in-out infinite;
    }

    /* ── Dataframe — glassmorphism ────────────────────────────────────────── */
    .stDataFrame,
    div[data-testid="stDataFrameResizable"] {
        border-radius: 12px !important;
        overflow: hidden !important;
        border: 1px solid rgba(0,255,65,0.18) !important;
        box-shadow: 0 4px 24px rgba(0,0,0,0.40) !important;
    }
    /* Table header row */
    div[data-testid="stDataFrameResizable"] th {
        background: rgba(0,255,65,0.07) !important;
        color: #00ff41 !important;
        font-size: 0.70rem !important;
        font-weight: 700 !important;
        letter-spacing: 0.10em !important;
        text-transform: uppercase !important;
        border-bottom: 1px solid rgba(0,255,65,0.20) !important;
    }
    /* Table body cells */
    div[data-testid="stDataFrameResizable"] td {
        background: rgba(255,255,255,0.02) !important;
        color: #c9d1d9 !important;
        font-size: 0.82rem !important;
        border-bottom: 1px solid rgba(255,255,255,0.04) !important;
        font-family: 'JetBrains Mono', monospace !important;
    }
    div[data-testid="stDataFrameResizable"] tr:hover td {
        background: rgba(0,255,65,0.05) !important;
    }

    /* ── Console panels — glassmorphism ───────────────────────────────────── */
    .console-panel {
        background: rgba(255,255,255,0.025);
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
        border: 1px solid rgba(0,255,65,0.18);
        border-radius: 12px;
        padding: 22px 24px;
        box-shadow: 0 4px 24px rgba(0,0,0,0.40), inset 0 1px 0 rgba(255,255,255,0.04);
    }

    /* ── Streamlit buttons ────────────────────────────────────────────────── */
    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, rgba(0,255,65,0.15) 0%, rgba(0,180,60,0.10) 100%) !important;
        border: 1px solid rgba(0,255,65,0.55) !important;
        color: #00ff41 !important;
        font-weight: 700 !important;
        font-size: 0.83rem !important;
        letter-spacing: 0.06em !important;
        border-radius: 8px !important;
        box-shadow: 0 0 10px rgba(0,255,65,0.12) !important;
        transition: all 0.18s ease !important;
        font-family: 'Inter', sans-serif !important;
    }
    .stButton > button[kind="primary"]:hover {
        background: linear-gradient(135deg, rgba(0,255,65,0.28) 0%, rgba(0,180,60,0.20) 100%) !important;
        border-color: #00ff41 !important;
        box-shadow: 0 0 18px rgba(0,255,65,0.30), 0 0 4px rgba(0,255,65,0.15) !important;
        color: #fff !important;
    }
    .stButton > button[kind="primary"]:active {
        transform: scale(0.98) !important;
        box-shadow: 0 0 8px rgba(0,255,65,0.20) !important;
    }

    /* ── Text input ───────────────────────────────────────────────────────── */
    div[data-testid="stTextInput"] input {
        background: rgba(255,255,255,0.04) !important;
        border: 1px solid rgba(0,255,65,0.30) !important;
        border-radius: 8px !important;
        color: #e6f4f8 !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.84rem !important;
        caret-color: #00ff41 !important;
    }
    div[data-testid="stTextInput"] input:focus {
        border-color: #00ff41 !important;
        box-shadow: 0 0 0 2px rgba(0,255,65,0.15) !important;
        outline: none !important;
    }
    div[data-testid="stTextInput"] label {
        color: #8b949e !important;
        font-size: 0.78rem !important;
        font-weight: 600 !important;
        letter-spacing: 0.06em !important;
        text-transform: uppercase !important;
    }

    /* ── Alert / info / success / warning boxes ───────────────────────────── */
    div[data-testid="stAlert"] {
        border-radius: 8px !important;
        backdrop-filter: blur(8px) !important;
        -webkit-backdrop-filter: blur(8px) !important;
        font-size: 0.84rem !important;
    }

    /* ── Audit trail ──────────────────────────────────────────────────────── */
    .audit-trail-wrap {
        background: rgba(255,255,255,0.025);
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
        border: 1px solid rgba(0,255,65,0.18);
        border-radius: 12px;
        padding: 22px 26px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.81rem;
        color: #c9d1d9;
        box-shadow: 0 4px 24px rgba(0,0,0,0.40), inset 0 1px 0 rgba(255,255,255,0.04);
    }
    .audit-trail-wrap h2 {
        color: #00ff41;
        font-size: 0.95rem;
        font-weight: 700;
        border-bottom: 1px solid rgba(0,255,65,0.20);
        padding-bottom: 6px;
        margin-top: 18px;
        font-family: 'Inter', sans-serif;
    }
    .audit-trail-wrap hr {
        border-top: 1px solid rgba(0,255,65,0.10) !important;
    }
    .audit-trail-wrap table {
        border-collapse: collapse;
        width: 100%;
        margin: 10px 0;
    }
    .audit-trail-wrap th {
        color: #00ff41;
        font-size: 0.72rem;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        border-bottom: 1px solid rgba(0,255,65,0.25);
        padding: 6px 10px;
        font-family: 'Inter', sans-serif;
    }
    .audit-trail-wrap td {
        padding: 5px 10px;
        border-bottom: 1px solid rgba(255,255,255,0.05);
        color: #adbac7;
        font-size: 0.80rem;
    }
    .audit-trail-wrap blockquote {
        border-left: 3px solid rgba(0,255,65,0.40);
        margin: 10px 0;
        padding: 6px 14px;
        color: #8b949e;
        font-style: italic;
    }
    .audit-trail-wrap code {
        background: rgba(0,255,65,0.08);
        border: 1px solid rgba(0,255,65,0.20);
        border-radius: 4px;
        padding: 1px 6px;
        color: #00ff41;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.78rem;
    }

    /* ── Severity colour overrides inside table cells ─────────────────────── */
    .sev-critical { color: #ff6b6b !important; font-weight: 700 !important; }
    .sev-high     { color: #ffb347 !important; font-weight: 700 !important; }
    .sev-medium   { color: #ffe566 !important; font-weight: 600 !important; }
    .sev-low      { color: #58a6ff !important; font-weight: 600 !important; }
</style>
""", unsafe_allow_html=True)

# ── Header ─────────────────────────────────────────────────────────────────────

st.markdown("""
<div style="display:flex;align-items:center;gap:14px;margin-bottom:2px;">
  <div style="
      width:42px;height:42px;border-radius:10px;flex-shrink:0;
      background:rgba(0,255,65,0.10);border:1px solid rgba(0,255,65,0.40);
      display:flex;align-items:center;justify-content:center;font-size:1.35rem;
      box-shadow:0 0 14px rgba(0,255,65,0.18);">🛡️</div>
  <div>
    <h1 style="
        color:#e6f4f8;font-size:1.55rem;font-weight:800;margin:0;line-height:1.2;
        letter-spacing:-0.02em;font-family:'Inter',sans-serif;">
      Automated SOAR Incident Response Factory
    </h1>
    <p style="
        color:rgba(0,255,65,0.65);font-size:0.78rem;margin:3px 0 0;font-weight:500;
        letter-spacing:0.10em;text-transform:uppercase;font-family:'Inter',sans-serif;">
      Real-time monitoring &nbsp;·&nbsp; Automated containment &nbsp;·&nbsp; Corporate audit trail
    </p>
  </div>
</div>
""", unsafe_allow_html=True)
st.markdown("<hr/>", unsafe_allow_html=True)

# ── Load data ──────────────────────────────────────────────────────────────────

alerts = load_alerts()
total, active_critical, contained = compute_metrics(alerts)

# ── Metric cards ───────────────────────────────────────────────────────────────

st.markdown("<div class='section-header'>⬡ Live Security Posture</div>", unsafe_allow_html=True)
c1, c2, c3, c4 = st.columns(4)

c1.metric("Total Incidents",         total)
c2.metric("Active Critical Threats", active_critical,
          delta=f"{active_critical} unmitigated" if active_critical else "All clear",
          delta_color="inverse")
c3.metric("Automatically Contained", contained)
c4.metric("Containment Rate",        f"{(contained / total * 100):.0f}%" if total else "N/A")

st.markdown("<hr/>", unsafe_allow_html=True)

# ── Alert data table ───────────────────────────────────────────────────────────

st.markdown("<div class='section-header'>⬡ Incident Register — auth_alerts.json</div>", unsafe_allow_html=True)

# Render severity pill legend inline with the header
st.markdown(
    "<div style='display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px;'>"
    "<span class='pill-critical'>Critical</span>"
    "<span class='pill-high'>High</span>"
    "<span class='pill-medium'>Medium</span>"
    "<span class='pill-contained'>Contained</span>"
    "<span class='pill-pending'>Pending</span>"
    "</div>",
    unsafe_allow_html=True,
)

if alerts:
    df = pd.DataFrame(alerts)

    # Normalise and order columns for display
    display_cols = ["id", "severity", "event_type", "asset", "source_ip",
                    "username", "timestamp", "mitigated", "rule_id"]
    display_cols = [c for c in display_cols if c in df.columns]
    df_display   = df[display_cols].copy()

    col_rename = {
        "id"          : "Incident ID",
        "severity"    : "Severity",
        "event_type"  : "Event Type",
        "asset"       : "Affected Asset",
        "source_ip"   : "Source IP",
        "username"    : "Target User",
        "timestamp"   : "Detected At",
        "mitigated"   : "Mitigated",
        "rule_id"     : "Rule ID",
    }
    df_display.rename(columns=col_rename, inplace=True)
    df_display["Mitigated"] = df_display["Mitigated"].map({True: "✅ Contained", False: "🔴 Pending"})
    df_display["Severity"]  = df_display["Severity"].map(
        lambda s: {"CRITICAL": "🔴 CRITICAL", "HIGH": "🟠 HIGH", "MEDIUM": "🟡 MEDIUM"}.get(
            str(s).upper(), s
        )
    )

    st.dataframe(
        df_display,
        use_container_width = True,
        hide_index          = True,
    )
else:
    st.info("No alerts found in auth_alerts.json.")

st.markdown("<hr/>", unsafe_allow_html=True)

# ── Interactive controls ───────────────────────────────────────────────────────

st.markdown("<div class='section-header'>⬡ Threat Management Console</div>", unsafe_allow_html=True)
left_col, right_col = st.columns(2, gap="large")

# ── Left: Inject mock threat ───────────────────────────────────────────────────
with left_col:
    st.markdown("""
    <div class="console-panel">
      <p style="color:#00ff41;font-weight:700;font-size:0.88rem;margin:0 0 6px;
                letter-spacing:0.05em;font-family:'Inter',sans-serif;">
        ⚡ INJECT MOCK THREAT
      </p>
      <p style="color:#8b949e;font-size:0.80rem;margin:0 0 14px;line-height:1.55;">
        Simulate a new inbound threat by supplying a source username or IP address.
        A <span class='pill-critical' style='font-size:0.65rem;padding:2px 8px;'>Critical</span>
        alert will be written to <code style='color:#00ff41;'>auth_alerts.json</code> immediately.
      </p>
    </div>
    """, unsafe_allow_html=True)
    threat_input = st.text_input(
        label            = "Username or Source IP",
        placeholder      = "e.g.  attacker@evil.org  or  192.168.1.200",
        key              = "threat_input",
        label_visibility = "visible",
    )
    if st.button("⚡ Inject Threat", type="primary", use_container_width=True):
        if threat_input.strip():
            new_alert = inject_mock_threat(threat_input.strip())
            st.success(
                f"Threat **{new_alert['id']}** injected — "
                f"{new_alert['event_type']} on **{new_alert['asset']}**."
            )
            st.rerun()
        else:
            st.warning("Please enter a username or IP address before injecting.")

# ── Right: Process pending threats ────────────────────────────────────────────
with right_col:
    pending_count = sum(
        1 for a in alerts
        if a.get("severity", "").upper() == "CRITICAL" and not a.get("mitigated", False)
    )
    pending_html = (
        f"<span class='pill-pending'>{pending_count} pending</span>"
        if pending_count
        else "<span class='pill-contained'>All clear</span>"
    )
    st.markdown(f"""
    <div class="console-panel">
      <p style="color:#00ff41;font-weight:700;font-size:0.88rem;margin:0 0 6px;
                letter-spacing:0.05em;font-family:'Inter',sans-serif;">
        🔒 PROCESS PENDING CRITICAL THREATS
      </p>
      <p style="color:#8b949e;font-size:0.80rem;margin:0 0 10px;line-height:1.55;">
        Trigger the SOAR engine to evaluate and contain all unmitigated
        <span class='pill-critical' style='font-size:0.65rem;padding:2px 8px;'>Critical</span>
        alerts. A desktop notification fires and a full markdown report is appended to
        <code style='color:#00ff41;'>incident_history.log</code>.
      </p>
      <p style="margin:0;font-size:0.80rem;color:#8b949e;">
        Status: &nbsp;{pending_html}
      </p>
    </div>
    """, unsafe_allow_html=True)

    if st.button("🚨 Process & Contain All Critical Threats", type="primary", use_container_width=True):
        handled = process_pending_threats()
        if handled:
            notif_note = " Desktop notification fired." if PLYER_AVAILABLE else " (Install `plyer` for desktop notifications.)"
            st.success(
                f"**{len(handled)} threat(s) contained.** "
                f"Reports appended to `incident_history.log`.{notif_note}"
            )
            for h in handled:
                st.markdown(
                    f"- `{h['id']}` — **{h['event_type']}** on `{h['asset']}` → "
                    f"Rule `{h.get('rule_id', 'N/A')}` applied.",
                )
            st.rerun()
        else:
            st.info("No pending critical threats found — nothing to process.")

st.markdown("<hr/>", unsafe_allow_html=True)

# ── Corporate audit trail ──────────────────────────────────────────────────────

st.markdown(
    "<div class='section-header'>⬡ Corporate Audit Trail — incident_history.log</div>",
    unsafe_allow_html=True,
)

history = load_history()

# Render history inside the styled audit-trail wrapper.
# We open the wrapper div, let Streamlit render the markdown natively, then close it.
st.markdown("<div class='audit-trail-wrap'>", unsafe_allow_html=True)
if history in ("_No incident history recorded yet._", "_Unable to read incident history log._"):
    st.markdown(
        "<p style='color:#484f58;font-style:italic;margin:0;'>No incident history recorded yet.</p>",
        unsafe_allow_html=True,
    )
else:
    st.markdown(history)
st.markdown("</div>", unsafe_allow_html=True)

# ── Footer ─────────────────────────────────────────────────────────────────────

st.markdown("<hr/>", unsafe_allow_html=True)
st.markdown("""
<p style="
    text-align:center;
    color:rgba(0,255,65,0.25);
    font-size:0.72rem;
    letter-spacing:0.10em;
    text-transform:uppercase;
    font-family:'Inter',sans-serif;
    margin:0;
">
  SOAR Incident Response Factory &nbsp;·&nbsp; Confidential — Internal Use Only
  &nbsp;·&nbsp; All automated actions are logged for compliance review
</p>
""", unsafe_allow_html=True)
