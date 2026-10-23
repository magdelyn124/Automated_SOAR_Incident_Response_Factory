# 🛡️ Automated SOAR Incident Response Factory

> **Enterprise-grade Security Orchestration, Automation, and Response (SOAR) platform built in Python — featuring a real-time Streamlit dashboard, automated threat containment, and a persistent corporate audit trail.**

---

## 📌 Project Description

The **Automated SOAR Incident Response Factory** simulates the core capabilities of a production SOAR platform in a fully self-contained, portable Python environment. It bridges the gap between raw threat intelligence data and actionable security operations workflows — providing real-time incident visibility, one-click automated containment, and a compliance-ready audit log without requiring an external database, cloud service, or enterprise SIEM.

The platform is built around two components that can operate independently or together:

- **`app.py`** — An interactive Streamlit web dashboard for live monitoring, threat injection, and containment.
- **`soar_engine.py`** — A headless background daemon that polls for unmitigated critical threats every 5 seconds and auto-contains them.

---

## 📂 Dataset / Incident Register

All security incident data is stored in a plain JSON file on disk:

- **[`auth_alerts.json`](auth_alerts.json)** — The live incident register. A JSON array of alert objects with fields: `id`, `severity`, `event_type`, `asset`, `source_ip`, `username`, `timestamp`, `mitigated`, `mitigated_at`, `rule_id`.
- **[`incident_history.log`](incident_history.log)** — Append-only Markdown audit log. Generated automatically each time a threat is contained.

Seed scripts are provided to populate the register with realistic enterprise cyberattack scenarios before first run:

| Script | Records | Schema |
|---|---|---|
| [`seed_threat_data.py`](seed_threat_data.py) | 5 alerts (3 CRITICAL, 1 HIGH, 1 MEDIUM) | Full canonical — compatible with all dashboard features |
| [`seed_threats.py`](seed_threats.py) | 3 alerts (2 CRITICAL, 1 HIGH) | Simplified testing harness schema |

---

## 🖥️ Technologies Used

| Technology | Version | Role |
|---|---|---|
| Python | 3.10+ | Core runtime |
| [Streamlit](https://streamlit.io) | 1.66.1 | Web dashboard framework |
| [Pandas](https://pandas.pydata.org) | 3.1.0 | DataFrame rendering for the incident register table |
| [Plyer](https://plyer.readthedocs.io) | 2.1.0 | Cross-platform native desktop notifications |
| Standard Library (`json`, `re`, `datetime`, `random`, `os`, `time`, `textwrap`) | Built-in | JSON I/O, IP detection, timestamps, mock data, file ops |

---

## ⚙️ Setup & Run Instructions

### 1. Clone or download the repository

```bash
git clone https://github.com/yourname/automated-soar-factory.git
cd automated-soar-factory
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Seed the incident register

Populate `auth_alerts.json` with realistic test data before launching the dashboard:

```bash
python seed_threat_data.py
```

> ⚠️ If `soar_engine.py` is running, stop it before seeding (`Ctrl-C`) — it will auto-contain the 3 pending CRITICAL alerts within 5 seconds of the file being written.

### 4. Launch the Streamlit dashboard

```bash
streamlit run app.py
```

The dashboard opens automatically at **http://localhost:8501**.  
The page re-renders live on every button click — no manual refresh needed.

### 5. (Optional) Run the headless SOAR engine

Open a second terminal and run:

```bash
python soar_engine.py
```

The engine polls `auth_alerts.json` every 5 seconds, auto-mitigates any unmitigated `CRITICAL` alerts, and prints a formatted **Executive Incident Brief** to the terminal. Stop with `Ctrl-C`.

---

## 🗂️ Project Structure

```
automated-soar-factory/
│
├── app.py                  # Streamlit dashboard (main entry point)
├── soar_engine.py          # Headless SOAR polling daemon
├── fire_alert.py           # Multi-stage live threat injection simulator
├── seed_threat_data.py     # Production test fixture (5 canonical alerts)
├── seed_threats.py         # Minimal testing harness (3 simplified alerts)
│
├── auth_alerts.json        # Live incident register (read/written at runtime)
├── incident_history.log    # Append-only containment audit trail (auto-generated)
│
├── requirements.txt        # Python dependency pins
└── README.md               # This file
```

---

## ✨ Key Features

| Feature | Description |
|---|---|
| **Live Metric Cards** | Total Incidents, Active Critical Threats, Automatically Contained, Containment Rate — recalculated on every page load |
| **Incident Register Table** | Full `auth_alerts.json` rendered as a Pandas DataFrame with severity emoji prefixes and mitigation state labels |
| **Threat Injection Console** | Type a username or IP → click **Inject** → new `CRITICAL` alert written to disk instantly |
| **Automated Containment** | Click **Process** → all pending CRITICAL alerts stamped mitigated, Markdown report appended to audit log, desktop notification fired |
| **Corporate Audit Trail** | Live render of `incident_history.log` at the bottom of the dashboard — structured Markdown table per incident |
| **Dark Cybersecurity Theme** | Custom CSS: dark-green base (`#050f07`), glassmorphism cards, animated status pills, JetBrains Mono font |

---

## 🚦 Threat Severity Levels

| Level | Colour | Auto-Contained by Engine |
|---|---|---|
| `CRITICAL` | 🔴 Red | ✅ Yes |
| `HIGH` | 🟠 Amber | ❌ No (manual review) |
| `MEDIUM` | 🟡 Yellow | ❌ No (manual review) |

---

## 📋 Sample Incident Register Entry

```json
{
  "id": "INC-88312",
  "severity": "CRITICAL",
  "event_type": "RANSOMWARE_INITIAL_ACCESS",
  "description": "Spear-phishing payload executed on ENDPOINT-FIN-03. Cobalt Strike beacon communicating with known RaaS C2 at 185.220.101.55.",
  "asset": "ENDPOINT-FIN-03 (10.10.3.44)",
  "username": "p.wright",
  "source_ip": "185.220.101.55",
  "geo_location": "Minsk, Belarus",
  "timestamp": "2026-11-14T09:17:04Z",
  "mitigated": false,
  "rule_id": null
}
```

---

## 📄 License

This project is for educational and demonstration purposes.

---

*Built with Python · Streamlit · Pandas · Plyer*
