# WinSentinel 🛡️

> **Windows Security Audit, Log Analysis and Risk Scoring Framework**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0-green?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![SQLite](https://img.shields.io/badge/Database-SQLite-lightblue?logo=sqlite)](https://sqlite.org/)
[![License](https://img.shields.io/badge/License-Academic-orange)](./LICENSE)
[![Tests](https://img.shields.io/badge/Tests-67%20Passing-brightgreen)](#running-tests)

A Python-based Windows security posture analysis tool built as a micro-project for three academic cybersecurity subjects:
**VAPT Lab** · **Security Information Management** · **Application Security**

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Web Dashboard](#web-dashboard)
- [Security Architecture](#security-architecture)
- [Risk Scoring Methodology](#risk-scoring-methodology)
- [Running Tests](#running-tests)
- [Known Limitations](#known-limitations)
- [Academic Subject Mapping](#academic-subject-mapping)

---

## Overview

WinSentinel audits a Windows machine's security posture by:

1. **Auditing Windows configuration** — 30+ checks covering password policies, SMBv1, RDP exposure, firewall profiles, Windows Defender, UAC, Guest account, open ports, and more.
2. **Analysing Windows Security Event Logs** — detects brute-force logon attempts (Event ID 4625), account lockouts (4740), and credential compromise patterns.
3. **Inventorying installed software** — enumerates Windows Registry for installed applications and cross-references allowlisted apps against the **NIST National Vulnerability Database (NVD)** CVE feed.
4. **Scoring security posture** — uses a **NIST SP 800-30** risk matrix (Likelihood × Impact) to calculate a 0–100 posture score with severity-weighted penalty deductions.
5. **Visualising results** — SOC-analyst-style **Flask web dashboard** with Chart.js charts, expandable findings, incident alerts, and scan history trend.
6. **Generating reports** — downloadable self-contained **HTML audit reports** (A4 print-to-PDF ready).

### Ethical Scope

> ⚠️ WinSentinel audits **only the local machine** (`127.0.0.1`). All checks are **read-only** and **non-destructive**. No exploits are executed, no configuration is modified, and no remote hosts are contacted. All subprocess calls use argument lists — `shell=True` is never used.

---

## Features

| Module | What It Does |
|---|---|
| **Config Audit** | 30+ Windows checks: password policy, SMBv1, RDP/NLA, firewall, Defender, UAC, open ports, Guest account |
| **Event Log Analysis** | Reads Security Event Log via `wevtutil` / `Get-WinEvent`, correlates failed logons into brute-force alerts |
| **Software Inventory** | Enumerates HKLM and HKCU registry hives for all installed applications |
| **CVE Lookup** | Queries NVD API v2 for CVEs on allowlisted software, with 24-hour SQLite caching |
| **Risk Scoring** | NIST SP 800-30 Likelihood × Impact → severity band → posture score deduction |
| **Web Dashboard** | "Ops console" Flask UI: posture gauge, risk heat strip, Chart.js charts, filterable findings, live scan pipeline |
| **Scan Comparison** | Diff two scans to see new, resolved and still-open risks (drift detection) |
| **CSV Export** | Export any scan's findings for spreadsheets or ticketing tools |
| **Report Builder** | Self-contained HTML report with inline CSS and `@media print` for A4 printing |
| **CLI Interface** | `scan`, `serve`, `demo`, `set-password` subcommands |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      main.py (CLI)                      │
│         scan | serve | demo | set-password              │
└────┬────────────┬──────────────┬──────────────┬─────────┘
     │            │              │              │
     ▼            ▼              ▼              ▼
collectors/   analysis/       risk/          web/
config_audit  bruteforce   scoring.py      app.py (Flask)
event_logs               remediation.py  auth.py
software_inv                             views.py
nvd_client                               scanner.py
     │            │              │              │
     └────────────┴──────────────┘              │
                  │                             │
                  ▼                             ▼
              db/database.py ←──────── db/models.py
              (SQLite)
                  │
                  ▼
             reports/
          report_builder.py
```

---

## Project Structure

```
WinSentinel/
├── main.py                         # CLI entrypoint
├── config.py                       # Central config (loads .env)
├── requirements.txt
├── .env.example                    # Copy to .env and customise
├── PROJECT_CONTEXT.md              # Academic project brief & decisions
│
├── collectors/                     # Data collection modules
│   ├── config_audit.py             # 30+ Windows configuration checks
│   ├── event_logs.py               # Security Event Log reader
│   ├── software_inventory.py       # Windows Registry software enumeration
│   └── nvd_client.py               # NVD REST API v2 CVE lookup + caching
│
├── analysis/                       # Attack detection
│   └── bruteforce.py               # Brute-force / lockout / compromise detection
│
├── risk/                           # Risk scoring engine
│   ├── scoring.py                  # NIST SP 800-30 posture score calculator
│   └── remediation.py              # Per-check remediation advice lookup table
│
├── db/                             # Database layer
│   ├── database.py                 # SQLite schema + parameterised query helpers
│   └── models.py                   # Finding, Alert, SoftwareItem, Scan dataclasses
│
├── web/                            # Flask web dashboard
│   ├── app.py                      # Flask application factory
│   ├── auth.py                     # Login/logout + brute-force throttle
│   ├── views.py                    # Dashboard routes + /api/summary JSON feed
│   ├── scanner.py                  # Background scan thread manager
│   ├── security.py                 # Input validators + CSP/security headers
│   ├── templates/
│   │   ├── layout.html             # Fixed sidebar + topbar shell
│   │   ├── login.html
│   │   ├── dashboard.html          # Score ring, Chart.js, top-5 risks
│   │   ├── findings.html           # Filterable findings table with expand/collapse
│   │   ├── alerts.html             # Incident alerts table
│   │   ├── software.html           # Software inventory + CVE findings
│   │   ├── history.html            # Scan history + posture trend chart
│   │   └── report_preview.html     # Report preview + download button
│   └── static/
│       ├── css/app.css             # Dark SOC-analyst stylesheet
│       ├── js/app.js               # Chart.js renderer + scan polling + row expand
│       └── vendor/chart.umd.min.js # Vendored Chart.js (no CDN calls)
│
├── reports/                        # Report generation
│   └── report_builder.py           # Self-contained HTML report (A4 print-ready)
│
├── scripts/                        # Demo / simulation utilities
│   ├── generate_failed_logins.py   # Simulate Event Log 4625 entries
│   └── load_sample_events.py       # Load fixture events into DB
│
├── tests/                          # Unit & integration tests (67 tests)
│   ├── test_skeleton.py            # DB schema, user auth, config defaults
│   ├── test_config_parsers.py      # Config audit parser coverage
│   ├── test_bruteforce.py          # Brute-force detection logic
│   ├── test_scoring.py             # Risk scoring + remediation lookup
│   ├── test_software_nvd.py        # NVD client, caching, severity mapping
│   └── test_validation.py          # Flask security headers, CSRF, login throttle
│
└── fixtures/
    └── sample_command_outputs/     # Sample outputs for offline unit tests
```

---

## Prerequisites

| Requirement | Version |
|---|---|
| **Python** | 3.10 or higher |
| **OS** | Windows 10 / 11 / Server 2019+ |
| **Privileges** | Administrator (for live audit; demo works without) |

---

## Installation

### 1. Clone the repository

```powershell
git clone https://github.com/PranavShirke/winsentinel.git
cd winsentinel
```

### 2. Install Python dependencies

```powershell
pip install -r requirements.txt
```

### 3. Configure environment

```powershell
copy .env.example .env
```

Open `.env` and set your `SECRET_KEY` (if left empty a random per-run key is used and you are signed out on restart). The admin password must be at least 12 characters.

> On machines where `python` is only the Microsoft Store stub, use `py` instead (for example `py main.py serve`).

Generate a strong key with:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

### 4. Set the admin dashboard password

```powershell
python main.py set-password
```

---

## Usage

### Option A — Live scan (requires Administrator)

Open **PowerShell as Administrator**, then:

```powershell
python main.py scan
python main.py serve
```

### Option B — Demo data (no admin required)

```powershell
python main.py demo
python main.py serve
```

Open your browser at **[http://127.0.0.1:5000](http://127.0.0.1:5000)** to view the product landing page, then select **Administrator sign in** and log in with the password you set.

---

## Command Reference

| Command | Description |
|---|---|
| `python main.py set-password` | Set / update admin dashboard password |
| `python main.py set-password -u analyst` | Set password for a custom username |
| `python main.py scan` | Run full live audit *(requires Administrator)* |
| `python main.py serve` | Start web dashboard on `127.0.0.1:5000` |
| `python main.py demo` | Load sample findings for UI demonstration |

---

## Web Dashboard

| Page | URL | Description |
|---|---|---|
| **Login** | `/login` | Username + password with brute-force lockout |
| **Dashboard** | `/dashboard` | Posture gauge, risk heat strip, severity / module / failed-logon charts, top 5 risks |
| **Findings** | `/findings` | All audit checks with severity / module / status / text search filters; click any row to expand evidence + remediation |
| **Alerts** | `/alerts` | Correlated brute-force and incident detections with source IP |
| **Software & CVEs** | `/software` | Installed software registry inventory with NVD CVE flags |
| **Scan History** | `/history` | All previous scans with posture score trend chart |
| **Compare scans** | `/compare` | New / resolved / still-open findings between two completed scans, with score change |
| **Findings CSV** | `/findings/export.csv` | Download all findings of a scan (formula-injection safe) |
| **Report** | `/report` | Report preview + **Download HTML Report** button |

**Run new scan:** Click **"Run new scan"** from any page to start a background audit with live progress banner.

**Download report:** Navigate to `/report` → click **"Download Standalone HTML Report"** for a fully self-contained, print-to-A4-PDF audit report.

---

## Security Architecture

| Control | Implementation |
|---|---|
| **Password Hashing** | Werkzeug `scrypt` (Argon2-grade) |
| **CSRF Protection** | Flask-WTF `CSRFProtect` on all `POST` routes |
| **Content Security Policy** | `default-src 'self'` — no inline scripts, no CDN requests |
| **Clickjacking** | `X-Frame-Options: DENY` + `frame-ancestors 'none'` |
| **MIME Sniffing** | `X-Content-Type-Options: nosniff` |
| **Session Security** | `HttpOnly`, `SameSite=Lax`, 30-minute inactivity timeout |
| **Login Throttle** | 5 failed attempts → 5-minute lockout per IP |
| **SQL Injection** | 100% parameterised queries — no string interpolation |
| **Subprocess Safety** | Argument lists only — `shell=True` never used |
| **Network Binding** | Flask bound strictly to `127.0.0.1` |
| **Cache Control** | `no-store` on all authenticated responses |

---

## Risk Scoring Methodology

WinSentinel implements **NIST SP 800-30** risk scoring:

```
Risk Score   = Likelihood (1–5) × Impact (1–5)          [max = 25]

Severity Bands:
  Critical   →  Risk Score ≥ 16
  High       →  Risk Score ≥  9
  Medium     →  Risk Score ≥  4
  Low        →  Risk Score ≥  1
  Info       →  Risk Score =  0 (pass / informational)

Posture Score = 100 − Σ penalties   (floor = 0)
  Critical penalty  = −15
  High penalty      =  −8
  Medium penalty    =  −3
  Low penalty       =  −1
```

---

## Running Tests

```powershell
pip install pytest
python -m pytest tests/ -v
```

Expected: **67 passed** in ~10 seconds.

```
tests/test_skeleton.py         4 tests   DB schema, user auth, config defaults
tests/test_config_parsers.py  14 tests   All config audit parsers
tests/test_bruteforce.py       7 tests   Brute-force detection logic
tests/test_scoring.py          7 tests   Risk matrix, penalties, remediation
tests/test_software_nvd.py     8 tests   NVD client, caching, CVSS mapping
tests/test_validation.py       6 tests   Flask headers, CSRF, login throttle
tests/test_web.py             21 tests   End-to-end web flow, open-redirect, CSV, compare, CVE version matching
```

---

## Known Limitations

- **Windows only** — Event log collection uses `wevtutil.exe` / `Get-WinEvent`; config checks use `net`, `netsh`, `sc`, and PowerShell cmdlets.
- **Local machine only** — No network or remote scanning by design.
- **NVD rate limits** — The free NVD API allows ~5 requests/30s. Set `NVD_API_KEY` in `.env` for higher throughput.
- **CVE version filtering** — CVEs are kept only when the installed version falls inside NVD's published CPE version range; CVEs with no usable version data for the product are dropped (possible false negatives, far fewer false positives).
- **CPE mapping** — Only applications listed in `NVD_ALLOWLIST` (in `config.py`) are checked against NVD. The list covers common apps (Chrome, Firefox, Python, 7-Zip, VLC, etc.).
- **Elevated privileges** — Running without Administrator causes Event Log and some policy checks to return `error` status instead of real values.
- **WMIC deprecated** — Windows 11 22H2+ deprecates WMIC. WinSentinel uses `sc query`, `netsh`, and PowerShell alternatives throughout.

---

## Academic Subject Mapping

| Subject | WinSentinel Modules |
|---|---|
| **VAPT Lab** | `collectors/config_audit.py` (SMBv1, RDP, UAC, ports), `analysis/bruteforce.py`, `collectors/nvd_client.py` |
| **Security Information Management** | `collectors/event_logs.py`, `analysis/bruteforce.py`, `risk/scoring.py`, `db/database.py`, scan history |
| **Application Security** | `web/security.py` (CSP, X-Frame-Options, CSRF), `web/auth.py` (session, throttle), `db/database.py` (parameterised SQL) |

---

## License

Academic project — educational use only. Not intended for production deployment.

---

*Built with Python · Flask · SQLite · Chart.js · NIST SP 800-30*
