# WinSentinel: Project Context and Decisions

## 1. Project context

I am a cybersecurity student building a micro-project for three subjects: VAPT Lab, Security Information Management, and Application Security. I must understand and be able to explain every module in an interview, so code clarity matters more than cleverness. Keep code simple, commented, and modular, with a docstring on every function.

Project: WinSentinel, a Windows Security Audit, Log Analysis and Risk Scoring Framework.

One-line pitch: a Python tool that audits a Windows machine's security posture, analyzes Windows Event Logs for attacks, checks installed software against known CVEs, and produces a risk-scored compliance report in a Flask dashboard.

What it does:
1. Config audit: password policy, local users and admins, firewall, Defender, RDP/SMB exposure, listening ports.
2. Log analysis: parse Security events 4625 (failed logon), 4624 (logon), 4720 (account created), plus 4672, 4740, 4732, and detect brute-force patterns.
3. Vulnerability check: inventory installed software and query the NVD API for CVEs and CVSS scores.
4. Risk scoring: every finding gets Likelihood x Impact (NIST SP 800-30 style), a severity and a remediation step.
5. Dashboard and report: Flask dashboard plus an exportable HTML report.

Syllabus mapping (must be reflected in docs/syllabus_mapping.md):
- VAPT Lab: password audit, privilege audit, open port scan of own machine, log analysis with Python scripts, CVE-based compliance reporting.
- Security Information Management: likelihood x impact risk assessment (NIST SP 800-30), access control and accountability checks, incident detection (brute-force alerts), audits in a Windows environment.
- Application Security: the tool is built securely (input validation, no hardcoded secrets, security headers, CSRF, authentication), plus a STRIDE threat model and a secure SDLC write-up.

Legal and ethical scope: the tool audits ONLY the machine it runs on (my own). No remote scanning, no exploitation, no auto-remediation, no Active Directory domain auditing. State this in the README, the report and the dashboard footer.

## 2. Decisions (final, do not change without asking me)

### Tech stack
- Python 3.10+, Windows only. Run from an elevated (Administrator) terminal; detect and warn clearly if not elevated.
- Libraries: flask, flask-wtf (CSRF), psutil, requests, python-dotenv, pywin32 (only if needed; prefer PowerShell with JSON output via subprocess), werkzeug (password hashing). Optional: reportlab.
- Database: SQLite via the built-in sqlite3 module, parameterized queries only.
- Frontend: Jinja2 templates, plain CSS, minimal vanilla JS. No React, no Tailwind, no CSS framework.
- Chart.js vendored locally in web/static/vendor/. No CDNs, no external fonts, no external requests from the browser.
- Windows data sources: PowerShell (Get-WinEvent, Get-MpComputerStatus, Get-SmbServerConfiguration, ConvertTo-Json), net accounts, net user, net localgroup administrators, netsh advfirewall, secedit, registry via winreg.

### Behavior rules
- Read-only: never change system settings. Recommend only.
- Always call subprocess with argument lists, never shell=True, never build commands from user input.
- Every check returns a Finding with status pass, fail or error. If a command fails (missing, access denied, empty output), return status error with a clear message. Never crash the scan.
- Scans run in a background thread. Only one scan at a time (use a lock). The UI polls GET /scan/status (JSON) until finished.
- Make the tool testable without real attacks: include a JSON fixture of sample events and a demo script (scripts/generate_failed_logins.py) that creates failed logins against a local test account I own.

### Finding and scoring model
- Finding fields: id, scan_id, module (config, logs, software), title, evidence, status (pass, fail, error), likelihood (1-5), impact (1-5), risk_score, severity, remediation.
- risk_score = likelihood x impact (1-25).
- Severity bands: Low 1-4, Medium 5-9, High 10-15, Critical 16-25. Passing checks get severity "Info" and no score.
- For CVE findings: impact derived from CVSS (0-3.9 -> 2, 4-6.9 -> 3, 7-8.9 -> 4, 9-10 -> 5), likelihood set by simple documented rules (for example higher if the software is a browser or internet-facing).
- Posture score (0-100) = 100 minus penalties for failed findings: Critical 15, High 8, Medium 3, Low 1, floored at 0. Document this formula in docs and in the report methodology section.
- Document the method as aligned with NIST SP 800-30 (likelihood x impact risk matrix).

### Brute-force detection defaults (configurable in config.py)
- 5 failed logons (4625) for the same account or the same source IP within 10 minutes -> alert (High).
- Successful logon (4624) after 5 or more failures for the same account within 10 minutes -> "Possible compromise" (Critical).
- 4720 account created -> alert (Medium). 4740 account lockout -> alert (Medium). 4732 user added to a privileged group -> alert (High).
- Default analysis window: last 7 days, configurable.

### CVE lookup scope (be honest about limitations)
- NVD matches by CPE, not by Windows display names. Do NOT claim full coverage.
- Check only an allowlist of well-known products (Chrome, Firefox, Edge, 7-Zip, Java, Python, VLC, Notepad++, WinRAR, Adobe Reader). Match by product keyword, then filter results by version where possible.
- Cache every NVD response in the cve_cache table (cache TTL 24h). Respect rate limits: about 5 requests per 30 seconds without an API key, more with one. API key comes from the NVD_API_KEY environment variable (optional).
- Handle timeouts and offline mode (show "CVE check skipped, offline" as an error finding).
- Document false-positive and false-negative limitations in the README and in the report.

### Authentication
- Single admin account. Password set once via CLI: python main.py set-password (prompt with getpass, store werkzeug hash in a users table). No default password.
- Login throttling: after 5 failed dashboard logins, lock further attempts for 5 minutes. Log all login successes and failures to the tool's own log file.
- Session cookie: HttpOnly, SameSite=Lax. Session timeout 30 minutes. Bind Flask to 127.0.0.1 only. debug=False always.

### Security headers and web hardening
- On every response: Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'", X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy no-referrer, Cache-Control no-store for authenticated pages.
- No inline scripts or inline styles anywhere (CSP forbids them). Pass chart data to JavaScript via a JSON endpoint (GET /api/summary), not inline script blocks.
- CSRF protection on every POST. Validate all query parameters (scan id, severity, module, page) against allowlists or integer ranges. Jinja autoescaping on, never use |safe on data from scans.
- SECRET_KEY and NVD_API_KEY come from .env. Provide .env.example. Add .env and the database file to .gitignore.

### UI design decisions
Style: dark, SOC-analyst look. Clean and information-dense, not flashy.

Layout: fixed left sidebar (220px) with the logo text "WinSentinel" and nav links, top bar showing hostname, last scan time and a "Run new scan" button, and a main content area (max width 1280px). The sidebar collapses to a top menu under 800px.

Nav: Dashboard, Findings, Alerts, Software and CVEs, Scan History, Report, Logout.

Colors (define as CSS variables in one file, web/static/css/app.css):
- Background #0f1419, panel #171d26, border #263040, text #e6edf3, muted text #8b98a9, accent #3b82f6.
- Severity colors: Critical #ef4444, High #f97316, Medium #eab308, Low #22c55e, Info #64748b, Error #a78bfa.
- Severity is ALWAYS shown as a text badge (never color alone) for accessibility.

Typography: system font stack for UI, monospace stack for evidence, event data and commands. Base 15px.

Pages:
1. Login: centered card, password field, error message area.
2. Dashboard: row of 4 summary cards (Posture score as a large number with a ring, Total failed findings, Active alerts, Vulnerable software count); below that a doughnut chart (findings by severity), a bar chart (findings by module), a line or bar chart (failed logons per day over the window), and a "Top 5 risks" table.
3. Findings: filter bar (severity, module, status, text search), table with columns severity badge, title, module, risk score (L x I), status. Clicking a row expands a detail panel with evidence (monospace), explanation and remediation steps. Sortable by risk score.
4. Alerts: table of detections with timestamp, type, account, source IP, count, severity, details. Brute-force and possible-compromise alerts highlighted.
5. Software and CVEs: installed software table, with a CVE sub-table for flagged products (CVE id linking out as plain text only, CVSS score, severity, description truncated).
6. Scan History: list of past scans with date, posture score and finding counts; click to view that scan; simple trend chart of posture score over time.
7. Report: preview page with a "Download HTML report" button.
Empty states: every page shows a friendly message and a "Run new scan" prompt when no scan exists. While a scan runs, show a progress bar with the current step (Config audit, Log analysis, Software inventory, CVE lookup, Scoring).
Responsive down to tablet width. Keyboard accessible, visible focus outlines, proper labels on form fields.

### Report design
Standalone single-file HTML (CSS inlined into the report file, which is a downloaded document, not a page served under the CSP). Light theme with a print stylesheet (@media print) so Print to PDF looks clean, A4. Sections: cover (title, hostname, scan date, posture score), executive summary, scope and ethics statement, methodology (scoring formula, severity bands, NIST SP 800-30 alignment), findings by severity with remediation, alerts, CVE table, limitations, appendix of passed checks. PDF via reportlab is optional and comes last.
