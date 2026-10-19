# Syllabus Mapping

WinSentinel is one micro-project covering three subjects. All checks run live against the local machine; sample data exists only as a fallback for demos and tests.

## VAPT Lab

| Syllabus area | What WinSentinel does | Where |
|---|---|---|
| Module 4: password audit | Reads `net accounts`: minimum length, lockout threshold, history, maximum age | `collectors/config_audit.py::check_password_policy` |
| Module 4: privilege / active-directory style audit | Enumerates local users and the Administrators group, Guest account state | `check_user_accounts` |
| Module 4: open-port audit of own machine | `psutil` listening sockets compared with a risky-port list (23, 135, 139, 445, 3389, 5985) | `check_listening_ports` |
| Module 5: log analysis with Python | `Get-WinEvent` for 4625, 4624, 4720, 4740, 4732, 4672; sliding-window brute-force correlation | `collectors/event_logs.py`, `analysis/bruteforce.py` |
| Module 6: compliance report with CVE scores | NVD CVEs with CVSS, downloadable PDF and HTML reports, CSV export | `collectors/nvd_client.py`, `reports/pdf_report.py`, `reports/report_builder.py` |

## Security Information Management

| Syllabus area | What WinSentinel does | Where |
|---|---|---|
| Module 3: risk assessment (NIST SP 800-30) | Likelihood x impact (1-25), severity bands, posture score formula | `risk/scoring.py` |
| Module 4: access control and accountability | Admin and Guest audit; dashboard login with lockout and audit log | `web/auth.py` |
| Module 5: incident management | Brute-force, possible-compromise, new-account, lockout and privileged-group alerts | `analysis/bruteforce.py` |
| Module 6: audits in a Windows environment | Firewall, Defender, SMB, RDP/NLA, UAC, BitLocker, Secure Boot, patch level, credential-theft protections, shares, persistence; scan history and comparison for drift | `collectors/config_audit.py`, `collectors/extra_checks.py`, `/compare` |
| Module 3: risk assessment (treatment) | Risk register: accept, mitigate (in progress) or reject (false positive) with justification, plus adjusted score | `/findings`, `db/database.py` |
| Module 5: incident management (classification) | Alerts tagged with MITRE ATT&CK techniques; CIS Controls v8 coverage view | `risk/frameworks.py`, `/frameworks` |

## Application Security

| Syllabus area | What WinSentinel does | Where |
|---|---|---|
| Module 3: security headers, input validation | CSP, X-Frame-Options, nosniff, Referrer/Permissions-Policy; allow-list validation | `web/security.py` |
| Module 4: secure SDLC | Written process with verification and release checklist | `docs/secure_sdlc.md` |
| Module 6: threat modelling | STRIDE analysis with data-flow diagram and abuse cases | `docs/threat_model.md` |
| Secure coding | Parameterised SQL, no `shell=True`, scrypt, CSRF, no hardcoded secrets | whole code base |
