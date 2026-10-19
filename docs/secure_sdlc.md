# Secure Software Development Lifecycle (Secure SDLC)

How security is built into WinSentinel at every phase, and where the evidence is in this repository.

## 1. Requirements
- Legal and ethical scope is a requirement: audit **only the local machine**, read-only, no exploitation, no auto-remediation, no remote scanning (README, report, dashboard footer).
- Security requirements written before coding: authentication, CSRF, CSP with no inline script, input allow-lists, secrets only in `.env`, audit logging (`PROJECT_CONTEXT.md`).
- Abuse cases written next to use cases (see `docs/threat_model.md`, section 4).

## 2. Design
- STRIDE threat model with trust boundaries and a data-flow diagram: `docs/threat_model.md`.
- Least privilege and degradation: the tool recommends Administrator for full results but every check degrades to an `error` finding instead of failing open.
- Defence in depth: validation at the boundary, parameterised SQL, output escaping, CSP, and security headers each stand on their own.
- Minimal external surface: loopback binding, vendored Chart.js, no CDN, no web fonts, and only a product name sent to NVD.

## 3. Implementation (secure coding standards)

| Standard | Where it is applied |
|---|---|
| Validate input at the boundary | `web/security.py` allow-lists and integer checks; `safe_next_url()` in `web/auth.py` |
| Parameterised SQL only | `db/database.py` (every query uses `?` placeholders) |
| No shell injection | `collectors/config_audit.py::run_command` uses argument lists, `shell=False` |
| Strong password storage | scrypt via Werkzeug; 12-character minimum (`main.py set-password`) |
| No hardcoded secrets | `config.py` has no usable default `SECRET_KEY`; `.env` and the database are git-ignored |
| Safe output | Jinja autoescape; no inline script or style; CSV formula-injection guard |
| Safe errors | custom error pages, `debug=False`, failed checks become `error` findings |
| Logging and accountability | `winsentinel.log` records login success, failure, lockout, logout |
| Docstrings and small modules | every function documented; collectors, analysis, risk, web are separate packages |

## 4. Verification (testing)
- Unit tests for parsers, scoring, brute-force correlation and NVD matching.
- End-to-end web tests: authentication, CSRF, open redirect, headers, CSV, comparison (`tests/test_web.py`).
- Regression tests for defects found on a real scan (for example legacy "Edge" CVEs wrongly attributed to Chromium Edge).
- Run all: `py -m pytest tests/ -v` (currently 69 tests).
- Manual verification: run a real scan on the host and review the findings for false positives (done during development and documented in the commit history).
- Dependency hygiene: `pip install pip-audit` then `pip-audit -r requirements.txt` before every release; pin and review new dependencies.

## 5. Release and deployment
- Local-only tool: bound to `127.0.0.1`; there is no network deployment.
- Checklist before tagging a release:
  1. `py -m pytest tests/` passes.
  2. `pip-audit -r requirements.txt` shows no known high or critical issues.
  3. `git grep -n -i "secret\|password\|api_key"` shows no real credentials.
  4. `.env` and `*.db` are not tracked.
  5. README limitations section still matches behaviour.

## 6. Maintenance and response
- Version-controlled history on a single working branch for the redesign; `main` stays releasable.
- Vulnerability handling: reproduce, add a failing test, fix, record in the commit message.
- Revisit the threat model when a new boundary is added (new data source, new route, new external API).

## 7. Mapping to the syllabus
- Module 4 (Secure SDLC): this document.
- Module 3 (security headers, input validation): `web/security.py`, section 3 above.
- Module 6 (threat modelling): `docs/threat_model.md`.
