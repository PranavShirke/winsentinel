"""
WinSentinel - Central Configuration Module.

This module loads environment variables and provides centralized configuration
for the audit framework, log analysis, risk scoring, web dashboard, and CVE lookup.
All configuration is strictly read-only at runtime to maintain security posture.
"""

import os
import secrets
from pathlib import Path
from dotenv import load_dotenv

# Base Directory of the Project
BASE_DIR = Path(__file__).resolve().parent

# Load environment variables from .env file if present
load_dotenv(BASE_DIR / ".env")


# Placeholder values that must never be used to sign sessions.
_INSECURE_SECRET_KEYS = {"", "winsentinel-default-change-in-production-key-secret", "change-me"}
_env_secret_key = os.getenv("SECRET_KEY", "").strip()


class Config:
    """Central configuration class for WinSentinel."""

    # Project metadata
    PROJECT_NAME = "WinSentinel"
    VERSION = "1.0.0"
    LEGAL_DISCLAIMER = (
        "WinSentinel is strictly intended for local system auditing of authorized machines. "
        "It performs read-only checks on the host it runs on. No remote scanning, exploitation, "
        "or automated remediation is performed."
    )

    # Database settings
    DB_PATH = os.getenv("DATABASE_PATH", str(BASE_DIR / "winsentinel.db"))

    # Security & Flask settings
    # No hardcoded fallback: if .env has no real key, a random per-process key is used
    # (sessions simply end when the server restarts) and a warning is shown at startup.
    SECRET_KEY_IS_EPHEMERAL = _env_secret_key in _INSECURE_SECRET_KEYS
    SECRET_KEY = secrets.token_hex(32) if SECRET_KEY_IS_EPHEMERAL else _env_secret_key
    DEBUG = False  # Hardcoded False per application security decisions
    HOST = "127.0.0.1"  # Bound strictly to localhost loopback
    PORT = 5000
    SESSION_TIMEOUT_MINUTES = 30
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # Dashboard Login Throttling
    LOGIN_MAX_FAILED_ATTEMPTS = 5
    LOGIN_LOCKOUT_MINUTES = 5

    # Automatic scans while the server runs (minutes; 0 = disabled, minimum 15 when enabled)
    AUTO_SCAN_INTERVAL_MINUTES = int(os.getenv("AUTO_SCAN_INTERVAL_MINUTES", "0") or 0)

    # Windows Security Log Analysis Defaults
    DEFAULT_LOG_ANALYSIS_DAYS = int(os.getenv("ANALYSIS_WINDOW_DAYS", "7"))
    BRUTE_FORCE_FAILURE_THRESHOLD = 5  # 5 failed logons (4625)
    BRUTE_FORCE_WINDOW_MINUTES = 10  # within 10 minutes

    # NVD CVE Lookup Settings
    NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip() or None
    NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_CACHE_TTL_HOURS = 24
    # Rate limits: ~5 req/30s unauthenticated (6.0s delay), ~50 req/30s with API key (0.7s delay)
    NVD_REQUEST_DELAY_SECONDS = 0.7 if NVD_API_KEY else 6.0
    NVD_TIMEOUT_SECONDS = 15
    # Pages of 2000 CVEs fetched per product before local version filtering
    NVD_MAX_PAGES = 3  # up to 3 x 2000 CVEs per product

    # Software Inventory Allowlist (Only check well-known products against NVD)
    SOFTWARE_ALLOWLIST = [
        "google chrome",
        "mozilla firefox",
        "microsoft edge",
        "7-zip",
        "java",
        "python",
        "vlc media player",
        "notepad++",
        "winrar",
        "adobe acrobat",
        "adobe reader",
    ]

    # Exact NVD CPE (vendor, product) pairs for each allowlisted keyword. Matching on exact CPE
    # names (not substrings) prevents e.g. "nautilus-python" or legacy "edge" CVEs being
    # attributed to Python or Chromium Edge.
    CPE_PRODUCTS = {
        "google chrome": [("google", "chrome")],
        "mozilla firefox": [("mozilla", "firefox")],
        "microsoft edge": [("microsoft", "edge_chromium")],
        "7-zip": [("7-zip", "7-zip")],
        "java": [("oracle", "jre"), ("oracle", "jdk")],
        "python": [("python", "python")],
        "vlc media player": [("videolan", "vlc_media_player")],
        "notepad++": [("notepad-plus-plus", r"notepad\+\+")],
        "winrar": [("rarlab", "winrar")],
        "adobe acrobat": [("adobe", "acrobat_dc"), ("adobe", "acrobat")],
        "adobe reader": [("adobe", "acrobat_reader_dc"), ("adobe", "acrobat_reader")],
    }

    # Risky Listening Ports to Flag in Config Audit
    RISKY_PORTS = {
        23: "Telnet (Unencrypted remote terminal)",
        135: "RPC Endpoint Mapper (Exposure risk / lateral movement)",
        139: "NetBIOS Session Service (SMB legacy)",
        445: "SMB over TCP (High vulnerability surface, e.g., EternalBlue)",
        3389: "Remote Desktop Protocol / RDP (Exposure risk)",
        5985: "WinRM HTTP (Remote management unencrypted transport)",
    }

    # Risk Scoring Model: NIST SP 800-30 Aligned Severity Bands
    SEVERITY_BANDS = {
        "Critical": (16, 25),
        "High": (10, 15),
        "Medium": (5, 9),
        "Low": (1, 4),
        "Info": (0, 0),
    }

    # Posture Score Deduction Penalties (Baseline 100, floored at 0)
    POSTURE_PENALTIES = {
        "Critical": 15,
        "High": 8,
        "Medium": 3,
        "Low": 1,
        "Info": 0,
        "Error": 0,
    }


_config_instance = Config()


def get_config() -> Config:
    """Return the active configuration object singleton."""
    return _config_instance
