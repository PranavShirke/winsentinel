"""
WinSentinel - Central Configuration Module.

This module loads environment variables and provides centralized configuration
for the audit framework, log analysis, risk scoring, web dashboard, and CVE lookup.
All configuration is strictly read-only at runtime to maintain security posture.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Base Directory of the Project
BASE_DIR = Path(__file__).resolve().parent

# Load environment variables from .env file if present
load_dotenv(BASE_DIR / ".env")


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
    SECRET_KEY = os.getenv("SECRET_KEY", "winsentinel-default-change-in-production-key-secret")
    DEBUG = False  # Hardcoded False per application security decisions
    HOST = "127.0.0.1"  # Bound strictly to localhost loopback
    PORT = 5000
    SESSION_TIMEOUT_MINUTES = 30
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # Dashboard Login Throttling
    LOGIN_MAX_FAILED_ATTEMPTS = 5
    LOGIN_LOCKOUT_MINUTES = 5

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
