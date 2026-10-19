"""
WinSentinel - Web Hardening, Security Headers, and Input Validation.

Applies strict security policies to all HTTP traffic:
  - Strict Content-Security-Policy (CSP) blocking inline scripts and external origins.
  - Anti-clickjacking (X-Frame-Options: DENY, frame-ancestors 'none').
  - MIME-sniffing prevention (X-Content-Type-Options: nosniff).
  - Cache prevention for sensitive security reports (Cache-Control: no-store).
  - Whitelist validation for query parameters.
"""

from typing import Optional, Any
from flask import Response, session


ALLOWED_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info", "Error"}
ALLOWED_MODULES = {"config", "logs", "software"}
ALLOWED_STATUSES = {"pass", "fail", "error"}


def apply_security_headers(response: Response) -> Response:
    """
    Attach defense-in-depth security headers to every outgoing Flask response.

    Args:
        response: Outgoing Flask response object.

    Returns:
        Response: Hardened response object with security headers.
    """
    # 1. Content Security Policy (CSP)
    # Strictly disallows inline scripts ('unsafe-inline'), eval, and any third-party domains
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )

    # 2. Clickjacking Protection
    response.headers["X-Frame-Options"] = "DENY"

    # 3. MIME Type Sniffing Prevention
    response.headers["X-Content-Type-Options"] = "nosniff"

    # 4. Referrer Policy
    response.headers["Referrer-Policy"] = "no-referrer"

    # 4b. Disable powerful browser features and isolate the browsing context
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

    # 5. Sensitive Data Caching Protection (Authenticated views)
    if "user_id" in session or response.mimetype in ("text/csv", "application/json"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

    return response


def validate_scan_id(val: Any) -> Optional[int]:
    """
    Validate that scan_id is a positive integer.

    Args:
        val: Input string or integer.

    Returns:
        Optional[int]: Validated integer ID or None.
    """
    if val is None:
        return None
    try:
        scan_id = int(val)
        return scan_id if scan_id > 0 else None
    except (ValueError, TypeError):
        return None


def validate_severity(val: Optional[str]) -> Optional[str]:
    """
    Validate that severity matches the allowed NIST severity bands.

    Args:
        val: Input severity string.

    Returns:
        Optional[str]: Validated severity or None.
    """
    if not val:
        return None
    cleaned = val.strip().capitalize()
    return cleaned if cleaned in ALLOWED_SEVERITIES else None


def validate_module(val: Optional[str]) -> Optional[str]:
    """
    Validate that module matches the allowed collector module names.

    Args:
        val: Input module string.

    Returns:
        Optional[str]: Validated module or None.
    """
    if not val:
        return None
    cleaned = val.strip().lower()
    return cleaned if cleaned in ALLOWED_MODULES else None


def validate_status(val: Optional[str]) -> Optional[str]:
    """
    Validate that status matches pass, fail, or error.

    Args:
        val: Input status string.

    Returns:
        Optional[str]: Validated status or None.
    """
    if not val:
        return None
    cleaned = val.strip().lower()
    return cleaned if cleaned in ALLOWED_STATUSES else None


def sanitize_search_query(val: Optional[str], max_len: int = 100) -> Optional[str]:
    """
    Sanitize and truncate search filter text to prevent buffer and regex issues.

    Args:
        val: Input search string.
        max_len: Maximum permitted character length.

    Returns:
        Optional[str]: Cleaned search string or None.
    """
    if not val:
        return None
    cleaned = val.strip()
    return cleaned[:max_len] if cleaned else None
