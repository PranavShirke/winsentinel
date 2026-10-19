"""
WinSentinel - Authentication, Session Management, and Login Throttling.

Implements single-admin authentication with:
  - Werkzeug scrypt password hashing verification.
  - Brute-force throttling: 5 failed attempts locks login for 5 minutes.
  - Audit logging of all login attempts (success and failure) to winsentinel.log.
  - Session timeout enforcement (30 minutes).
  - Secure session cookies (HttpOnly, SameSite=Lax).
"""

import time
import logging
from datetime import datetime, timezone
from functools import wraps
from typing import Dict, Tuple, Optional
from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
)
from werkzeug.security import check_password_hash

from config import get_config
from db.database import get_user_by_username, has_users

auth_bp = Blueprint("auth", __name__)

# Configure dedicated auth logger writing to winsentinel.log
logger = logging.getLogger("winsentinel.auth")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    file_handler = logging.FileHandler("winsentinel.log", encoding="utf-8")
    file_formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [AUTH] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

# In-memory tracking of failed login attempts: {ip_or_user: (failure_count, lockout_until_timestamp)}
_login_failures: Dict[str, Tuple[int, float]] = {}


def is_locked_out(identifier: str) -> Tuple[bool, int]:
    """
    Check if an IP address or username is currently locked out from logging in.

    Args:
        identifier: Client IP address or username.

    Returns:
        Tuple[bool, int]: (is_locked, remaining_lockout_seconds).
    """
    record = _login_failures.get(identifier)
    if not record:
        return False, 0

    count, lockout_until = record
    now = time.time()

    if now < lockout_until:
        remaining = int(lockout_until - now)
        return True, remaining
    return False, 0


def record_failed_attempt(identifier: str) -> Tuple[int, bool]:
    """
    Increment failed attempt count and trigger lockout if threshold is exceeded.

    Args:
        identifier: Client IP address or username.

    Returns:
        Tuple[int, bool]: (new_count, just_locked_out).
    """
    cfg = get_config()
    now = time.time()
    record = _login_failures.get(identifier)

    count = 0
    if record:
        count, lockout_until = record
        if now >= lockout_until and count >= cfg.LOGIN_MAX_FAILED_ATTEMPTS:
            # Previous lockout has expired, reset counter
            count = 0

    count += 1
    locked = False
    lockout_until = 0.0

    if count >= cfg.LOGIN_MAX_FAILED_ATTEMPTS:
        lockout_duration = cfg.LOGIN_LOCKOUT_MINUTES * 60
        lockout_until = now + lockout_duration
        locked = True

    _login_failures[identifier] = (count, lockout_until)
    return count, locked


def clear_failed_attempts(identifier: str) -> None:
    """Clear failed attempt records upon successful authentication."""
    if identifier in _login_failures:
        del _login_failures[identifier]


def login_required(view_func):
    """Decorator to enforce authentication and 30-minute session timeouts."""
    @wraps(view_func)
    def decorated_view(*args, **kwargs):
        cfg = get_config()
        if "user_id" not in session or "username" not in session:
            return redirect(url_for("auth.login", next=request.path))

        # Check session expiration
        last_active = session.get("last_active")
        now = time.time()
        timeout_seconds = cfg.SESSION_TIMEOUT_MINUTES * 60

        if last_active and (now - last_active > timeout_seconds):
            session.clear()
            flash("Your session has expired due to 30 minutes of inactivity. Please log in again.", "warning")
            return redirect(url_for("auth.login", next=request.path))

        session["last_active"] = now
        return view_func(*args, **kwargs)

    return decorated_view


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Handle administrator authentication and lockout validation."""
    if "user_id" in session:
        return redirect(url_for("views.dashboard"))

    if not has_users():
        flash("No administrator account exists. Run 'python main.py set-password' in your terminal.", "error")
        return render_template("login.html", disabled=True)

    client_ip = request.remote_addr or "127.0.0.1"
    locked, remaining = is_locked_out(client_ip)

    if locked:
        mins = remaining // 60
        secs = remaining % 60
        flash(f"Account locked due to 5 consecutive failed login attempts. Retry in {mins}m {secs}s.", "error")
        return render_template("login.html", locked=True, remaining_secs=remaining)

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_user_by_username(username)

        if user and check_password_hash(user["password_hash"], password):
            # Success
            clear_failed_attempts(client_ip)
            clear_failed_attempts(username)
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["last_active"] = time.time()
            session.permanent = True

            logger.info("Login SUCCESS for user '%s' from IP %s", username, client_ip)
            next_url = request.args.get("next") or url_for("views.dashboard")
            return redirect(next_url)
        else:
            # Failure
            count, just_locked = record_failed_attempt(client_ip)
            logger.warning("Login FAILURE for user '%s' from IP %s (Attempt %d)", username, client_ip, count)

            if just_locked:
                logger.error("Login LOCKOUT activated for IP %s (5 failures)", client_ip)
                flash(f"5 failed login attempts reached. Login locked for 5 minutes.", "error")
                return render_template("login.html", locked=True, remaining_secs=300)
            else:
                remaining_attempts = get_config().LOGIN_MAX_FAILED_ATTEMPTS - count
                flash(f"Invalid credentials. {remaining_attempts} attempt(s) remaining before 5-minute lockout.", "error")

    return render_template("login.html", locked=False)


@auth_bp.route("/logout")
def logout():
    """Clear session data and redirect to login."""
    username = session.get("username", "Unknown")
    client_ip = request.remote_addr or "127.0.0.1"
    logger.info("Logout for user '%s' from IP %s", username, client_ip)
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for("auth.login"))
