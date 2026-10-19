"""
WinSentinel - Alert notifications.

Sends an alert to up to three channels:
  - Windows desktop notification (balloon/toast via PowerShell; on by default)
  - Webhook (Slack, Discord or Teams style incoming webhook; set NOTIFY_WEBHOOK_URL)
  - Email over SMTP with STARTTLS (set SMTP_* and NOTIFY_EMAIL_* in .env)

Notifications are best-effort: a failing channel is logged and never raises, and the text sent is
limited to the alert title and a short summary (no passwords, no full event data).
"""

import logging
import os
import smtplib
import subprocess
import sys
from email.message import EmailMessage
from typing import Dict
from urllib.parse import urlparse

import requests

from config import get_config

logger = logging.getLogger("winsentinel.notify")

SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}

# The text reaches PowerShell through environment variables, never through the command line,
# so alert content (which includes attacker-controlled account names) cannot inject code.
_TOAST_SCRIPT = (
    "Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; "
    "$n = New-Object System.Windows.Forms.NotifyIcon; "
    "$n.Icon = [System.Drawing.SystemIcons]::Shield; "
    "$n.BalloonTipTitle = $env:WS_TITLE; $n.BalloonTipText = $env:WS_BODY; "
    "$n.BalloonTipIcon = 'Warning'; $n.Visible = $true; $n.ShowBalloonTip(8000); "
    "Start-Sleep -Seconds 9; $n.Dispose()"
)


def should_notify(severity: str) -> bool:
    """Return True if `severity` is at or above NOTIFY_MIN_SEVERITY."""
    minimum = SEVERITY_RANK.get(get_config().NOTIFY_MIN_SEVERITY, 3)
    return SEVERITY_RANK.get(severity, 0) >= minimum


def _clean(text: str, limit: int) -> str:
    """Single-line, length-limited text."""
    return " ".join(str(text).split())[:limit]


def _send_desktop(title: str, body: str) -> None:
    """Show a Windows desktop notification without blocking the caller."""
    if sys.platform != "win32":
        return
    env = dict(os.environ, WS_TITLE=_clean(title, 60), WS_BODY=_clean(body, 240))
    subprocess.Popen(
        ["powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", _TOAST_SCRIPT],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False,
    )


def _send_webhook(url: str, title: str, body: str) -> None:
    """POST a Slack/Discord/Teams compatible JSON message."""
    scheme = urlparse(url).scheme
    if scheme not in ("http", "https"):
        raise ValueError("NOTIFY_WEBHOOK_URL must start with http:// or https://")
    text = f"[WinSentinel] {title}\n{body}"
    resp = requests.post(url, json={"text": text, "content": text}, timeout=10)
    resp.raise_for_status()


def _send_email(title: str, body: str) -> None:
    """Send an email through the configured SMTP server (STARTTLS)."""
    cfg = get_config()
    msg = EmailMessage()
    msg["Subject"] = f"[WinSentinel] {_clean(title, 120)}"
    msg["From"] = cfg.NOTIFY_EMAIL_FROM or cfg.SMTP_USER
    msg["To"] = cfg.NOTIFY_EMAIL_TO
    msg.set_content(body)
    with smtplib.SMTP(cfg.SMTP_HOST, cfg.SMTP_PORT, timeout=15) as smtp:
        smtp.starttls()
        if cfg.SMTP_USER and cfg.SMTP_PASSWORD:
            smtp.login(cfg.SMTP_USER, cfg.SMTP_PASSWORD)
        smtp.send_message(msg)


def notify(title: str, body: str, severity: str) -> Dict[str, str]:
    """
    Send an alert on every configured channel if its severity passes the threshold.

    Args:
        title: Short alert title.
        body: One or two sentences of context.
        severity: Alert severity (Low, Medium, High, Critical).

    Returns:
        Dict mapping channel name to 'sent', 'skipped' or 'error: ...'.
    """
    cfg = get_config()
    results: Dict[str, str] = {}
    if not should_notify(severity):
        return {"all": "skipped (below NOTIFY_MIN_SEVERITY)"}

    channels = []
    if cfg.NOTIFY_DESKTOP:
        channels.append(("desktop", lambda: _send_desktop(title, body)))
    if cfg.NOTIFY_WEBHOOK_URL:
        channels.append(("webhook", lambda: _send_webhook(cfg.NOTIFY_WEBHOOK_URL, title, body)))
    if cfg.SMTP_HOST and cfg.NOTIFY_EMAIL_TO and (cfg.NOTIFY_EMAIL_FROM or cfg.SMTP_USER):
        channels.append(("email", lambda: _send_email(title, body)))

    for name, send in channels:
        try:
            send()
            results[name] = "sent"
        except Exception as exc:  # best effort: never let a notification break a scan or the monitor
            logger.warning("Notification channel %s failed: %s", name, exc)
            results[name] = f"error: {exc.__class__.__name__}"
    return results or {"all": "skipped (no channel configured)"}
