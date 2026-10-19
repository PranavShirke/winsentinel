"""
WinSentinel - Live Security-log monitor.

While the dashboard server runs, polls the Windows Security log every LIVE_MONITOR_INTERVAL_SECONDS
(default 60) for failed logons, account changes and privileged-group changes, correlates them with
the same rules as a full scan (analysis/bruteforce.py) and records new alerts as they happen.
Each new High/Critical alert also triggers a notification (desktop, webhook, email).

It needs Administrator rights to read the Security log. Without them it reports "needs Administrator"
and does nothing, instead of pretending the system is clean.
"""

import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from analysis.bruteforce import analyze_security_events, parse_event_timestamp
from collectors.event_logs import collect_security_events
from collectors.privileges import is_elevated
from config import get_config
from db.database import insert_live_alert
from web.notifier import notify

logger = logging.getLogger("winsentinel.monitor")


class LiveMonitor:
    """Background poller that turns Security-log events into live alerts."""

    def __init__(self, interval_seconds: int):
        self.interval_seconds = max(20, int(interval_seconds))
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._buffer: Dict[Any, Dict[str, Any]] = {}
        self.last_poll: Optional[str] = None
        self.last_error: str = ""
        self.polls = 0
        self.alerts_raised = 0

    # -- lifecycle ----------------------------------------------------
    def start(self) -> None:
        """Start the polling thread (daemon)."""
        self._thread = threading.Thread(target=self._loop, name="live-monitor", daemon=True)
        self._thread.start()
        logger.info("Live monitor started (every %ds)", self.interval_seconds)

    def stop(self) -> None:
        """Ask the polling thread to stop."""
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception as exc:  # the monitor must never die from one bad poll
                self.last_error = f"{exc.__class__.__name__}: {exc}"
                logger.exception("Live monitor poll failed")
            self._stop.wait(self.interval_seconds)

    # -- one polling cycle -------------------------------------------
    def poll_once(self) -> List[int]:
        """
        Poll the Security log once and record any new alerts.

        Returns:
            List of ids of newly stored live alerts.
        """
        cfg = get_config()
        window = cfg.BRUTE_FORCE_WINDOW_MINUTES
        history_minutes = window * 3

        ok, events, err = collect_security_events(since_minutes=history_minutes, max_events=1500)
        self.polls += 1
        self.last_poll = datetime.now(timezone.utc).isoformat(timespec="seconds")
        if not ok:
            self.last_error = err or "Security log query failed"
            return []
        self.last_error = ""

        # Keep a rolling buffer so a burst that spans several polls is still seen as one burst.
        for ev in events:
            self._buffer[ev.get("record_id") or (ev.get("id"), ev.get("time_created"), ev.get("target_user_name"))] = ev
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=history_minutes)
        self._buffer = {k: v for k, v in self._buffer.items() if parse_event_timestamp(v.get("time_created")) >= cutoff}

        alerts, _, _ = analyze_security_events(list(self._buffer.values()))
        new_ids: List[int] = []
        for a in alerts:
            fingerprint = f"{a.alert_type}|{a.account}|{a.source_ip}|{a.timestamp[:16]}"
            alert_id = insert_live_alert(
                fingerprint, a.alert_type, a.timestamp, a.account, a.source_ip, a.count, a.severity, a.details
            )
            if alert_id is None:
                continue  # already raised on an earlier poll
            new_ids.append(alert_id)
            self.alerts_raised += 1
            notify(f"{a.severity}: {a.alert_type} ({a.account})", a.details[:200], a.severity)
        return new_ids

    # -- status for the UI ------------------------------------------
    def status(self) -> Dict[str, Any]:
        """Return a JSON-serialisable status snapshot."""
        return {
            "enabled": True,
            "interval_seconds": self.interval_seconds,
            "last_poll": self.last_poll,
            "last_error": self.last_error,
            "polls": self.polls,
            "alerts_raised": self.alerts_raised,
        }


_monitor: Optional[LiveMonitor] = None


def start_monitor_if_enabled() -> Optional[LiveMonitor]:
    """
    Start the global monitor according to LIVE_MONITOR (auto / on / off).

    'auto' starts it only when the process is elevated, because the Security log is unreadable otherwise.
    """
    global _monitor
    cfg = get_config()
    mode = cfg.LIVE_MONITOR
    if _monitor is not None or mode == "off":
        return _monitor
    if mode == "auto" and not is_elevated():
        return None
    _monitor = LiveMonitor(cfg.LIVE_MONITOR_INTERVAL_SECONDS)
    _monitor.start()
    return _monitor


def get_monitor() -> Optional[LiveMonitor]:
    """Return the running monitor, if any."""
    return _monitor


def monitor_status() -> Dict[str, Any]:
    """Status for the UI, including why the monitor is not running."""
    if _monitor is not None:
        return _monitor.status()
    cfg = get_config()
    if cfg.LIVE_MONITOR == "off":
        reason = "Disabled (LIVE_MONITOR=off)."
    elif not is_elevated():
        reason = "Needs Administrator rights to read the Security log. Start WinSentinel with run.bat."
    else:
        reason = "Not started."
    return {"enabled": False, "reason": reason, "interval_seconds": cfg.LIVE_MONITOR_INTERVAL_SECONDS,
            "last_poll": None, "last_error": "", "polls": 0, "alerts_raised": 0}
