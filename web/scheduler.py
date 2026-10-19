"""
WinSentinel - Automatic scan scheduler.

Runs a full audit every AUTO_SCAN_INTERVAL_MINUTES while the dashboard server is running
(0 = disabled, the default). It reuses the ScanManager lock, so a scheduled scan never overlaps
a manual one. The scheduler only starts audits; it never changes anything on the host.
"""

import logging
import threading
import time
from typing import Optional

from config import get_config
from web.scanner import get_scan_manager

logger = logging.getLogger("winsentinel.scheduler")

MIN_INTERVAL_MINUTES = 15  # keeps NVD usage and host load reasonable


class AutoScanScheduler:
    """Background thread that starts a scan at a fixed interval."""

    def __init__(self, interval_minutes: int):
        self.interval_seconds = max(MIN_INTERVAL_MINUTES, int(interval_minutes)) * 60
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.next_run: Optional[float] = None

    def start(self) -> None:
        """Start the scheduler thread (daemon, so it never blocks shutdown)."""
        self.next_run = time.time() + self.interval_seconds
        self._thread = threading.Thread(target=self._loop, name="auto-scan", daemon=True)
        self._thread.start()
        logger.info("Auto-scan enabled every %d minutes", self.interval_seconds // 60)

    def stop(self) -> None:
        """Ask the scheduler thread to stop."""
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.wait(timeout=max(1.0, (self.next_run or 0) - time.time())):
            started, scan_id, message = get_scan_manager().start_scan()
            logger.info("Scheduled scan: started=%s scan_id=%s (%s)", started, scan_id, message)
            self.next_run = time.time() + self.interval_seconds


_scheduler: Optional[AutoScanScheduler] = None


def start_scheduler_if_enabled() -> Optional[AutoScanScheduler]:
    """Start the global scheduler when AUTO_SCAN_INTERVAL_MINUTES > 0."""
    global _scheduler
    minutes = get_config().AUTO_SCAN_INTERVAL_MINUTES
    if minutes > 0 and _scheduler is None:
        _scheduler = AutoScanScheduler(minutes)
        _scheduler.start()
    return _scheduler


def get_scheduler() -> Optional[AutoScanScheduler]:
    """Return the running scheduler, if any."""
    return _scheduler
