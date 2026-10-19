"""
WinSentinel - Background Scan Orchestrator & Status Polling Engine.

Executes local Windows security audits in a dedicated background worker thread.
Enforces mutual exclusion with a thread lock so only one scan can execute at a time.
Provides progress updates across the 5 audit stages:
  1. Config audit
  2. Log analysis
  3. Software inventory
  4. CVE lookup
  5. Scoring
"""

import os
import threading
import logging
from typing import Dict, Any, Optional, Tuple

from db.database import (
    create_scan,
    update_scan_status,
    insert_findings,
    insert_alerts,
    insert_software,
)
from collectors.config_audit import run_config_audit
from collectors.event_logs import run_event_log_audit
from collectors.software_inventory import get_installed_software
from collectors.nvd_client import audit_software_vulnerabilities
from risk.scoring import calculate_posture_score

logger = logging.getLogger("winsentinel.scanner")


class ScanManager:
    """Thread-safe manager for background audit scan execution."""

    def __init__(self):
        self._lock = threading.Lock()
        self._is_running = False
        self._status = "idle"  # 'idle', 'running', 'completed', 'failed'
        self._step = ""
        self._progress = 0
        self._scan_id: Optional[int] = None
        self._error_message: Optional[str] = None

    def get_status(self) -> Dict[str, Any]:
        """Return the current progress and execution status of the scanner."""
        with self._lock:
            return {
                "status": self._status,
                "step": self._step,
                "progress": self._progress,
                "scan_id": self._scan_id,
                "error": self._error_message,
            }

    def start_scan(self) -> Tuple[bool, Optional[int], str]:
        """
        Initiate a new security scan in a background thread if no scan is currently running.

        Returns:
            Tuple[bool, Optional[int], str]: (started_flag, scan_id, message).
        """
        with self._lock:
            if self._is_running:
                return False, self._scan_id, "A security audit is already running."

            self._is_running = True
            self._status = "running"
            self._step = "Initializing audit"
            self._progress = 5
            self._error_message = None

            hostname = os.environ.get("COMPUTERNAME", "localhost")
            try:
                self._scan_id = create_scan(hostname=hostname)
            except Exception as exc:
                self._is_running = False
                self._status = "failed"
                self._error_message = f"Failed to initialize scan in database: {exc}"
                return False, None, self._error_message

            scan_id = self._scan_id

        # Spawn worker thread
        thread = threading.Thread(
            target=self._execute_scan_worker,
            args=(scan_id,),
            daemon=True,
        )
        thread.start()
        return True, scan_id, "Scan started successfully."

    def _execute_scan_worker(self, scan_id: int) -> None:
        """Worker thread executing the 5 scan phases sequentially."""
        try:
            logger.info("Starting Scan #%d", scan_id)

            # Step 1: Config audit
            self._update_progress("Config audit", 20)
            config_findings = run_config_audit(scan_id=scan_id)

            # Step 2: Log analysis
            self._update_progress("Log analysis", 40)
            alerts, log_findings, _ = run_event_log_audit(scan_id=scan_id, fallback_to_sample=False)

            # Step 3: Software inventory
            self._update_progress("Software inventory", 60)
            software_items = get_installed_software(scan_id=scan_id)
            insert_software(software_items)

            # Step 4: CVE lookup
            self._update_progress("CVE lookup", 80)
            sw_findings, _ = audit_software_vulnerabilities(software_items, scan_id=scan_id)

            # Step 5: Scoring
            self._update_progress("Scoring", 95)
            all_findings = config_findings + log_findings + sw_findings

            insert_findings(all_findings)
            insert_alerts(alerts)

            posture_score = calculate_posture_score(all_findings)
            update_scan_status(scan_id=scan_id, status="completed", posture_score=posture_score)

            with self._lock:
                self._is_running = False
                self._status = "completed"
                self._step = "Scan completed"
                self._progress = 100

            logger.info("Scan #%d completed successfully. Posture Score: %d/100", scan_id, posture_score)

        except Exception as exc:
            logger.exception("Scan #%d failed with exception: %s", scan_id, exc)
            try:
                update_scan_status(scan_id=scan_id, status="failed")
            except Exception:
                pass

            with self._lock:
                self._is_running = False
                self._status = "failed"
                self._step = "Failed"
                self._error_message = str(exc)

    def _update_progress(self, step_name: str, percent: int) -> None:
        """Update step label and percentage within the lock."""
        with self._lock:
            self._step = step_name
            self._progress = percent


# Global singleton instance
scan_manager = ScanManager()


def get_scan_manager() -> ScanManager:
    """Return the global ScanManager instance."""
    return scan_manager
