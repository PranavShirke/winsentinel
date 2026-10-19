"""
WinSentinel - SQLite Database Management and Query Helpers.

This module provides schema creation and parameterized query helpers for
scans, findings, alerts, software inventory, CVE caching, and admin authentication.
All SQL queries use strictly parameterized placeholders (?) to eliminate SQL injection risks.
"""

import json
import sqlite3
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
from config import get_config
from db.models import Finding, Alert, SoftwareItem, Scan


def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """
    Establish and configure a connection to the SQLite database.

    Enables foreign key enforcement and sets row_factory to sqlite3.Row
    for dictionary-like column access.

    Args:
        db_path: Path to the SQLite database file. Defaults to config DB_PATH.

    Returns:
        sqlite3.Connection: An open SQLite connection.
    """
    path = db_path or get_config().DB_PATH
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """
    Initialize all database tables and indexes if they do not exist.

    Args:
        db_path: Optional path to the database file.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # 1. Users table (Admin credentials)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
    """)

    # 2. Scans table (Audit sessions)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            hostname TEXT NOT NULL,
            posture_score INTEGER,
            status TEXT NOT NULL
        );
    """)

    # 3. Findings table (Security check results)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            module TEXT NOT NULL,
            title TEXT NOT NULL,
            evidence TEXT,
            status TEXT NOT NULL,
            likelihood INTEGER NOT NULL,
            impact INTEGER NOT NULL,
            risk_score INTEGER NOT NULL,
            severity TEXT NOT NULL,
            remediation TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );
    """)

    # 4. Alerts table (Event log detections & incidents)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            alert_type TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            account TEXT,
            source_ip TEXT,
            count INTEGER NOT NULL,
            severity TEXT NOT NULL,
            details TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );
    """)

    # 5. Software table (Installed software inventory)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS software (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            version TEXT,
            publisher TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );
    """)

    # 6. CVE Cache table (NVD vulnerability responses)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cve_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product TEXT NOT NULL,
            version TEXT NOT NULL,
            cve_id TEXT NOT NULL,
            cvss_score REAL,
            description TEXT,
            fetched_at TEXT NOT NULL
        );
    """)

    # 7. Scan metrics table (per-scan log statistics such as daily failed logons)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_metrics (
            scan_id INTEGER NOT NULL,
            metric TEXT NOT NULL,
            value TEXT NOT NULL,
            PRIMARY KEY (scan_id, metric),
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );
    """)

    # Drop CVE results cached by older matching logic (keys without a "#" version suffix)
    cursor.execute("DELETE FROM cve_cache WHERE product NOT LIKE '%#%';")

    # Create indexes for scan_id and cve_cache lookups
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_scan_id ON alerts(scan_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_software_scan_id ON software(scan_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_cache_prod_ver ON cve_cache(product, version);")

    conn.commit()
    conn.close()


# -------------------------------------------------------------------------
# User Management Helpers
# -------------------------------------------------------------------------

def create_or_update_admin(username: str, password_hash: str, db_path: Optional[str] = None) -> None:
    """
    Create or update the single admin user credentials.

    Args:
        username: Administrator username.
        password_hash: Secure Werkzeug password hash.
        db_path: Optional path to the database file.
    """
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO users (username, password_hash, created_at)
        VALUES (?, ?, ?)
        ON CONFLICT(username) DO UPDATE SET
            password_hash = excluded.password_hash,
            created_at = excluded.created_at;
        """,
        (username, password_hash, now),
    )
    conn.commit()
    conn.close()


def get_user_by_username(username: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Retrieve user record by username.

    Args:
        username: Target username to lookup.
        db_path: Optional path to the database file.

    Returns:
        Dict representing user record or None if not found.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password_hash, created_at FROM users WHERE username = ? LIMIT 1;", (username,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def has_users(db_path: Optional[str] = None) -> bool:
    """
    Check if any user accounts have been initialized.

    Args:
        db_path: Optional path to the database file.

    Returns:
        bool: True if at least one user exists, False otherwise.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) AS cnt FROM users;")
    row = cursor.fetchone()
    conn.close()
    return bool(row and row["cnt"] > 0)


# -------------------------------------------------------------------------
# Scan Helpers
# -------------------------------------------------------------------------

def create_scan(hostname: str, db_path: Optional[str] = None) -> int:
    """
    Record the start of a new scan session.

    Args:
        hostname: Name of the audited machine.
        db_path: Optional path to the database file.

    Returns:
        int: ID of the newly created scan record.
    """
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO scans (started_at, hostname, status)
        VALUES (?, ?, 'running');
        """,
        (now, hostname),
    )
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def update_scan_status(
    scan_id: int,
    status: str,
    posture_score: Optional[int] = None,
    finished_at: Optional[str] = None,
    db_path: Optional[str] = None,
) -> None:
    """
    Update scan status, posture score, and completion timestamp.

    Args:
        scan_id: ID of the scan to update.
        status: New status ('completed', 'failed', etc.).
        posture_score: Calculated posture score (0-100).
        finished_at: ISO formatted completion timestamp (defaults to now).
        db_path: Optional path to the database file.
    """
    if finished_at is None and status in ("completed", "failed"):
        finished_at = datetime.now(timezone.utc).isoformat()

    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE scans
        SET status = ?, posture_score = ?, finished_at = ?
        WHERE id = ?;
        """,
        (status, posture_score, finished_at, scan_id),
    )
    conn.commit()
    conn.close()


def insert_findings(findings: List[Finding], db_path: Optional[str] = None) -> None:
    """
    Insert a list of Finding objects in a single transaction.

    Args:
        findings: List of Finding instances.
        db_path: Optional path to the database file.
    """
    if not findings:
        return

    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.executemany(
        """
        INSERT INTO findings (
            scan_id, module, title, evidence, status,
            likelihood, impact, risk_score, severity, remediation
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """,
        [
            (
                f.scan_id,
                f.module,
                f.title,
                f.evidence,
                f.status,
                f.likelihood,
                f.impact,
                f.risk_score,
                f.severity,
                f.remediation,
            )
            for f in findings
        ],
    )
    conn.commit()
    conn.close()


def insert_alerts(alerts: List[Alert], db_path: Optional[str] = None) -> None:
    """
    Insert a list of Alert objects into the database.

    Args:
        alerts: List of Alert instances.
        db_path: Optional path to the database file.
    """
    if not alerts:
        return

    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.executemany(
        """
        INSERT INTO alerts (
            scan_id, alert_type, timestamp, account, source_ip,
            count, severity, details
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """,
        [
            (
                a.scan_id,
                a.alert_type,
                a.timestamp,
                a.account,
                a.source_ip,
                a.count,
                a.severity,
                a.details,
            )
            for a in alerts
        ],
    )
    conn.commit()
    conn.close()


def insert_software(software_items: List[SoftwareItem], db_path: Optional[str] = None) -> None:
    """
    Insert a list of installed software items into the database.

    Args:
        software_items: List of SoftwareItem instances.
        db_path: Optional path to the database file.
    """
    if not software_items:
        return

    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.executemany(
        """
        INSERT INTO software (scan_id, name, version, publisher)
        VALUES (?, ?, ?, ?);
        """,
        [(s.scan_id, s.name, s.version, s.publisher) for s in software_items],
    )
    conn.commit()
    conn.close()


def get_latest_scan(db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Retrieve the most recent scan record.

    Args:
        db_path: Optional path to the database file.

    Returns:
        Dict representing the scan or None if no scans exist.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1;")
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_latest_completed_scan(db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Retrieve the most recent scan that finished successfully.

    Dashboards use this so a scan that is still running (or failed) never shows as an empty report.

    Args:
        db_path: Optional path to the database file.

    Returns:
        Dict representing the scan or None if no completed scan exists.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE status = 'completed' ORDER BY id DESC LIMIT 1;")
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def insert_scan_metrics(scan_id: int, metrics: Dict[str, Any], db_path: Optional[str] = None) -> None:
    """
    Persist JSON-serialisable scan metrics (e.g. daily failed logons) for a scan.

    Args:
        scan_id: ID of the scan.
        metrics: Mapping of metric name to JSON-serialisable value.
        db_path: Optional path to the database file.
    """
    if not metrics:
        return
    conn = get_db_connection(db_path)
    conn.executemany(
        "INSERT OR REPLACE INTO scan_metrics (scan_id, metric, value) VALUES (?, ?, ?);",
        [(scan_id, name, json.dumps(value)) for name, value in metrics.items()],
    )
    conn.commit()
    conn.close()


def get_scan_metrics(scan_id: int, db_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load the metrics saved for a scan.

    Args:
        scan_id: ID of the scan.
        db_path: Optional path to the database file.

    Returns:
        Dict mapping metric name to its decoded value (empty if none stored).
    """
    conn = get_db_connection(db_path)
    rows = conn.execute("SELECT metric, value FROM scan_metrics WHERE scan_id = ?;", (scan_id,)).fetchall()
    conn.close()
    result: Dict[str, Any] = {}
    for row in rows:
        try:
            result[row["metric"]] = json.loads(row["value"])
        except ValueError:
            continue
    return result


def compare_scans(old_scan_id: int, new_scan_id: int, db_path: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
    """
    Compare the failed findings of two scans to show security drift.

    Findings are matched on (module, title). Titles that embed a changing value
    (such as a CVE id) will appear as one resolved plus one new entry, which is the
    desired behaviour.

    Args:
        old_scan_id: Baseline scan.
        new_scan_id: Scan to compare against the baseline.
        db_path: Optional path to the database file.

    Returns:
        Dict with 'new' (appeared), 'resolved' (fixed) and 'persisting' finding lists.
    """
    old = {(f["module"], f["title"]): f for f in get_findings_by_scan_id(old_scan_id, status="fail", db_path=db_path)}
    new = {(f["module"], f["title"]): f for f in get_findings_by_scan_id(new_scan_id, status="fail", db_path=db_path)}
    return {
        "new": [new[k] for k in new if k not in old],
        "resolved": [old[k] for k in old if k not in new],
        "persisting": [new[k] for k in new if k in old],
    }


def get_scan_by_id(scan_id: int, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Retrieve a scan record by its ID.

    Args:
        scan_id: Primary key of the scan.
        db_path: Optional path to the database file.

    Returns:
        Dict of the scan record or None if not found.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE id = ?;", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_scans(limit: int = 50, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Retrieve recent scans ordered by ID descending.

    Args:
        limit: Maximum number of scans to return.
        db_path: Optional path to the database file.

    Returns:
        List of scan dictionaries with finding summary counts.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT s.*,
            (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id AND f.status = 'fail') AS failed_count,
            (SELECT COUNT(*) FROM alerts a WHERE a.scan_id = s.id) AS alert_count
        FROM scans s
        ORDER BY s.id DESC
        LIMIT ?;
        """,
        (limit,),
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_findings_by_scan_id(
    scan_id: int,
    severity: Optional[str] = None,
    module: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Retrieve findings for a specific scan with optional filtering.

    Args:
        scan_id: ID of the scan.
        severity: Filter by severity ('Critical', 'High', etc.).
        module: Filter by module ('config', 'logs', 'software').
        status: Filter by status ('pass', 'fail', 'error').
        search: Text search filter matching title or evidence.
        db_path: Optional path to the database file.

    Returns:
        List of findings matching the query parameters.
    """
    query = "SELECT * FROM findings WHERE scan_id = ?"
    params: List[Any] = [scan_id]

    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if module:
        query += " AND module = ?"
        params.append(module)
    if status:
        query += " AND status = ?"
        params.append(status)
    if search:
        query += " AND (title LIKE ? OR evidence LIKE ?)"
        like_pattern = f"%{search}%"
        params.extend([like_pattern, like_pattern])

    query += " ORDER BY risk_score DESC, id ASC;"

    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_alerts_by_scan_id(scan_id: int, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Retrieve all alerts detected during a specific scan.

    Args:
        scan_id: ID of the scan.
        db_path: Optional path to the database file.

    Returns:
        List of alert dictionaries.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM alerts WHERE scan_id = ? ORDER BY id DESC;",
        (scan_id,),
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_software_by_scan_id(scan_id: int, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Retrieve installed software items inventoried during a scan.

    Args:
        scan_id: ID of the scan.
        db_path: Optional path to the database file.

    Returns:
        List of software dictionaries.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM software WHERE scan_id = ? ORDER BY name ASC;",
        (scan_id,),
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_scan_summary_counts(scan_id: int, db_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Calculate summary breakdown counts for the dashboard.

    Args:
        scan_id: ID of the scan.
        db_path: Optional path to the database file.

    Returns:
        Dict with counts by severity, module, alerts, and total software.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # Severity counts
    cursor.execute(
        """
        SELECT severity, COUNT(*) as cnt
        FROM findings
        WHERE scan_id = ?
        GROUP BY severity;
        """,
        (scan_id,),
    )
    severity_counts = {row["severity"]: row["cnt"] for row in cursor.fetchall()}

    # Module counts
    cursor.execute(
        """
        SELECT module, COUNT(*) as cnt
        FROM findings
        WHERE scan_id = ? AND status = 'fail'
        GROUP BY module;
        """,
        (scan_id,),
    )
    module_counts = {row["module"]: row["cnt"] for row in cursor.fetchall()}

    # Total failed findings
    cursor.execute(
        "SELECT COUNT(*) as cnt FROM findings WHERE scan_id = ? AND status = 'fail';",
        (scan_id,),
    )
    failed_total = cursor.fetchone()["cnt"]

    # Active alerts count
    cursor.execute(
        "SELECT COUNT(*) as cnt FROM alerts WHERE scan_id = ?;",
        (scan_id,),
    )
    alert_total = cursor.fetchone()["cnt"]

    # Total software items inventoried
    cursor.execute(
        "SELECT COUNT(*) as cnt FROM software WHERE scan_id = ?;",
        (scan_id,),
    )
    software_total = cursor.fetchone()["cnt"]

    # Vulnerable software count (failed software findings)
    cursor.execute(
        "SELECT COUNT(*) as cnt FROM findings WHERE scan_id = ? AND module = 'software' AND status = 'fail';",
        (scan_id,),
    )
    vulnerable_software = cursor.fetchone()["cnt"]

    conn.close()
    return {
        "severity": severity_counts,
        "modules": module_counts,
        "failed_findings": failed_total,
        "active_alerts": alert_total,
        "software_total": software_total,
        "vulnerable_software": vulnerable_software,
    }


# -------------------------------------------------------------------------
# CVE Cache Helpers
# -------------------------------------------------------------------------

def get_cached_cves(
    product: str,
    version: str,
    max_age_hours: int = 24,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Retrieve cached CVE records for a specific product and version if fresh.

    Args:
        product: Normalized product name.
        version: Version string.
        max_age_hours: Maximum age of cached entries before considered stale.
        db_path: Optional path to the database file.

    Returns:
        List of matching CVE dictionaries.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT * FROM cve_cache
        WHERE product = ? AND version = ?
        ORDER BY cvss_score DESC;
        """,
        (product.lower(), version),
    )
    rows = cursor.fetchall()
    conn.close()

    results = []
    now = datetime.now(timezone.utc)
    for r in rows:
        row_dict = dict(r)
        try:
            fetched_time = datetime.fromisoformat(row_dict["fetched_at"])
            age_hours = (now - fetched_time).total_seconds() / 3600.0
            if age_hours <= max_age_hours:
                results.append(row_dict)
        except Exception:
            results.append(row_dict)

    return results


def insert_cached_cve(
    product: str,
    version: str,
    cve_id: str,
    cvss_score: float,
    description: str,
    db_path: Optional[str] = None,
) -> None:
    """
    Cache a CVE entry retrieved from the NVD API.

    Args:
        product: Normalized product name.
        version: Product version string.
        cve_id: Common Vulnerabilities and Exposures identifier.
        cvss_score: CVSS score (0.0 to 10.0).
        description: Truncated or full vulnerability description.
        db_path: Optional path to the database file.
    """
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO cve_cache (product, version, cve_id, cvss_score, description, fetched_at)
        VALUES (?, ?, ?, ?, ?, ?);
        """,
        (product.lower(), version, cve_id, cvss_score, description, now),
    )
    conn.commit()
    conn.close()
