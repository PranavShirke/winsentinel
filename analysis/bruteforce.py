"""
WinSentinel - Security Event Log Analysis & Brute-Force Detection Engine.

This module analyzes Windows Security Event Logs to detect:
  1. Brute-Force Logon Attacks (Event 4625: >= 5 failures within 10 minutes)
  2. Possible Account Compromise (Event 4624 following >= 5 failures within 10 minutes)
  3. New User Account Creation (Event 4720)
  4. Account Lockouts (Event 4740)
  5. Membership Additions to Privileged Groups (Event 4732)
  6. Privileged Administrative Logons (Event 4672)

All correlation logic operates on chronological sliding time windows configured in config.py.
"""

from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict

from config import get_config
from db.models import Alert, Finding


def parse_event_timestamp(ts_val: Any) -> datetime:
    """
    Parse event timestamp into a timezone-aware UTC datetime object.

    Handles ISO-8601 strings, Windows JSON date formats, and datetime objects.

    Args:
        ts_val: String or datetime value representing the event time.

    Returns:
        datetime: Timezone-aware UTC datetime.
    """
    if isinstance(ts_val, datetime):
        if ts_val.tzinfo is None:
            return ts_val.replace(tzinfo=timezone.utc)
        return ts_val.astimezone(timezone.utc)

    if not isinstance(ts_val, str) or not ts_val.strip():
        return datetime.now(timezone.utc)

    ts_str = ts_val.strip()

    # Handle ISO formats
    try:
        # Standard ISO 8601 (replace 'Z' with '+00:00')
        clean_str = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        pass

    # Handle standard fallback formats
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%d-%m-%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
    ):
        try:
            dt = datetime.strptime(ts_str, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    return datetime.now(timezone.utc)


def analyze_security_events(
    events: List[Dict[str, Any]],
    scan_id: Optional[int] = None,
) -> Tuple[List[Alert], List[Finding], Dict[str, Any]]:
    """
    Analyze normalized Windows Security events using sliding time window correlation rules.

    Args:
        events: List of event dictionaries (containing keys: id, time_created, target_user_name, etc.).
        scan_id: Optional ID of the associated scan session.

    Returns:
        Tuple:
            - List[Alert]: Generated security incident alerts.
            - List[Finding]: Findings for module='logs' with Likelihood x Impact scoring.
            - Dict[str, Any]: Aggregated metrics (daily logon failures, total events analyzed).
    """
    cfg = get_config()
    threshold = cfg.BRUTE_FORCE_FAILURE_THRESHOLD
    window_delta = timedelta(minutes=cfg.BRUTE_FORCE_WINDOW_MINUTES)

    alerts: List[Alert] = []
    findings: List[Finding] = []

    # Daily breakdown of failed logons (for dashboard charts)
    daily_failures: Dict[str, int] = defaultdict(int)

    # Sort events chronologically
    sorted_events = sorted(events, key=lambda e: parse_event_timestamp(e.get("time_created")))

    # History buffers for sliding window analysis
    # user_failures[user] = list of (datetime, event)
    user_failures: Dict[str, List[Tuple[datetime, Dict[str, Any]]]] = defaultdict(list)
    # ip_failures[ip] = list of (datetime, event)
    ip_failures: Dict[str, List[Tuple[datetime, Dict[str, Any]]]] = defaultdict(list)

    # Track already alerted bursts to avoid redundant alert spam
    alerted_user_windows: Dict[str, datetime] = {}
    alerted_ip_windows: Dict[str, datetime] = {}

    total_events = len(sorted_events)
    failed_logon_count = 0
    successful_logon_count = 0
    privileged_logon_count = 0

    for ev in sorted_events:
        ev_id = ev.get("id")
        ts = parse_event_timestamp(ev.get("time_created"))
        # Windows account names are case-insensitive: "Admin" and "admin" are one target
        user = (ev.get("target_user_name") or "Unknown").lower()
        ip = ev.get("ip_address") or "N/A"
        date_key = ts.strftime("%Y-%m-%d")

        # -------------------------------------------------------------
        # Event 4625: Failed Logon
        # -------------------------------------------------------------
        if ev_id == 4625:
            failed_logon_count += 1
            daily_failures[date_key] += 1

            # Prune and append to user sliding window
            user_window = [
                (t, e) for t, e in user_failures[user]
                if ts - t <= window_delta
            ]
            user_window.append((ts, ev))
            user_failures[user] = user_window

            user_alert_triggered = False
            # Check user threshold
            if len(user_window) >= threshold:
                last_alert_time = alerted_user_windows.get(user)
                if last_alert_time is None or (ts - last_alert_time) > window_delta:
                    alerted_user_windows[user] = ts
                    if ip not in ("-", "::1", "127.0.0.1", "N/A"):
                        alerted_ip_windows[ip] = ts
                    user_alert_triggered = True
                    first_attempt_time = user_window[0][0].strftime("%H:%M:%S")
                    alerts.append(Alert(
                        scan_id=scan_id,
                        alert_type="Brute Force Attack",
                        timestamp=ts.isoformat(),
                        account=user,
                        source_ip=ip,
                        count=len(user_window),
                        severity="High",
                        details=(
                            f"Detected {len(user_window)} failed logon attempts targeting account '{user}' "
                            f"within {cfg.BRUTE_FORCE_WINDOW_MINUTES} minutes (from {first_attempt_time} to {ts.strftime('%H:%M:%S')}). "
                            f"Source IP: {ip}."
                        ),
                    ))

            # Prune and append to IP sliding window (ignore local '-' or loopback)
            if ip not in ("-", "::1", "127.0.0.1", "N/A"):
                ip_window = [
                    (t, e) for t, e in ip_failures[ip]
                    if ts - t <= window_delta
                ]
                ip_window.append((ts, ev))
                ip_failures[ip] = ip_window

                if len(ip_window) >= threshold and not user_alert_triggered:
                    last_alert_time = alerted_ip_windows.get(ip)
                    if last_alert_time is None or (ts - last_alert_time) > window_delta:
                        alerted_ip_windows[ip] = ts
                        alerts.append(Alert(
                            scan_id=scan_id,
                            alert_type="Brute Force Attack",
                            timestamp=ts.isoformat(),
                            account=user,
                            source_ip=ip,
                            count=len(ip_window),
                            severity="High",
                            details=(
                                f"Detected {len(ip_window)} failed logon attempts originating from source IP '{ip}' "
                                f"within {cfg.BRUTE_FORCE_WINDOW_MINUTES} minutes across multiple accounts."
                            ),
                        ))

        # -------------------------------------------------------------
        # Event 4624: Successful Logon
        # -------------------------------------------------------------
        elif ev_id == 4624:
            successful_logon_count += 1
            # Check for Possible Compromise: successful logon immediately after 5+ failures
            recent_failures = [
                (t, e) for t, e in user_failures[user]
                if ts - t <= window_delta
            ]
            if len(recent_failures) >= threshold:
                alerts.append(Alert(
                    scan_id=scan_id,
                    alert_type="Possible Compromise",
                    timestamp=ts.isoformat(),
                    account=user,
                    source_ip=ip,
                    count=len(recent_failures) + 1,
                    severity="Critical",
                    details=(
                        f"CRITICAL: Successful logon recorded for account '{user}' from IP '{ip}' "
                        f"immediately following {len(recent_failures)} failed logon attempts within {cfg.BRUTE_FORCE_WINDOW_MINUTES} minutes. "
                        f"This pattern indicates a high probability of successful credential brute-forcing or password spraying."
                    ),
                ))
                # Clear failure buffer after compromise alert
                user_failures[user] = []

        # -------------------------------------------------------------
        # Event 4720: User Account Created
        # -------------------------------------------------------------
        elif ev_id == 4720:
            creator = ev.get("subject_user_name") or "System/Unknown"
            alerts.append(Alert(
                scan_id=scan_id,
                alert_type="Account Created",
                timestamp=ts.isoformat(),
                account=user,
                source_ip=ip,
                count=1,
                severity="Medium",
                details=(
                    f"New local user account '{user}' was created by '{creator}'. "
                    f"Verify whether this account creation was authorized."
                ),
            ))

        # -------------------------------------------------------------
        # Event 4740: User Account Locked Out
        # -------------------------------------------------------------
        elif ev_id == 4740:
            alerts.append(Alert(
                scan_id=scan_id,
                alert_type="Account Lockout",
                timestamp=ts.isoformat(),
                account=user,
                source_ip=ip,
                count=1,
                severity="Medium",
                details=(
                    f"User account '{user}' was locked out after reaching the maximum failed logon threshold."
                ),
            ))

        # -------------------------------------------------------------
        # Event 4732: Member Added to Privileged Group
        # -------------------------------------------------------------
        elif ev_id == 4732:
            group = ev.get("group_name") or "Administrators"
            member = ev.get("member_name") or user
            creator = ev.get("subject_user_name") or "Unknown"
            alerts.append(Alert(
                scan_id=scan_id,
                alert_type="Privileged Group Addition",
                timestamp=ts.isoformat(),
                account=member,
                source_ip=ip,
                count=1,
                severity="High",
                details=(
                    f"Security-sensitive group modification: User '{member}' was added to group '{group}' "
                    f"by '{creator}'. Privilege escalation risk."
                ),
            ))

        # -------------------------------------------------------------
        # Event 4672: Special Privileges Assigned to New Logon
        # -------------------------------------------------------------
        elif ev_id == 4672:
            privileged_logon_count += 1

    # -----------------------------------------------------------------
    # Generate Module Findings for Risk Scoring
    # -----------------------------------------------------------------
    compromise_alerts = [a for a in alerts if a.alert_type == "Possible Compromise"]
    bruteforce_alerts = [a for a in alerts if a.alert_type == "Brute Force Attack"]
    group_alerts = [a for a in alerts if a.alert_type == "Privileged Group Addition"]
    account_alerts = [a for a in alerts if a.alert_type in ("Account Created", "Account Lockout")]

    if compromise_alerts:
        for ca in compromise_alerts:
            findings.append(Finding(
                scan_id=scan_id,
                module="logs",
                title=f"Possible Account Compromise: {ca.account}",
                evidence=ca.details,
                status="fail",
                likelihood=5,
                impact=5,
                risk_score=25,
                severity="Critical",
                remediation=(
                    f"Immediately isolate host, reset credentials for '{ca.account}', "
                    f"and inspect active sessions for unauthorized persistence."
                ),
            ))

    if bruteforce_alerts:
        for ba in bruteforce_alerts:
            findings.append(Finding(
                scan_id=scan_id,
                module="logs",
                title=f"Brute-Force Logon Activity: {ba.account}",
                evidence=ba.details,
                status="fail",
                likelihood=4,
                impact=3,
                risk_score=12,
                severity="High",
                remediation=(
                    "Enforce account lockout thresholds, block offending source IP at perimeter firewall, "
                    "and review account credentials for complexity."
                ),
            ))

    if group_alerts:
        for ga in group_alerts:
            findings.append(Finding(
                scan_id=scan_id,
                module="logs",
                title=f"Privileged Group Membership Escalation: {ga.account}",
                evidence=ga.details,
                status="fail",
                likelihood=3,
                impact=4,
                risk_score=12,
                severity="High",
                remediation="Audit group membership changes in local Administrators or privileged groups.",
            ))

    if account_alerts:
        for aa in account_alerts:
            findings.append(Finding(
                scan_id=scan_id,
                module="logs",
                title=f"Security Event Notice: {aa.alert_type} ({aa.account})",
                evidence=aa.details,
                status="fail",
                likelihood=3,
                impact=2,
                risk_score=6,
                severity="Medium",
                remediation="Confirm authorization for the account creation or investigate cause of lockout.",
            ))

    # If no incident alerts were detected, record a passing check
    if not alerts:
        findings.append(Finding(
            scan_id=scan_id,
            module="logs",
            title="Windows Security Log Incident Audit",
            evidence=(
                f"Analyzed {total_events} events over the analysis window "
                f"({failed_logon_count} failed logons, {successful_logon_count} successful logons, "
                f"{privileged_logon_count} privileged sessions). No brute-force or unauthorized activity detected."
            ),
            status="pass",
            likelihood=1,
            impact=1,
            risk_score=0,
            severity="Info",
            remediation="No remediation needed.",
        ))

    metrics = {
        "total_events_analyzed": total_events,
        "failed_logon_count": failed_logon_count,
        "successful_logon_count": successful_logon_count,
        "privileged_logon_count": privileged_logon_count,
        "daily_failures": dict(daily_failures),
    }

    return alerts, findings, metrics
