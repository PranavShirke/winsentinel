"""
WinSentinel - Windows Security Event Log Collector.

This module extracts Windows Security events (4625, 4624, 4720, 4740, 4732, 4672)
using PowerShell Get-WinEvent with encoded commands to avoid shell injection or quoting issues.
If access is denied (non-elevated terminal), it yields a clear error Finding instead of crashing.
"""

import sys
import os
import json
import base64
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from config import get_config
from db.models import Finding, Alert
from collectors.config_audit import run_command
from analysis.bruteforce import analyze_security_events

FIXTURES_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "sample_events.json"


def load_events_from_fixture(fixture_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """
    Load pre-recorded Windows Security events from a JSON fixture for testing.

    Args:
        fixture_path: Optional path to the sample events JSON file.

    Returns:
        List[Dict[str, Any]]: Loaded event records.
    """
    path = fixture_path or FIXTURES_PATH
    if not path.exists():
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception as exc:
        print(f"[-] Error loading event fixture: {exc}", file=sys.stderr)
        return []


def collect_security_events(
    days: int = 7,
    max_events: int = 1000,
) -> Tuple[bool, List[Dict[str, Any]], str]:
    """
    Query the Windows Security event log for authentication and privilege events.

    Args:
        days: Number of days in the past to query.
        max_events: Maximum number of events to extract.

    Returns:
        Tuple[bool, List[Dict[str, Any]], str]: (success, list_of_events, error_message).
    """
    if sys.platform != "win32":
        return False, [], "Event log collector only supported on Windows operating systems."

    # Build PowerShell script with XML parsing to extract structured event data
    ps_script = f"""
$ErrorActionPreference = 'Stop'
try {{
    $startDate = (Get-Date).AddDays(-{days})
    $Filter = @{{
        LogName   = 'Security'
        Id        = @(4625, 4624, 4720, 4740, 4732, 4672)
        StartTime = $startDate
    }}
    $rawEvents = Get-WinEvent -FilterHashtable $Filter -MaxEvents {max_events}
    $results = @()
    foreach ($ev in $rawEvents) {{
        $xml = [xml]$ev.ToXml()
        $data = @{{}}
        foreach ($d in $xml.Event.EventData.Data) {{
            if ($d.Name) {{ $data[$d.Name] = $d.'#text' }}
        }}
        $results += [PSCustomObject]@{{
            id                 = [int]$ev.Id
            time_created       = $ev.TimeCreated.ToString('o')
            target_user_name   = $data['TargetUserName']
            target_domain_name = $data['TargetDomainName']
            ip_address         = $data['IpAddress']
            logon_type         = $data['LogonType']
            status             = $data['Status']
            sub_status         = $data['SubStatus']
            subject_user_name  = $data['SubjectUserName']
            member_name        = $data['MemberName']
            group_name         = $data['TargetUserName']
        }}
    }}
    $results | ConvertTo-Json -Compress
}} catch {{
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}}
"""

    # Encode script as UTF-16LE base64 for PowerShell -EncodedCommand (robust against quotes & newlines)
    encoded_bytes = base64.b64encode(ps_script.encode("utf-16le"))
    encoded_str = encoded_bytes.decode("ascii")

    success, stdout, stderr = run_command(
        ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded_str],
        timeout=30,
    )

    if not success or not stdout.strip():
        err_msg = stderr.strip() or "No events retrieved or unauthorized operation."
        return False, [], err_msg

    try:
        parsed = json.loads(stdout)
        if isinstance(parsed, dict):
            return True, [parsed], ""
        elif isinstance(parsed, list):
            return True, parsed, ""
        return True, [], ""
    except json.JSONDecodeError as jde:
        return False, [], f"Failed to parse PowerShell JSON output: {jde}"


def run_event_log_audit(
    scan_id: Optional[int] = None,
    days: Optional[int] = None,
    fallback_to_sample: bool = False,
) -> Tuple[List[Alert], List[Finding], Dict[str, Any]]:
    """
    Execute full event log collection and brute-force correlation.

    Args:
        scan_id: Associated scan identifier.
        days: Analysis window in days (defaults to config setting).
        fallback_to_sample: If True, uses sample_events.json when live log query fails.

    Returns:
        Tuple[List[Alert], List[Finding], Dict[str, Any]]:
            - alerts: List of security incident alerts.
            - findings: Findings for module='logs'.
            - metrics: Summary statistics (daily failures, counts).
    """
    cfg = get_config()
    window_days = days or cfg.DEFAULT_LOG_ANALYSIS_DAYS

    success, events, err_msg = collect_security_events(days=window_days)

    if not success:
        if fallback_to_sample:
            events = load_events_from_fixture()
            print(f"[!] Live Security log access failed ({err_msg}). Falling back to sample events fixture ({len(events)} events).")
        else:
            # Create graceful error Finding per brief specifications
            error_finding = Finding(
                scan_id=scan_id,
                module="logs",
                title="Windows Security Event Log Query Failed",
                evidence=f"Get-WinEvent error: {err_msg}. Access to the Security event log requires Administrator elevation.",
                status="error",
                likelihood=1,
                impact=1,
                risk_score=0,
                severity="Error",
                remediation="Run the terminal with Administrator privileges ('Run as administrator') to permit Security log inspection.",
            )
            return [], [error_finding], {}

    return analyze_security_events(events, scan_id=scan_id)
