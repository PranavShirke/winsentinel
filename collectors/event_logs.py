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
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from config import get_config
from db.models import Finding, Alert
from collectors.config_audit import run_command
from analysis.bruteforce import analyze_security_events

FIXTURES_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "sample_events.json"


def clean_powershell_error(stderr: str) -> str:
    """
    Turn PowerShell's CLIXML-wrapped stderr into plain text.

    With -EncodedCommand, errors arrive as '#< CLIXML <Objs>...<S S="Error">text_x000D__x000A_</S>...'.

    Args:
        stderr: Raw stderr from the PowerShell process.

    Returns:
        str: Human-readable error text.
    """
    if "CLIXML" not in stderr:
        return stderr.strip()
    parts = re.findall(r'<S S="Error">(.*?)</S>', stderr, flags=re.DOTALL)
    text = "".join(parts).replace("_x000D_", "").replace("_x000A_", " ")
    return text.strip() or "PowerShell reported an error."


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
    max_events: int = 5000,
    since_minutes: Optional[int] = None,
) -> Tuple[bool, List[Dict[str, Any]], str]:
    """
    Query the Windows Security event log for authentication and privilege events.

    Args:
        days: Number of days in the past to query.
        max_events: Maximum number of events to extract.
        since_minutes: If set, query only the last N minutes (used by the live monitor) instead of `days`.

    Returns:
        Tuple[bool, List[Dict[str, Any]], str]: (success, list_of_events, error_message).
    """
    if sys.platform != "win32":
        return False, [], "Event log collector only supported on Windows operating systems."

    # Build PowerShell script with XML parsing to extract structured event data
    days = int(days)
    max_events = int(max_events)
    # Integers only are interpolated into the script, so no input can inject PowerShell
    start_expr = f"(Get-Date).AddMinutes(-{int(since_minutes)})" if since_minutes else f"(Get-Date).AddDays(-{days})"
    # Two queries: attack/audit events are rare and always fetched in full, while the
    # very noisy 4624/4672 logon events are capped so they cannot push 4625s out of the result.
    ps_script = f"""
$ErrorActionPreference = 'Stop'
try {{
    # Windows reports "no events found" (not "access denied") when a non-admin reads the
    # Security log, which would look like a clean log. Probe first so that is never a false all-clear.
    try {{ $null = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop }}
    catch {{
        [Console]::Error.WriteLine('Cannot read the Security log (access denied or log empty). Run as Administrator or join Event Log Readers.')
        exit 1
    }}
    $startDate = {start_expr}
    $rawEvents = @()
    foreach ($q in @(@{{ids = @(4625, 4720, 4740, 4732); max = {max_events}}}, @{{ids = @(4624, 4672); max = {max_events // 2}}})) {{
        try {{
            $rawEvents += Get-WinEvent -FilterHashtable @{{
                LogName = 'Security'; Id = $q.ids; StartTime = $startDate
            }} -MaxEvents $q.max
        }} catch {{
            # "No events were found" simply means a clean log for this ID set
            if ($_.FullyQualifiedErrorId -notlike '*NoMatchingEventsFound*') {{ throw }}
        }}
    }}
    $results = @()
    foreach ($ev in $rawEvents) {{
        $xml = [xml]$ev.ToXml()
        $data = @{{}}
        foreach ($d in $xml.Event.EventData.Data) {{
            if ($d.Name) {{ $data[$d.Name] = $d.'#text' }}
        }}
        $results += [PSCustomObject]@{{
            record_id          = [int64]$ev.RecordId
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
    if ($results.Count -eq 0) {{ '[]' }} else {{ ConvertTo-Json -InputObject @($results) -Compress }}
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
        timeout=90,
    )

    if not success:
        err_msg = clean_powershell_error(stderr) or "Security log query failed (access denied or log unavailable)."
        return False, [], err_msg
    if not stdout.strip():
        return True, [], ""

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
