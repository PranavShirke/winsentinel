"""
WinSentinel - Windows Configuration Audit Collector.

This module performs read-only security posture audits on the local Windows system:
  1. Password Policy (net accounts)
  2. Local User and Administrator Accounts (net user, net localgroup administrators)
  3. Windows Firewall Status across Domain, Private, and Public profiles (netsh advfirewall)
  4. Microsoft Defender Status and Signature Age (Get-MpComputerStatus)
  5. Remote Desktop Protocol (RDP) & Network Level Authentication (NLA) (winreg)
  6. SMBv1 Legacy Protocol Exposure (Get-SmbServerConfiguration)
  7. Risky Listening Network Ports (psutil.net_connections)

Design rules:
  - Read-only: never alters system settings.
  - Subprocess calls strictly use argument lists (no shell=True).
  - Parsers are decoupled from command execution for pure unit testing.
  - Errors produce status="error" Finding objects without crashing the scan.
"""

import sys
import subprocess
import json
import re
from typing import List, Dict, Any, Optional, Tuple

import psutil

try:
    import winreg
except ImportError:
    winreg = None  # Fallback for non-Windows test environments

from config import get_config
from db.models import Finding


# ---------------------------------------------------------------------------
# Safe Subprocess Command Execution
# ---------------------------------------------------------------------------

def run_command(cmd_args: List[str], timeout: int = 15) -> Tuple[bool, str, str]:
    """
    Execute a system command safely with an argument list (no shell=True).

    Args:
        cmd_args: List of command arguments.
        timeout: Maximum execution timeout in seconds.

    Returns:
        Tuple[bool, str, str]: (success_flag, stdout_text, stderr_text).
    """
    try:
        proc = subprocess.run(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            shell=False,
        )
        success = (proc.returncode == 0)
        return success, proc.stdout, proc.stderr
    except FileNotFoundError as fnf:
        return False, "", f"Command executable not found: {fnf}"
    except subprocess.TimeoutExpired:
        return False, "", f"Command timed out after {timeout} seconds: {' '.join(cmd_args)}"
    except PermissionError as pe:
        return False, "", f"Permission denied executing command: {pe}"
    except Exception as exc:
        return False, "", f"Execution error: {exc}"


# ---------------------------------------------------------------------------
# Pure Parsers (Decoupled from OS execution for testing)
# ---------------------------------------------------------------------------

def parse_net_accounts(output: str) -> Dict[str, Any]:
    """
    Parse the plain text output of 'net accounts' into a dictionary of policy settings.

    Args:
        output: Raw stdout from the 'net accounts' command.

    Returns:
        Dict[str, Any]: Extracted password policy values.
    """
    policy = {
        "min_pw_len": 0,
        "max_pw_age_days": 0,
        "min_pw_age_days": 0,
        "pw_history_len": 0,
        "lockout_threshold": 0,
        "lockout_duration_mins": 0,
        "lockout_window_mins": 0,
    }

    for line in output.splitlines():
        line_clean = line.strip()
        if not line_clean or ":" not in line_clean:
            continue

        key, val = [part.strip() for part in line_clean.split(":", 1)]
        key_lower = key.lower()

        try:
            if "minimum password length" in key_lower:
                policy["min_pw_len"] = int(val)
            elif "maximum password age" in key_lower:
                policy["max_pw_age_days"] = 0 if val.lower() == "unlimited" else int(val)
            elif "minimum password age" in key_lower:
                policy["min_pw_age_days"] = int(val)
            elif "password history" in key_lower:
                policy["pw_history_len"] = 0 if val.lower() == "none" else int(val)
            elif "lockout threshold" in key_lower:
                policy["lockout_threshold"] = 0 if val.lower() == "never" else int(val)
            elif "lockout duration" in key_lower:
                policy["lockout_duration_mins"] = int(val)
            elif "lockout observation window" in key_lower:
                policy["lockout_window_mins"] = int(val)
        except ValueError:
            continue

    return policy


def parse_net_user_list(output: str) -> List[str]:
    """
    Parse the plain text output of 'net user' into a list of usernames.

    Args:
        output: Raw stdout from 'net user'.

    Returns:
        List[str]: List of discovered local user account names.
    """
    accounts = []
    capture = False
    for line in output.splitlines():
        line_clean = line.strip()
        if "---" in line_clean:
            capture = True
            continue
        if "The command completed successfully." in line_clean:
            break
        if capture and line_clean:
            parts = line_clean.split()
            accounts.extend(parts)
    return accounts


def parse_net_user_detail(output: str) -> Dict[str, Any]:
    """
    Parse the plain text output of 'net user <username>' into account details.

    Args:
        output: Raw stdout from 'net user <username>'.

    Returns:
        Dict[str, Any]: Extracted account attributes (e.g. active status).
    """
    details = {
        "username": "",
        "active": False,
        "password_required": True,
    }
    for line in output.splitlines():
        line_clean = line.strip()
        if not line_clean:
            continue
        if line_clean.lower().startswith("user name"):
            parts = line_clean.split(maxsplit=2)
            if len(parts) >= 3:
                details["username"] = parts[2].strip()
        elif line_clean.lower().startswith("account active"):
            parts = line_clean.split(maxsplit=2)
            if len(parts) >= 3:
                details["active"] = (parts[2].strip().lower() == "yes")
        elif line_clean.lower().startswith("password required"):
            parts = line_clean.split(maxsplit=2)
            if len(parts) >= 3:
                details["password_required"] = (parts[2].strip().lower() == "yes")
    return details


def parse_net_localgroup_administrators(output: str) -> List[str]:
    """
    Parse the members list from 'net localgroup administrators' output.

    Args:
        output: Raw stdout from 'net localgroup administrators'.

    Returns:
        List[str]: Names of members belonging to local Administrators group.
    """
    members = []
    capture = False
    for line in output.splitlines():
        line_clean = line.strip()
        if "---" in line_clean:
            capture = True
            continue
        if "The command completed successfully." in line_clean:
            break
        if capture and line_clean:
            members.append(line_clean)
    return members


def parse_firewall_profiles(output: str) -> Dict[str, str]:
    """
    Parse profile states from 'netsh advfirewall show allprofiles state'.

    Args:
        output: Raw stdout from the netsh firewall query.

    Returns:
        Dict[str, str]: Map of profile name to state ('ON', 'OFF', or 'UNKNOWN').
    """
    profiles = {
        "Domain": "UNKNOWN",
        "Private": "UNKNOWN",
        "Public": "UNKNOWN",
    }
    current_profile = None

    for line in output.splitlines():
        line_clean = line.strip()
        if "Domain Profile Settings" in line_clean:
            current_profile = "Domain"
        elif "Private Profile Settings" in line_clean:
            current_profile = "Private"
        elif "Public Profile Settings" in line_clean:
            current_profile = "Public"
        elif line_clean.startswith("State") and current_profile:
            parts = line_clean.split()
            if len(parts) >= 2:
                profiles[current_profile] = parts[1].strip().upper()

    return profiles


def parse_defender_status(json_str: str) -> Dict[str, Any]:
    """
    Parse JSON output from PowerShell Get-MpComputerStatus.

    Args:
        json_str: JSON formatted string from PowerShell.

    Returns:
        Dict[str, Any]: Key Defender metrics or empty dictionary if invalid.
    """
    try:
        data = json.loads(json_str)
        return {
            "antivirus_enabled": bool(data.get("AntivirusEnabled", False)),
            "realtime_enabled": bool(data.get("RealTimeProtectionEnabled", False)),
            "signature_age_days": int(data.get("AntivirusSignatureAge", 999)),
            "behavior_monitor_enabled": bool(data.get("BehaviorMonitorEnabled", False)),
            "ioav_protection_enabled": bool(data.get("IoavProtectionEnabled", False)),
        }
    except Exception:
        return {}


def parse_smb_config(json_str: str) -> Dict[str, Any]:
    """
    Parse JSON output from PowerShell Get-SmbServerConfiguration.

    Args:
        json_str: JSON formatted string from PowerShell.

    Returns:
        Dict[str, Any]: SMB configuration properties.
    """
    try:
        data = json.loads(json_str)
        return {
            "smb1_enabled": bool(data.get("EnableSMB1Protocol", False)),
            "smb2_enabled": bool(data.get("EnableSMB2Protocol", True)),
        }
    except Exception:
        return {}


def parse_rdp_registry(f_deny_ts: Optional[int], user_auth: Optional[int]) -> Dict[str, Any]:
    """
    Parse Windows Registry flags governing Remote Desktop and Network Level Authentication.

    Args:
        f_deny_ts: Value of fDenyTSConnections (1 = disabled, 0 = enabled).
        user_auth: Value of UserAuthentication (1 = NLA required, 0 = NLA not required).

    Returns:
        Dict[str, Any]: RDP status flags.
    """
    rdp_enabled = (f_deny_ts == 0)
    nla_required = (user_auth == 1)
    return {
        "rdp_enabled": rdp_enabled,
        "nla_required": nla_required,
        "f_deny_ts": f_deny_ts,
        "user_auth": user_auth,
    }


def parse_listening_ports(
    connections: List[Any],
    risky_ports_map: Dict[int, str],
) -> List[Dict[str, Any]]:
    """
    Filter active listening sockets against the risky port inventory.

    Args:
        connections: List of socket connection namedtuples from psutil.
        risky_ports_map: Map of risky port number to risk description.

    Returns:
        List[Dict[str, Any]]: List of flagged listening port entries.
    """
    flagged = []
    by_key: Dict[Tuple[int, int], Dict[str, Any]] = {}

    for conn in connections:
        if conn.status != "LISTEN":
            continue

        port = conn.laddr.port
        ip = conn.laddr.ip
        pid = conn.pid or 0

        # Loopback-only listeners are not reachable from the network, so they are not exposure
        if ip in ("127.0.0.1", "::1"):
            continue

        if port in risky_ports_map:
            key = (port, pid)
            if key in by_key:
                # Same service listening on IPv4 and IPv6: report once, list both addresses
                if ip not in by_key[key]["ip"].split(" / "):
                    by_key[key]["ip"] += " / " + ip
                continue

            proc_name = "Unknown"
            if pid > 0:
                try:
                    p = psutil.Process(pid)
                    proc_name = p.name()
                except Exception:
                    proc_name = "System/Protected"

            entry = {
                "port": port,
                "ip": ip,
                "pid": pid,
                "process_name": proc_name,
                "service": risky_ports_map[port],
            }
            by_key[key] = entry
            flagged.append(entry)

    return flagged


# ---------------------------------------------------------------------------
# Evaluators (Produce Findings aligned with NIST SP 800-30 Likelihood x Impact)
# ---------------------------------------------------------------------------

def evaluate_password_policy(policy: Dict[str, Any], scan_id: Optional[int] = None) -> List[Finding]:
    """
    Evaluate system password policy against industry benchmarks (CIS / NIST).

    Args:
        policy: Parsed password policy dictionary.
        scan_id: Associated scan ID.

    Returns:
        List[Finding]: Security findings for password policy.
    """
    findings = []

    # 1. Minimum Password Length
    min_len = policy.get("min_pw_len", 0)
    if min_len < 8:
        findings.append(Finding(
            scan_id=scan_id,
            module="config",
            title="Weak Minimum Password Length Policy",
            evidence=f"net accounts: Minimum password length is {min_len} characters (Recommended >= 12).",
            status="fail",
            likelihood=3,
            impact=3,
            risk_score=9,
            severity="Medium",
            remediation="Enforce minimum password length >= 12 via command: 'net accounts /minpwlen:12'.",
        ))
    else:
        findings.append(Finding(
            scan_id=scan_id,
            module="config",
            title="Minimum Password Length Enforced",
            evidence=f"net accounts: Minimum password length is configured to {min_len} characters.",
            status="pass",
            likelihood=1,
            impact=1,
            risk_score=0,
            severity="Info",
            remediation="No remediation needed.",
        ))

    # 2. Account Lockout Threshold (Brute-Force mitigation)
    lockout = policy.get("lockout_threshold", 0)
    if lockout == 0:
        findings.append(Finding(
            scan_id=scan_id,
            module="config",
            title="Account Lockout Threshold Disabled",
            evidence="net accounts: Lockout threshold is 0 (Accounts will never lock out after failed logons).",
            status="fail",
            likelihood=4,
            impact=3,
            risk_score=12,
            severity="High",
            remediation="Enable account lockout threshold: 'net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15'.",
        ))
    else:
        findings.append(Finding(
            scan_id=scan_id,
            module="config",
            title="Account Lockout Threshold Active",
            evidence=f"net accounts: Lockout threshold set to {lockout} failed attempts.",
            status="pass",
            likelihood=1,
            impact=1,
            risk_score=0,
            severity="Info",
            remediation="No remediation needed.",
        ))

    # 3. Password History (Prevent reuse)
    history = policy.get("pw_history_len", 0)
    if history < 5:
        findings.append(Finding(
            scan_id=scan_id,
            module="config",
            title="Insufficient Password History Maintained",
            evidence=f"net accounts: Password history maintained is {history} (Recommended >= 5).",
            status="fail",
            likelihood=2,
            impact=2,
            risk_score=4,
            severity="Low",
            remediation="Enforce password history: 'net accounts /uniquepw:5'.",
        ))
    else:
        findings.append(Finding(
            scan_id=scan_id,
            module="config",
            title="Password History Maintained",
            evidence=f"net accounts: Password history maintained is {history} passwords.",
            status="pass",
            likelihood=1,
            impact=1,
            risk_score=0,
            severity="Info",
            remediation="No remediation needed.",
        ))

    return findings


def evaluate_user_accounts(
    guest_details: Dict[str, Any],
    admin_members: List[str],
    scan_id: Optional[int] = None,
) -> List[Finding]:
    """
    Evaluate user accounts and local administrative privilege delegation.

    Args:
        guest_details: Parsed details for the built-in Guest account.
        admin_members: Members list from local Administrators group.
        scan_id: Associated scan ID.

    Returns:
        List[Finding]: Security findings for user account posture.
    """
    findings = []

    # 1. Built-in Guest account exposure
    is_guest_active = guest_details.get("active", False)
    if is_guest_active:
        findings.append(Finding(
            scan_id=scan_id,
            module="config",
            title="Built-in Guest Account Is Active",
            evidence="net user Guest: 'Account active: Yes'. Active Guest accounts provide unauthenticated access vectors.",
            status="fail",
            likelihood=4,
            impact=4,
            risk_score=16,
            severity="Critical",
            remediation="Disable the built-in Guest account: 'net user Guest /active:no'.",
        ))
    else:
        findings.append(Finding(
            scan_id=scan_id,
            module="config",
            title="Built-in Guest Account Is Disabled",
            evidence="net user Guest: 'Account active: No'.",
            status="pass",
            likelihood=1,
            impact=1,
            risk_score=0,
            severity="Info",
            remediation="No remediation needed.",
        ))

    # 2. Local Administrators Group Membership
    admin_count = len(admin_members)
    admin_list_str = ", ".join(admin_members) if admin_members else "None"

    if admin_count > 3:
        findings.append(Finding(
            scan_id=scan_id,
            module="config",
            title="Excessive Local Administrators Delegated",
            evidence=f"net localgroup administrators contains {admin_count} accounts: {admin_list_str}.",
            status="fail",
            likelihood=3,
            impact=3,
            risk_score=9,
            severity="Medium",
            remediation="Review local Administrators group membership and apply principle of least privilege.",
        ))
    else:
        findings.append(Finding(
            scan_id=scan_id,
            module="config",
            title="Local Administrators Privilege Audit",
            evidence=f"Local Administrators group members ({admin_count}): {admin_list_str}.",
            status="pass",
            likelihood=1,
            impact=1,
            risk_score=0,
            severity="Info",
            remediation="No remediation needed.",
        ))

    return findings


def evaluate_firewall_profiles(profiles: Dict[str, str], scan_id: Optional[int] = None) -> List[Finding]:
    """
    Evaluate Windows Defender Firewall status across Domain, Private, and Public profiles.

    Args:
        profiles: Map of profile name to state ('ON', 'OFF', or 'UNKNOWN').
        scan_id: Associated scan ID.

    Returns:
        List[Finding]: Security findings for firewall configuration.
    """
    findings = []
    disabled_profiles = [p for p, state in profiles.items() if state == "OFF"]

    if disabled_profiles:
        evidence_str = "; ".join([f"{p}: {state}" for p, state in profiles.items()])
        findings.append(Finding(
            scan_id=scan_id,
            module="config",
            title="Windows Defender Firewall Disabled on One or More Profiles",
            evidence=f"netsh advfirewall: Profiles disabled: {', '.join(disabled_profiles)}. ({evidence_str})",
            status="fail",
            likelihood=4,
            impact=4,
            risk_score=16,
            severity="Critical",
            remediation="Enable Windows Firewall on all profiles: 'netsh advfirewall set allprofiles state on'.",
        ))
    else:
        all_on = all(state == "ON" for state in profiles.values())
        evidence_str = "; ".join([f"{p}: {state}" for p, state in profiles.items()])
        findings.append(Finding(
            scan_id=scan_id,
            module="config",
            title="Windows Defender Firewall Active on All Profiles",
            evidence=f"netsh advfirewall: All firewall profiles are active ({evidence_str}).",
            status="pass" if all_on else "error",
            likelihood=1,
            impact=1,
            risk_score=0,
            severity="Info",
            remediation="No remediation needed.",
        ))

    return findings


def evaluate_defender_status(defender: Dict[str, Any], scan_id: Optional[int] = None) -> List[Finding]:
    """
    Evaluate Microsoft Defender Antivirus operational state and signature freshness.

    Args:
        defender: Parsed Defender status metrics.
        scan_id: Associated scan ID.

    Returns:
        List[Finding]: Security findings for Defender.
    """
    findings = []
    if not defender:
        return [
            Finding(
                scan_id=scan_id,
                module="config",
                title="Microsoft Defender Status Query Failed",
                evidence="Get-MpComputerStatus returned empty output or requires Administrator privileges.",
                status="error",
                likelihood=1,
                impact=1,
                risk_score=0,
                severity="Error",
                remediation="Ensure scan is run from an elevated PowerShell terminal.",
            )
        ]

    # Real-time protection check
    rtp_enabled = defender.get("realtime_enabled", False)
    av_enabled = defender.get("antivirus_enabled", False)

    if not rtp_enabled or not av_enabled:
        findings.append(Finding(
            scan_id=scan_id,
            module="config",
            title="Microsoft Defender Real-Time Protection Disabled",
            evidence=f"Get-MpComputerStatus: AntivirusEnabled={av_enabled}, RealTimeProtectionEnabled={rtp_enabled}.",
            status="fail",
            likelihood=5,
            impact=4,
            risk_score=20,
            severity="Critical",
            remediation="Enable real-time protection: 'Set-MpPreference -DisableRealtimeMonitoring $false'.",
        ))
    else:
        findings.append(Finding(
            scan_id=scan_id,
            module="config",
            title="Microsoft Defender Real-Time Protection Active",
            evidence="Get-MpComputerStatus: Antivirus and real-time protection services are active.",
            status="pass",
            likelihood=1,
            impact=1,
            risk_score=0,
            severity="Info",
            remediation="No remediation needed.",
        ))

    # Signature Age check
    sig_age = defender.get("signature_age_days", 999)
    if sig_age > 7:
        findings.append(Finding(
            scan_id=scan_id,
            module="config",
            title="Antivirus Signatures Outdated",
            evidence=f"Get-MpComputerStatus: AntivirusSignatureAge is {sig_age} days (Threshold <= 3 days).",
            status="fail",
            likelihood=4,
            impact=3,
            risk_score=12,
            severity="High",
            remediation="Update Defender intelligence signatures immediately via: 'Update-MpSignature'.",
        ))
    elif sig_age > 3:
        findings.append(Finding(
            scan_id=scan_id,
            module="config",
            title="Antivirus Signatures Moderately Stale",
            evidence=f"Get-MpComputerStatus: AntivirusSignatureAge is {sig_age} days.",
            status="fail",
            likelihood=2,
            impact=3,
            risk_score=6,
            severity="Medium",
            remediation="Trigger signature update via Windows Update or 'Update-MpSignature'.",
        ))
    else:
        findings.append(Finding(
            scan_id=scan_id,
            module="config",
            title="Antivirus Signatures Up to Date",
            evidence=f"Get-MpComputerStatus: AntivirusSignatureAge is {sig_age} days (Current).",
            status="pass",
            likelihood=1,
            impact=1,
            risk_score=0,
            severity="Info",
            remediation="No remediation needed.",
        ))

    return findings


def evaluate_rdp_exposure(rdp_data: Dict[str, Any], scan_id: Optional[int] = None) -> List[Finding]:
    """
    Evaluate Remote Desktop Protocol exposure and Network Level Authentication (NLA) enforcement.

    Args:
        rdp_data: Parsed RDP configuration dictionary.
        scan_id: Associated scan ID.

    Returns:
        List[Finding]: Security findings for RDP.
    """
    findings = []
    rdp_enabled = rdp_data.get("rdp_enabled", False)
    nla_required = rdp_data.get("nla_required", False)

    if rdp_enabled:
        if not nla_required:
            findings.append(Finding(
                scan_id=scan_id,
                module="config",
                title="RDP Enabled Without Network Level Authentication (NLA)",
                evidence="Registry: fDenyTSConnections=0 (RDP Enabled) and UserAuthentication=0 (NLA Disabled). "
                         "This exposes the endpoint to pre-authentication exploits (e.g. BlueKeep).",
                status="fail",
                likelihood=4,
                impact=4,
                risk_score=16,
                severity="Critical",
                remediation="Enforce NLA in registry: Set 'UserAuthentication'=1 under HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp.",
            ))
        else:
            findings.append(Finding(
                scan_id=scan_id,
                module="config",
                title="RDP Enabled With Network Level Authentication Enforced",
                evidence="Registry: fDenyTSConnections=0 (RDP Enabled) with UserAuthentication=1 (NLA Required).",
                status="pass",
                likelihood=1,
                impact=1,
                risk_score=0,
                severity="Info",
                remediation="If remote desktop access is not required, disable RDP completely.",
            ))
    else:
        findings.append(Finding(
            scan_id=scan_id,
            module="config",
            title="Remote Desktop Protocol (RDP) Disabled",
            evidence="Registry: fDenyTSConnections=1 (RDP Connections Denied).",
            status="pass",
            likelihood=1,
            impact=1,
            risk_score=0,
            severity="Info",
            remediation="No remediation needed.",
        ))

    return findings


def evaluate_smb_protocol(smb_data: Dict[str, Any], scan_id: Optional[int] = None) -> List[Finding]:
    """
    Evaluate SMB protocol versions for legacy SMBv1 exposure (EternalBlue vector).

    Args:
        smb_data: Parsed SMB server configuration.
        scan_id: Associated scan ID.

    Returns:
        List[Finding]: Security findings for SMB.
    """
    findings = []
    smb1_enabled = smb_data.get("smb1_enabled", False)

    if smb1_enabled:
        findings.append(Finding(
            scan_id=scan_id,
            module="config",
            title="SMBv1 Legacy Protocol Is Enabled",
            evidence="Get-SmbServerConfiguration: EnableSMB1Protocol is True. "
                     "SMBv1 lacks modern integrity protections and exposes host to MS17-010 / EternalBlue.",
            status="fail",
            likelihood=4,
            impact=5,
            risk_score=20,
            severity="Critical",
            remediation="Disable SMBv1 immediately: 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force'.",
        ))
    else:
        findings.append(Finding(
            scan_id=scan_id,
            module="config",
            title="SMBv1 Legacy Protocol Is Disabled",
            evidence="Get-SmbServerConfiguration: EnableSMB1Protocol is False.",
            status="pass",
            likelihood=1,
            impact=1,
            risk_score=0,
            severity="Info",
            remediation="No remediation needed.",
        ))

    return findings


def evaluate_listening_ports(flagged_ports: List[Dict[str, Any]], scan_id: Optional[int] = None) -> List[Finding]:
    """
    Evaluate active listening network sockets against risky service definitions.

    Args:
        flagged_ports: List of risky listening socket dictionaries.
        scan_id: Associated scan ID.

    Returns:
        List[Finding]: Security findings for risky listening ports.
    """
    findings = []

    if not flagged_ports:
        findings.append(Finding(
            scan_id=scan_id,
            module="config",
            title="No High-Risk Network Ports Exposed",
            evidence="Network socket scan did not detect unencrypted remote management or legacy exposure ports (23, 135, 139, 445, 3389, 5985).",
            status="pass",
            likelihood=1,
            impact=1,
            risk_score=0,
            severity="Info",
            remediation="No remediation needed.",
        ))
        return findings

    for item in flagged_ports:
        port = item["port"]
        ip = item["ip"]
        pid = item["pid"]
        proc_name = item["process_name"]
        service = item["service"]

        # Determine severity based on port type
        if port == 23:
            severity = "Critical"
            likelihood = 4
            impact = 4
            remediation = "Disable the Telnet Server service immediately."
        elif port == 445:
            severity = "High"
            likelihood = 3
            impact = 4
            remediation = "Restrict SMB port 445 on Windows Firewall to trusted subnets only."
        elif port == 3389:
            severity = "High"
            likelihood = 3
            impact = 4
            remediation = "Ensure RDP has Network Level Authentication (NLA) and firewall restrictions."
        else:
            severity = "Medium"
            likelihood = 3
            impact = 3
            remediation = f"Review listening process {proc_name} (PID: {pid}) and disable unused services."

        risk_score = likelihood * impact

        findings.append(Finding(
            scan_id=scan_id,
            module="config",
            title=f"Risky Listening Port {port} Exposed ({service.split()[0]})",
            evidence=f"Listening on {ip}:{port} by process '{proc_name}' (PID: {pid}). Service details: {service}.",
            status="fail",
            likelihood=likelihood,
            impact=impact,
            risk_score=risk_score,
            severity=severity,
            remediation=remediation,
        ))

    return findings


# ---------------------------------------------------------------------------
# High-Level Audit Collectors (Live Windows Execution with Safe Error Handling)
# ---------------------------------------------------------------------------

def check_password_policy(scan_id: Optional[int] = None) -> List[Finding]:
    """Execute 'net accounts' and evaluate the password policy."""
    success, stdout, stderr = run_command(["net", "accounts"])
    if not success or not stdout.strip():
        return [Finding(
            scan_id=scan_id,
            module="config",
            title="Password Policy Audit Failed",
            evidence=f"net accounts error: {stderr or 'Empty output'}",
            status="error",
            severity="Error",
            remediation="Ensure the tool is run with proper privileges.",
        )]
    parsed = parse_net_accounts(stdout)
    return evaluate_password_policy(parsed, scan_id=scan_id)


def check_user_accounts(scan_id: Optional[int] = None) -> List[Finding]:
    """Inspect built-in Guest status and local Administrators group members."""
    findings = []

    # Guest details
    g_success, g_stdout, g_stderr = run_command(["net", "user", "Guest"])
    if g_success:
        guest_details = parse_net_user_detail(g_stdout)
    else:
        guest_details = {"active": False}  # Default safe assumption or error

    # Administrators group
    a_success, a_stdout, a_stderr = run_command(["net", "localgroup", "administrators"])
    if a_success:
        admin_members = parse_net_localgroup_administrators(a_stdout)
    else:
        admin_members = []

    if not g_success and not a_success:
        return [Finding(
            scan_id=scan_id,
            module="config",
            title="User Account Audit Failed",
            evidence=f"net user / localgroup query error: {g_stderr or a_stderr}",
            status="error",
            severity="Error",
            remediation="Run the audit from an elevated administrator command prompt.",
        )]

    return evaluate_user_accounts(guest_details, admin_members, scan_id=scan_id)


def check_firewall_status(scan_id: Optional[int] = None) -> List[Finding]:
    """Query Windows Defender Firewall state across all profiles."""
    success, stdout, stderr = run_command(["netsh", "advfirewall", "show", "allprofiles", "state"])
    if not success or not stdout.strip():
        return [Finding(
            scan_id=scan_id,
            module="config",
            title="Firewall Audit Failed",
            evidence=f"netsh advfirewall error: {stderr or 'No output received'}",
            status="error",
            severity="Error",
            remediation="Ensure netsh is accessible and run as Administrator.",
        )]
    parsed = parse_firewall_profiles(stdout)
    return evaluate_firewall_profiles(parsed, scan_id=scan_id)


def check_defender_status(scan_id: Optional[int] = None) -> List[Finding]:
    """Query Windows Defender status and signature freshness via PowerShell."""
    ps_cmd = (
        "Get-MpComputerStatus | "
        "Select-Object -Property AntivirusEnabled,RealTimeProtectionEnabled,"
        "AntivirusSignatureAge,BehaviorMonitorEnabled,IoavProtectionEnabled | "
        "ConvertTo-Json"
    )
    success, stdout, stderr = run_command(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd])
    if not success or not stdout.strip():
        return [Finding(
            scan_id=scan_id,
            module="config",
            title="Microsoft Defender Query Failed",
            evidence=f"PowerShell Get-MpComputerStatus error: {stderr or 'No output'}",
            status="error",
            severity="Error",
            remediation="Run PowerShell with Administrator privileges to access Defender management APIs.",
        )]
    parsed = parse_defender_status(stdout)
    return evaluate_defender_status(parsed, scan_id=scan_id)


def check_rdp_configuration(scan_id: Optional[int] = None) -> List[Finding]:
    """Inspect Windows Registry for RDP and Network Level Authentication flags."""
    if winreg is None:
        return [Finding(
            scan_id=scan_id,
            module="config",
            title="RDP Configuration Query Skipped",
            evidence="winreg module not available on this platform.",
            status="error",
            severity="Error",
            remediation="Audit must be performed on a Windows host.",
        )]

    f_deny_ts = None
    user_auth = None

    try:
        # Check if RDP is enabled
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Control\Terminal Server") as key:
            val, _ = winreg.QueryValueEx(key, "fDenyTSConnections")
            f_deny_ts = int(val)
    except Exception:
        f_deny_ts = None

    try:
        # Check if NLA is enforced
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
        ) as key:
            val, _ = winreg.QueryValueEx(key, "UserAuthentication")
            user_auth = int(val)
    except Exception:
        user_auth = None

    if f_deny_ts is None:
        return [Finding(
            scan_id=scan_id,
            module="config",
            title="RDP Configuration Registry Read Error",
            evidence="Unable to open Terminal Server registry keys. Privileges may be insufficient.",
            status="error",
            severity="Error",
            remediation="Run the audit with local Administrator privileges.",
        )]

    parsed = parse_rdp_registry(f_deny_ts, user_auth)
    return evaluate_rdp_exposure(parsed, scan_id=scan_id)


def check_smb_configuration(scan_id: Optional[int] = None) -> List[Finding]:
    """Query SMBv1 server protocol configuration via PowerShell."""
    ps_cmd = (
        "Get-SmbServerConfiguration | "
        "Select-Object -Property EnableSMB1Protocol,EnableSMB2Protocol | "
        "ConvertTo-Json"
    )
    success, stdout, stderr = run_command(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd])
    if not success or not stdout.strip():
        return [Finding(
            scan_id=scan_id,
            module="config",
            title="SMB Configuration Query Failed",
            evidence=f"PowerShell Get-SmbServerConfiguration error: {stderr or 'No output'}",
            status="error",
            severity="Error",
            remediation="Ensure PowerShell has access to the SmbShare module with elevated permissions.",
        )]
    parsed = parse_smb_config(stdout)
    return evaluate_smb_protocol(parsed, scan_id=scan_id)


def check_listening_ports(scan_id: Optional[int] = None) -> List[Finding]:
    """Enumerate listening network ports via psutil and flag high-risk ports."""
    try:
        connections = psutil.net_connections(kind="inet")
    except Exception as exc:
        return [Finding(
            scan_id=scan_id,
            module="config",
            title="Network Port Enumeration Failed",
            evidence=f"psutil.net_connections raised: {exc}",
            status="error",
            severity="Error",
            remediation="Ensure user running the process has administrative network inspection rights.",
        )]

    cfg = get_config()
    flagged = parse_listening_ports(connections, cfg.RISKY_PORTS)
    return evaluate_listening_ports(flagged, scan_id=scan_id)


def run_config_audit(scan_id: Optional[int] = None) -> List[Finding]:
    """
    Run all Windows configuration audit checks.

    Args:
        scan_id: Associated scan identifier.

    Returns:
        List[Finding]: Consolidated list of configuration audit findings.
    """
    # Imported here because extra_checks itself imports run_command from this module
    from collectors import extra_checks

    all_findings: List[Finding] = []

    checks = [
        ("Windows Updates & OS Support", extra_checks.check_windows_updates),
        ("BitLocker", extra_checks.check_bitlocker),
        ("System Hardening (UAC, Secure Boot, LSA)", extra_checks.check_system_hardening),
        ("Network Shares", extra_checks.check_network_shares),
        ("Startup Entries", extra_checks.check_startup_entries),
        ("Password Policy", check_password_policy),
        ("User Accounts", check_user_accounts),
        ("Firewall Profiles", check_firewall_status),
        ("Microsoft Defender", check_defender_status),
        ("RDP & NLA", check_rdp_configuration),
        ("SMB Protocol", check_smb_configuration),
        ("Listening Ports", check_listening_ports),
    ]

    for check_name, check_func in checks:
        try:
            results = check_func(scan_id=scan_id)
            all_findings.extend(results)
        except Exception as exc:
            all_findings.append(Finding(
                scan_id=scan_id,
                module="config",
                title=f"{check_name} Audit Crashed Safely",
                evidence=f"Unexpected error during {check_name} check: {exc}",
                status="error",
                likelihood=1,
                impact=1,
                risk_score=0,
                severity="Error",
                remediation="Check system logs and permissions.",
            ))

    return all_findings
