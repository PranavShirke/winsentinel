"""
WinSentinel - Additional Windows Hardening Checks.

Read-only checks that complement collectors/config_audit.py:
  - Windows Update recency and pending reboot
  - Operating system support status (end-of-support builds)
  - BitLocker system-drive encryption
  - User Account Control (UAC) level
  - Secure Boot
  - Credential theft protections: LSA protection (RunAsPPL), WDigest, Winlogon auto-logon
  - Non-default network shares
  - Startup / persistence entries (Run keys) launching from user-writable folders

Each check has a pure evaluator function (testable without Windows) and a thin collector that
reads the registry or runs a fixed PowerShell command. Every collector degrades to an 'error'
finding instead of raising.
"""

import json
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    import winreg
except ImportError:  # non-Windows (unit tests of the pure evaluators still work)
    winreg = None

from collectors.config_audit import run_command
from db.models import Finding
from risk.scoring import calculate_risk_score, get_severity_band


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _finding(
    scan_id: Optional[int],
    title: str,
    status: str,
    evidence: str,
    remediation: str = "No remediation needed.",
    likelihood: int = 1,
    impact: int = 1,
) -> Finding:
    """Build a config-module Finding with NIST SP 800-30 scoring applied consistently."""
    if status == "fail":
        risk = calculate_risk_score(likelihood, impact)
    else:
        risk = 0
    return Finding(
        scan_id=scan_id,
        module="config",
        title=title,
        evidence=evidence,
        status=status,
        likelihood=likelihood,
        impact=impact,
        risk_score=risk,
        severity=get_severity_band(risk, status),
        remediation=remediation,
    )


def _error(scan_id: Optional[int], title: str, detail: str, remediation: str) -> Finding:
    """Standard 'could not check' finding."""
    return _finding(scan_id, title, "error", detail, remediation)


def read_registry_value(hive: Any, path: str, name: str) -> Optional[Any]:
    """
    Read one registry value.

    Args:
        hive: winreg hive constant (e.g. winreg.HKEY_LOCAL_MACHINE).
        path: Key path below the hive.
        name: Value name.

    Returns:
        The value, or None if winreg is unavailable, the key/value is missing or access is denied.
    """
    if winreg is None:
        return None
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
            return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None


def registry_key_exists(hive: Any, path: str) -> bool:
    """Return True if a registry key exists and can be opened."""
    if winreg is None:
        return False
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ):
            return True
    except OSError:
        return False


def _ps_json(script: str, timeout: int = 40) -> Tuple[bool, Any, str]:
    """
    Run a fixed PowerShell script that ends in ConvertTo-Json and parse its output.

    Returns:
        (success, parsed_json_or_None, error_text). An empty output parses to an empty list.
    """
    ok, out, err = run_command(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout=timeout)
    if not ok:
        return False, None, (err.strip() or "PowerShell command failed")
    if not out.strip():
        return True, [], ""
    try:
        data = json.loads(out)
    except ValueError as exc:
        return False, None, f"Invalid JSON from PowerShell: {exc}"
    if isinstance(data, dict):
        data = [data]
    return True, data, ""


# ---------------------------------------------------------------------------
# Windows Update and OS support
# ---------------------------------------------------------------------------
def evaluate_update_recency(
    hotfix_id: Optional[str],
    installed_on: Optional[str],
    scan_id: Optional[int] = None,
    now: Optional[datetime] = None,
) -> Finding:
    """
    Judge how recently Windows patches were installed.

    Thresholds: <= 45 days pass; 46-90 days Medium; > 90 days High.

    Args:
        hotfix_id: KB id of the newest installed update (None if none found).
        installed_on: ISO timestamp of its install date.
        scan_id: Associated scan.
        now: Override for the current time (tests).
    """
    if not hotfix_id or not installed_on:
        return _finding(
            scan_id, "No Windows Update History Found", "fail",
            "Get-HotFix returned no installed updates with an install date.",
            "Open Settings > Windows Update and install all available updates.", 3, 4,
        )
    try:
        when = datetime.fromisoformat(installed_on)
    except ValueError:
        return _error(scan_id, "Windows Update Date Unreadable", f"Could not parse install date '{installed_on}'.",
                      "Check Settings > Windows Update > Update history manually.")
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    age = ((now or datetime.now(timezone.utc)) - when).days
    evidence = f"Newest installed update {hotfix_id} was installed {age} day(s) ago ({when.date()})."
    if age <= 45:
        return _finding(scan_id, "Windows Updates Are Recent", "pass", evidence)
    if age <= 90:
        return _finding(scan_id, "Windows Updates Are Aging", "fail", evidence,
                        "Install pending updates: Settings > Windows Update > Check for updates.", 3, 3)
    return _finding(scan_id, "Windows Updates Are Outdated", "fail", evidence,
                    "Install pending updates immediately; unpatched Windows is a leading cause of compromise.", 3, 4)


def evaluate_pending_reboot(pending: bool, scan_id: Optional[int] = None) -> Finding:
    """Flag a pending reboot, which means installed security updates are not yet active."""
    if pending:
        return _finding(scan_id, "Reboot Pending to Complete Updates", "fail",
                        "Registry shows RebootRequired / RebootPending: installed updates are not fully applied.",
                        "Restart the computer to finish applying updates.", 2, 3)
    return _finding(scan_id, "No Reboot Pending", "pass", "No pending-reboot flags found in the registry.")


def evaluate_os_support(build: int, scan_id: Optional[int] = None) -> Finding:
    """
    Check the OS family. Windows 10 (build < 22000) left mainstream support on 2025-10-14.

    Args:
        build: Windows build number (e.g. 26300).
    """
    if 0 < build < 22000:
        return _finding(
            scan_id, "Windows 10 Is Past End of Support", "fail",
            f"Windows build {build} is Windows 10. Mainstream security updates ended on 2025-10-14 "
            f"(only Extended Security Updates continue).",
            "Upgrade to Windows 11 or enrol the device in Extended Security Updates.", 4, 4,
        )
    return _finding(scan_id, "Supported Windows Version", "pass", f"Windows build {build} is within support.")


def check_windows_updates(scan_id: Optional[int] = None) -> List[Finding]:
    """Collect hotfix recency, pending-reboot state and OS support status."""
    findings: List[Finding] = []
    ok, data, err = _ps_json(
        "Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | "
        "Select-Object -First 1 HotFixID, @{n='InstalledOn';e={$_.InstalledOn.ToString('o')}} | ConvertTo-Json -Compress"
    )
    if not ok:
        findings.append(_error(scan_id, "Windows Update Query Failed", err, "Run in an elevated terminal and retry."))
    else:
        top = data[0] if data else {}
        findings.append(evaluate_update_recency(top.get("HotFixID"), top.get("InstalledOn"), scan_id))

    if winreg is not None:
        pending = registry_key_exists(
            winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
        ) or registry_key_exists(
            winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
        )
        findings.append(evaluate_pending_reboot(pending, scan_id))
    if sys.platform == "win32":
        findings.append(evaluate_os_support(sys.getwindowsversion().build, scan_id))
    return findings


# ---------------------------------------------------------------------------
# BitLocker
# ---------------------------------------------------------------------------
def evaluate_bitlocker(protection_status: Optional[int], scan_id: Optional[int] = None) -> Finding:
    """
    Evaluate BitLocker on the system drive.

    Args:
        protection_status: Get-BitLockerVolume ProtectionStatus: 1 = On, 0 = Off, None = unknown.
    """
    if protection_status == 1:
        return _finding(scan_id, "BitLocker Protects the System Drive", "pass", "ProtectionStatus: On.")
    if protection_status == 0:
        return _finding(
            scan_id, "System Drive Is Not Encrypted (BitLocker Off)", "fail",
            "Get-BitLockerVolume: ProtectionStatus is Off for the system drive.",
            "Enable BitLocker (Settings > Privacy & security > Device encryption) and back up the recovery key.", 3, 4,
        )
    return _error(scan_id, "BitLocker Status Unknown", "Protection status could not be determined.",
                  "Run WinSentinel as Administrator to read BitLocker state.")


def check_bitlocker(scan_id: Optional[int] = None) -> List[Finding]:
    """Query BitLocker protection of the system drive (needs Administrator)."""
    ok, data, err = _ps_json(
        "Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop | "
        "Select-Object @{n='Protection';e={[int]$_.ProtectionStatus}} | ConvertTo-Json -Compress"
    )
    if not ok:
        return [_error(scan_id, "BitLocker Status Query Failed", err.splitlines()[0] if err else "Access denied",
                       "Run WinSentinel as Administrator to read BitLocker state.")]
    return [evaluate_bitlocker(data[0].get("Protection") if data else None, scan_id)]


# ---------------------------------------------------------------------------
# UAC, Secure Boot, credential protections
# ---------------------------------------------------------------------------
def evaluate_uac(enable_lua: Optional[int], consent_admin: Optional[int], secure_desktop: Optional[int],
                 scan_id: Optional[int] = None) -> List[Finding]:
    """
    Evaluate User Account Control settings.

    Args:
        enable_lua: EnableLUA (1 = UAC on).
        consent_admin: ConsentPromptBehaviorAdmin (0 = elevate silently, 5 = default prompt).
        secure_desktop: PromptOnSecureDesktop (1 = prompts isolated on secure desktop).
    """
    if enable_lua is None:
        return [_error(scan_id, "UAC Status Unknown", "EnableLUA registry value could not be read.",
                       "Verify UAC in Control Panel > User Accounts > Change User Account Control settings.")]
    if enable_lua == 0:
        return [_finding(scan_id, "User Account Control (UAC) Is Disabled", "fail",
                         "EnableLUA = 0: every program runs with full administrator rights without a prompt.",
                         "Enable UAC and restart: set EnableLUA to 1 or use the UAC settings slider.", 4, 4)]
    if consent_admin == 0:
        return [_finding(scan_id, "UAC Elevates Administrators Without Prompting", "fail",
                         "ConsentPromptBehaviorAdmin = 0 (Elevate without prompting).",
                         "Set UAC to at least 'Notify me only when apps try to make changes' (value 5).", 3, 4)]
    notes = f"EnableLUA=1, ConsentPromptBehaviorAdmin={consent_admin}, PromptOnSecureDesktop={secure_desktop}."
    if secure_desktop == 0:
        return [_finding(scan_id, "UAC Prompts Not Shown on Secure Desktop", "fail", notes,
                         "Enable 'User Account Control: Switch to the secure desktop when prompting for elevation'.", 2, 3)]
    return [_finding(scan_id, "User Account Control (UAC) Is Enforced", "pass", notes)]


def evaluate_secure_boot(value: Optional[int], scan_id: Optional[int] = None) -> Finding:
    """
    Evaluate UEFI Secure Boot.

    Args:
        value: UEFISecureBootEnabled (1 on, 0 off, None = key missing, i.e. legacy BIOS).
    """
    if value == 1:
        return _finding(scan_id, "Secure Boot Is Enabled", "pass", "UEFISecureBootEnabled = 1.")
    if value == 0:
        return _finding(
            scan_id, "Secure Boot Is Disabled", "fail",
            "UEFISecureBootEnabled = 0: the firmware does not verify the boot chain, allowing bootkits.",
            "Enable Secure Boot in UEFI/BIOS settings (the disk must use GPT).", 2, 4,
        )
    return _finding(scan_id, "Secure Boot Unsupported (Legacy BIOS)", "fail",
                    "SecureBoot registry state is absent: the system appears to boot in legacy BIOS mode.",
                    "Convert to UEFI/GPT (mbr2gpt) and enable Secure Boot.", 2, 3)


def evaluate_lsa_protection(run_as_ppl: Optional[int], scan_id: Optional[int] = None) -> Finding:
    """Evaluate LSA protection (RunAsPPL), which blocks credential dumping from lsass.exe."""
    if run_as_ppl in (1, 2):
        return _finding(scan_id, "LSA Protection (RunAsPPL) Is Enabled", "pass", f"RunAsPPL = {run_as_ppl}.")
    return _finding(
        scan_id, "LSA Protection (RunAsPPL) Is Not Enabled", "fail",
        f"RunAsPPL is {'unset' if run_as_ppl is None else run_as_ppl}: lsass.exe is not a protected process, so tools "
        f"like Mimikatz can read credentials from its memory.",
        "Enable 'Configure LSASS to run as a protected process' (set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL = 1) and reboot.",
        2, 4,
    )


def evaluate_wdigest(use_logon_credential: Optional[int], scan_id: Optional[int] = None) -> Finding:
    """Evaluate WDigest: UseLogonCredential = 1 keeps plaintext passwords in memory."""
    if use_logon_credential == 1:
        return _finding(
            scan_id, "WDigest Stores Plaintext Credentials in Memory", "fail",
            "UseLogonCredential = 1: logon passwords are cached in clear text in LSASS memory.",
            "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential to 0.", 3, 5,
        )
    return _finding(scan_id, "WDigest Plaintext Caching Is Disabled", "pass",
                    f"UseLogonCredential = {'unset (default off)' if use_logon_credential is None else use_logon_credential}.")


def evaluate_autologon(auto_admin_logon: Any, default_password_present: bool, scan_id: Optional[int] = None) -> Finding:
    """Evaluate Winlogon auto-logon; a stored DefaultPassword is a plaintext credential in the registry."""
    enabled = str(auto_admin_logon) == "1"
    if enabled and default_password_present:
        return _finding(scan_id, "Auto-Logon Password Stored in Registry", "fail",
                        "AutoAdminLogon = 1 and Winlogon DefaultPassword holds a plaintext password.",
                        "Disable auto-logon (AutoAdminLogon = 0) and delete the DefaultPassword value.", 4, 5)
    if enabled:
        return _finding(scan_id, "Windows Auto-Logon Is Enabled", "fail",
                        "AutoAdminLogon = 1: the machine signs in without a password at boot.",
                        "Disable auto-logon (netplwiz or set AutoAdminLogon = 0).", 3, 3)
    return _finding(scan_id, "Windows Auto-Logon Is Disabled", "pass", "AutoAdminLogon is not enabled.")


def check_system_hardening(scan_id: Optional[int] = None) -> List[Finding]:
    """Read UAC, Secure Boot, LSA protection, WDigest and auto-logon settings from the registry."""
    if winreg is None:
        return [_error(scan_id, "Registry Hardening Checks Skipped", "winreg is unavailable on this platform.",
                       "Run WinSentinel on Windows.")]
    hklm = winreg.HKEY_LOCAL_MACHINE
    system_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    winlogon = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    findings: List[Finding] = []
    findings += evaluate_uac(
        read_registry_value(hklm, system_key, "EnableLUA"),
        read_registry_value(hklm, system_key, "ConsentPromptBehaviorAdmin"),
        read_registry_value(hklm, system_key, "PromptOnSecureDesktop"),
        scan_id,
    )
    findings.append(evaluate_secure_boot(
        read_registry_value(hklm, r"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled"), scan_id))
    findings.append(evaluate_lsa_protection(
        read_registry_value(hklm, r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL"), scan_id))
    findings.append(evaluate_wdigest(
        read_registry_value(hklm, r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential"), scan_id))
    findings.append(evaluate_autologon(
        read_registry_value(hklm, winlogon, "AutoAdminLogon"),
        read_registry_value(hklm, winlogon, "DefaultPassword") not in (None, ""),
        scan_id,
    ))
    return findings


# ---------------------------------------------------------------------------
# Network shares
# ---------------------------------------------------------------------------
def evaluate_shares(shares: List[Dict[str, Any]], scan_id: Optional[int] = None) -> Finding:
    """
    Flag non-default SMB shares (administrative shares such as C$ and IPC$ are ignored).

    Args:
        shares: Dicts with Name, Path and Special keys from Get-SmbShare.
    """
    custom = [s for s in shares if not s.get("Special") and not str(s.get("Name", "")).endswith("$")]
    if not custom:
        return _finding(scan_id, "No Custom Network Shares Exposed", "pass",
                        f"Only default administrative shares exist ({len(shares)} total).")
    listing = "; ".join(f"{s.get('Name')} -> {s.get('Path') or '?'}" for s in custom)
    return _finding(
        scan_id, f"{len(custom)} Custom Network Share(s) Exposed", "fail",
        f"Non-default SMB shares: {listing}.",
        "Remove shares you do not need (Remove-SmbShare) and restrict share and NTFS permissions to specific accounts.", 3, 3,
    )


def check_network_shares(scan_id: Optional[int] = None) -> List[Finding]:
    """Enumerate SMB shares of this machine."""
    ok, data, err = _ps_json("Get-SmbShare | Select-Object Name, Path, Special | ConvertTo-Json -Compress")
    if not ok:
        return [_error(scan_id, "Network Share Query Failed", err, "Run as Administrator and retry.")]
    return [evaluate_shares(data, scan_id)]


# ---------------------------------------------------------------------------
# Startup / persistence entries
# ---------------------------------------------------------------------------
RISKY_STARTUP_PATH = re.compile(r"\\(appdata|temp|downloads|users\\public|programdata)\\", re.IGNORECASE)


def evaluate_startup_entries(entries: List[Dict[str, str]], scan_id: Optional[int] = None) -> Finding:
    """
    Review autorun registry entries and flag ones launching from user-writable folders.

    Malware commonly persists via Run keys pointing into AppData, Temp or Downloads; legitimate
    per-user apps (Teams, OneDrive) also live under AppData, so this is a review prompt, not proof.

    Args:
        entries: Dicts with name, command and location keys.
    """
    risky = [e for e in entries if RISKY_STARTUP_PATH.search(e.get("command", ""))]
    if not risky:
        return _finding(scan_id, "Startup Entries Look Normal", "pass",
                        f"{len(entries)} autorun entries reviewed; none launch from user-writable folders.")
    listing = "; ".join(f"[{e['location']}] {e['name']}: {e['command'][:120]}" for e in risky[:8])
    return _finding(
        scan_id, f"{len(risky)} Startup Entr{'y' if len(risky) == 1 else 'ies'} Run From User-Writable Folders", "fail",
        f"{len(entries)} autorun entries reviewed. Review these: {listing}",
        "Verify each program is one you installed. Remove unknown entries (Task Manager > Startup apps or delete the Run key value).", 2, 3,
    )


def check_startup_entries(scan_id: Optional[int] = None) -> List[Finding]:
    """Read the Run and RunOnce registry keys (machine and current user)."""
    if winreg is None:
        return []
    locations = [
        ("HKLM Run", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM RunOnce", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKCU Run", winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ("HKCU RunOnce", winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    entries: List[Dict[str, str]] = []
    for label, hive, path in locations:
        try:
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
                index = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    entries.append({"name": name, "command": str(value), "location": label})
                    index += 1
        except OSError:
            continue
    return [evaluate_startup_entries(entries, scan_id)]
