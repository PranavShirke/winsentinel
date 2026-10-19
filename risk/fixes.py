"""
WinSentinel - Remediation command suggestions.

Maps a finding to the exact PowerShell / cmd commands that fix it, so an analyst can copy and run
them deliberately. WinSentinel itself NEVER executes these: the tool stays read-only. Commands that
need values from your system use <placeholders> that you must replace.
"""

import re
from typing import Dict, List, Optional

# (title regex, commands, note)
_RULES = [
    (r"minimum password length",
     ["net accounts /minpwlen:12"], "Requires an elevated prompt. Existing passwords are not changed."),
    (r"lockout threshold",
     ["net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15"], "Locks an account for 15 minutes after 5 bad passwords."),
    (r"password history",
     ["net accounts /uniquepw:24"], "Remembers the last 24 passwords."),
    (r"guest account is active",
     ["net user Guest /active:no"], ""),
    (r"excessive local administrators",
     ["Get-LocalGroupMember -Group Administrators",
      "Remove-LocalGroupMember -Group Administrators -Member \"<account>\""],
     "Review the list first; keep at least one administrator you control."),
    (r"firewall disabled",
     ["Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True"], ""),
    (r"real-time protection disabled",
     ["Set-MpPreference -DisableRealtimeMonitoring $false"], "If it reverts, another security product or policy may be turning it off."),
    (r"signatures (outdated|moderately)",
     ["Update-MpSignature"], ""),
    (r"rdp enabled without",
     ["Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1"],
     "Enforces Network Level Authentication. To turn RDP off entirely set fDenyTSConnections to 1 under 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server'."),
    (r"smbv1",
     ["Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"], ""),
    (r"smb signing is not required",
     ["Set-SmbServerConfiguration -RequireSecuritySignature $true -Force"], "Very old SMB clients that cannot sign will stop connecting."),
    (r"windows updates are (outdated|aging)|no windows update history",
     ["Start-Process ms-settings:windowsupdate"], "Opens Windows Update; click Check for updates."),
    (r"reboot pending",
     ["Restart-Computer"], "Save your work first. This restarts the PC immediately."),
    (r"past end of support",
     ["Start-Process ms-settings:windowsupdate"], "Upgrade to Windows 11 or enrol in Extended Security Updates; no single command fixes this."),
    (r"bitlocker off|not encrypted",
     ["Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod XtsAes256 -UsedSpaceOnly -RecoveryPasswordProtector"],
     "Back up the recovery key it prints (Microsoft account, USB or printout) before rebooting."),
    (r"uac\) is disabled",
     ["Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1"], "Restart required."),
    (r"uac elevates administrators without prompting",
     ["Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name ConsentPromptBehaviorAdmin -Value 5"], ""),
    (r"uac prompts not shown on secure desktop",
     ["Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name PromptOnSecureDesktop -Value 1"], ""),
    (r"secure boot",
     [], "This is a firmware setting: restart into UEFI/BIOS setup and enable Secure Boot (the disk must be GPT; mbr2gpt can convert it)."),
    (r"lsa protection",
     ["Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL -Value 1 -Type DWord"],
     "Restart required. A few old security drivers are incompatible; test first."),
    (r"wdigest",
     ["Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name UseLogonCredential -Value 0 -Type DWord"], ""),
    (r"auto-logon",
     ["Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name AutoAdminLogon -Value 0",
      "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name DefaultPassword -ErrorAction SilentlyContinue"], ""),
    (r"custom network share",
     ["Get-SmbShare | Where-Object { -not $_.Special }", "Remove-SmbShare -Name \"<ShareName>\" -Force"], "Run the first line to list shares, then remove the ones you do not need."),
    (r"startup entr",
     ["Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location | Format-Table -Wrap",
      "Remove-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -Name \"<EntryName>\""],
     "Only remove entries you are sure are not yours. Task Manager > Startup apps is a safer way to disable one."),
    (r"defender exclusions cover|defender has exclusions",
     ["Get-MpPreference | Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess",
      "Remove-MpPreference -ExclusionPath \"<path>\""], "Remove ExclusionExtension / ExclusionProcess the same way."),
    (r"execution policy allows",
     ["Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force"], ""),
    (r"script block logging is not enabled",
     ["New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Force | Out-Null",
      "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1 -Type DWord"], "Logs appear as Event 4104 in Microsoft-Windows-PowerShell/Operational."),
    (r"llmnr name resolution is enabled",
     ["New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Force | Out-Null",
      "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast -Value 0 -Type DWord"], ""),
    (r"netbios over tcp/ip is enabled",
     ["Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true' | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = 2 }"],
     "Disables NetBIOS on every active adapter. Very old file-sharing setups may rely on it."),
    (r"accounts without a required password",
     ["net user <name> /passwordreq:yes", "net user <name> *"], "The second command prompts for a new password."),
    (r"passwords that never expire",
     ["Set-LocalUser -Name \"<name>\" -PasswordNeverExpires $false"], "Alternatively keep it and protect the account with a long unique password or a passkey."),
    (r"winrm service is running",
     ["Stop-Service WinRM", "Set-Service WinRM -StartupType Disabled", "Disable-PSRemoting -Force"], "Skip this if you manage this PC remotely."),
    (r"brute-force logon",
     ["Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 50 | Select-Object TimeCreated, Message | Format-List",
      "New-NetFirewallRule -DisplayName \"Block <ip>\" -Direction Inbound -RemoteAddress <ip> -Action Block"],
     "The first command shows the failed logons; the second blocks the source address."),
    (r"possible account compromise",
     ["net user <account> *", "query user", "Get-LocalGroupMember -Group Administrators"],
     "Change the password, check active sessions and review who is an administrator. Consider disconnecting the PC from the network."),
    (r"privileged group membership",
     ["Get-LocalGroupMember -Group Administrators", "Remove-LocalGroupMember -Group Administrators -Member \"<account>\""], "Remove the member only if the change was not authorised."),
    (r"security event notice",
     ["Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet"], "Check that the account is expected."),
]

_COMPILED = [(re.compile(p, re.IGNORECASE), cmds, note) for p, cmds, note in _RULES]
_SAFE_NAME = re.compile(r"[^A-Za-z0-9 .+\-()]")


def get_fix(title: str) -> Optional[Dict[str, object]]:
    """
    Return suggested commands for a finding title, or None if no fix command applies.

    Args:
        title: Finding title.

    Returns:
        Dict with 'commands' (list of str, may be empty), 'note' (str) and 'text' (commands joined by newlines).
    """
    port = re.search(r"risky listening port (\d+)", title, re.IGNORECASE)
    if port:
        number = int(port.group(1))
        cmd = (f'New-NetFirewallRule -DisplayName "Block inbound TCP {number} (WinSentinel suggestion)" '
               f"-Direction Inbound -Protocol TCP -LocalPort {number} -Action Block")
        return {"commands": [cmd], "text": cmd,
                "note": "Blocks it from the network. Make sure you do not rely on file sharing or remote management first; "
                        "this does not remove the service itself."}

    cve = re.match(r"vulnerability detected:\s*(.+?)\s*\((?:CVE|[^()]*CVE)", title, re.IGNORECASE)
    if cve:
        name = re.sub(r"\s*\((?:x64|x86|64-bit|32-bit)\)", "", cve.group(1), flags=re.IGNORECASE)
        name = re.sub(r"\s+v?\d+(?:\.\d+)+\s*$", "", name)  # trailing version number
        name = _SAFE_NAME.sub("", name).strip()
        if name:
            cmd = f'winget upgrade --name "{name}"'
            return {"commands": [cmd], "text": cmd,
                    "note": "Updates the app to the latest version. If winget cannot find it, download the latest release from the vendor."}

    for pattern, commands, note in _COMPILED:
        if pattern.search(title):
            return {"commands": commands, "text": "\n".join(commands), "note": note}
    return None
