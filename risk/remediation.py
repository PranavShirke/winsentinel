"""
WinSentinel - Remediation Guidance & Action Plan Engine.

Provides prescriptive, actionable remediation instructions for security findings
discovered during configuration audits, log analysis, and vulnerability checks.
Each remediation entry includes:
  - Exact Windows CLI/PowerShell command (for Administrator execution).
  - Graphical User Interface (GUI) steps.
  - Security rationale and regulatory/industry benchmark mapping (CIS / NIST).
"""

from typing import Dict, Any, Optional
from db.models import Finding


REMEDIATION_CATALOG: Dict[str, Dict[str, Any]] = {
    # -------------------------------------------------------------------------
    # Password Policy
    # -------------------------------------------------------------------------
    "Weak Minimum Password Length Policy": {
        "summary": "Enforce a minimum password length of at least 12 characters.",
        "command": "net accounts /minpwlen:12",
        "gui_steps": "Local Security Policy -> Account Policies -> Password Policy -> Minimum password length -> Set to 12.",
        "rationale": "Short passwords are susceptible to offline brute-force and dictionary attacks (CIS Benchmark 1.1.4).",
        "reference": "CIS Microsoft Windows 11 Benchmark v3.0.0 (1.1.4); NIST SP 800-63B",
    },
    "Account Lockout Threshold Disabled": {
        "summary": "Enable account lockout threshold after 5 failed attempts.",
        "command": "net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15",
        "gui_steps": "Local Security Policy -> Account Policies -> Account Lockout Policy -> Account lockout threshold -> Set to 5 invalid logon attempts.",
        "rationale": "Without lockout thresholds, attackers can execute unlimited online password brute-force attacks.",
        "reference": "CIS Benchmark 1.2.1; NIST SP 800-53 AC-7 (Unsuccessful Logon Attempts)",
    },
    "Insufficient Password History Maintained": {
        "summary": "Enforce password history of at least 5 remembered passwords.",
        "command": "net accounts /uniquepw:5",
        "gui_steps": "Local Security Policy -> Account Policies -> Password Policy -> Enforce password history -> Set to 5 passwords remembered.",
        "rationale": "Prevents users from immediately cycling back to recently compromised or known passwords.",
        "reference": "CIS Benchmark 1.1.1",
    },

    # -------------------------------------------------------------------------
    # User Accounts & Privileges
    # -------------------------------------------------------------------------
    "Built-in Guest Account Is Active": {
        "summary": "Disable the built-in Guest user account immediately.",
        "command": "net user Guest /active:no",
        "gui_steps": "Computer Management (compmgmt.msc) -> Local Users and Groups -> Users -> Right-click Guest -> Properties -> Check 'Account is disabled'.",
        "rationale": "The Guest account allows anonymous or unauthenticated access to network shares and system resources.",
        "reference": "CIS Benchmark 2.3.1.1; NIST SP 800-53 AC-2 (Account Management)",
    },
    "Excessive Local Administrators Delegated": {
        "summary": "Audit and restrict membership of the local Administrators group.",
        "command": "net localgroup administrators",
        "gui_steps": "Computer Management -> Local Users and Groups -> Groups -> Administrators -> Remove non-essential user accounts.",
        "rationale": "Excessive administrative privileges violate the principle of least privilege and increase blast radius of compromised credentials.",
        "reference": "CIS Benchmark 2.2.1; Principle of Least Privilege",
    },

    # -------------------------------------------------------------------------
    # Windows Firewall
    # -------------------------------------------------------------------------
    "Windows Defender Firewall Disabled on One or More Profiles": {
        "summary": "Enable Windows Defender Firewall on Domain, Private, and Public profiles.",
        "command": "netsh advfirewall set allprofiles state on",
        "gui_steps": "Windows Security -> Firewall & network protection -> Turn on firewall for Domain, Private, and Public networks.",
        "rationale": "An inactive firewall exposes network services and open ports to unauthorized inbound traffic and lateral movement.",
        "reference": "CIS Benchmark 9.1.1, 9.2.1, 9.3.1; NIST SP 800-53 SC-7 (Boundary Protection)",
    },

    # -------------------------------------------------------------------------
    # Microsoft Defender
    # -------------------------------------------------------------------------
    "Microsoft Defender Real-Time Protection Disabled": {
        "summary": "Enable Microsoft Defender Real-Time Monitoring and Antivirus services.",
        "command": "powershell -Command \"Set-MpPreference -DisableRealtimeMonitoring $false\"",
        "gui_steps": "Windows Security -> Virus & threat protection -> Manage settings -> Turn ON Real-time protection.",
        "rationale": "Real-time protection monitors active processes and downloads for known malicious signatures and behavioral anomalies.",
        "reference": "CIS Benchmark 18.9.43.1; NIST SP 800-53 SI-3 (Malicious Code Protection)",
    },
    "Antivirus Signatures Outdated": {
        "summary": "Update Microsoft Defender threat intelligence signatures immediately.",
        "command": "powershell -Command \"Update-MpSignature\"",
        "gui_steps": "Windows Security -> Virus & threat protection -> Check for updates.",
        "rationale": "Outdated virus signatures cannot recognize zero-day or newly compiled malware variants in the wild.",
        "reference": "CIS Benchmark 18.9.43.3; NIST SP 800-53 SI-3(1)",
    },

    # -------------------------------------------------------------------------
    # Protocols & Services (SMB / RDP / Ports)
    # -------------------------------------------------------------------------
    "SMBv1 Legacy Protocol Is Enabled": {
        "summary": "Disable legacy SMBv1 protocol to prevent EternalBlue-style exploitation.",
        "command": "powershell -Command \"Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force\"",
        "gui_steps": "Turn Windows features on or off -> Uncheck 'SMB 1.0/CIFS File Sharing Support' -> Restart host.",
        "rationale": "SMBv1 lacks modern encryption, integrity verification, and contains critical remote code execution vulnerabilities (MS17-010).",
        "reference": "US-CERT Alert TA17-132A; Microsoft Security Advisory 2673356",
    },
    "RDP Enabled Without Network Level Authentication (NLA)": {
        "summary": "Enforce Network Level Authentication (NLA) for Remote Desktop connections.",
        "command": "powershell -Command \"Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 1\"",
        "gui_steps": "System Properties -> Remote -> Check 'Allow connections only from computers running Remote Desktop with Network Level Authentication'.",
        "rationale": "NLA requires client authentication before establishing an RDP session, mitigating unauthenticated RCE exploits like BlueKeep (CVE-2019-0708).",
        "reference": "CIS Benchmark 18.9.59.3.2; NIST SP 800-53 AC-17 (Remote Access)",
    },
}


def get_remediation_guide(finding: Finding) -> Dict[str, Any]:
    """
    Retrieve comprehensive remediation guidance for a specific finding.

    Args:
        finding: The Finding object requiring remediation.

    Returns:
        Dict[str, Any]: Prescriptive remediation details including CLI command and GUI steps.
    """
    # 1. Exact catalog match
    if finding.title in REMEDIATION_CATALOG:
        return REMEDIATION_CATALOG[finding.title]

    # 2. Port exposure findings
    if "Risky Listening Port" in finding.title:
        port_num = ""
        for token in finding.title.split():
            if token.isdigit():
                port_num = token
                break

        if port_num == "23":
            return {
                "summary": "Disable and remove the insecure Telnet Server feature.",
                "command": "powershell -Command \"Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient\"",
                "gui_steps": "Services (services.msc) -> Telnet -> Stop and set Startup type to Disabled.",
                "rationale": "Telnet transmits all credentials and terminal sessions in cleartext unencrypted packets.",
                "reference": "NIST SP 800-52; CIS Benchmark 5.1",
            }
        elif port_num == "445":
            return {
                "summary": "Restrict SMB port 445 on Windows Firewall to trusted subnets only.",
                "command": "powershell -Command \"New-NetFirewallRule -DisplayName 'Block Inbound SMB 445' -Direction Inbound -LocalPort 445 -Protocol TCP -Action Block\"",
                "gui_steps": "Windows Defender Firewall with Advanced Security -> Inbound Rules -> New Rule -> Port 445 -> Block the connection.",
                "rationale": "Exposing port 445 permits unauthorized lateral movement and file share reconnaissance.",
                "reference": "CIS Benchmark 9.1; US-CERT Alert TA17-132A",
            }
        elif port_num == "3389":
            return {
                "summary": "Restrict RDP access with firewall scope rules and require NLA.",
                "command": "powershell -Command \"Set-NetFirewallRule -DisplayGroup 'Remote Desktop' -RemoteAddress LocalSubnet\"",
                "gui_steps": "Windows Defender Firewall -> Inbound Rules -> Remote Desktop -> Scope -> Remote IP addresses.",
                "rationale": "Restricting RDP to internal or VPN subnets prevents brute-force login attacks from untrusted networks.",
                "reference": "NIST SP 800-53 AC-17",
            }
        else:
            return {
                "summary": f"Inspect process listening on port {port_num} and restrict network access.",
                "command": f"netstat -ano | findstr :{port_num}",
                "gui_steps": "Task Manager -> Details -> Locate PID from netstat -> End Task or adjust service startup.",
                "rationale": "Unnecessary open listening ports expand the host attack surface.",
                "reference": "CIS Benchmark 5.0; Principle of Least Exposure",
            }

    # 3. Log analysis findings (Brute Force / Compromise)
    if finding.module == "logs":
        if "Possible Account Compromise" in finding.title:
            return {
                "summary": "Immediately isolate the workstation and perform credential reset.",
                "command": "net user <TargetAccount> * /domain",
                "gui_steps": "Disconnect host network cable or disable NIC -> Reset user password in Active Directory or Local Users.",
                "rationale": "A successful logon immediately following repeated failed attempts indicates probable credential guessing success.",
                "reference": "NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide)",
            }
        elif "Brute-Force" in finding.title:
            return {
                "summary": "Enforce account lockout policies and block the offending source IP address.",
                "command": "net accounts /lockoutthreshold:5",
                "gui_steps": "Local Security Policy -> Account Policies -> Account Lockout Policy -> Set threshold to 5.",
                "rationale": "Throttles automated password guessing attacks and locks targeted accounts.",
                "reference": "NIST SP 800-53 AC-7",
            }
        elif "Privileged Group" in finding.title:
            return {
                "summary": "Audit local Administrators group membership and revert unauthorized additions.",
                "command": "net localgroup administrators",
                "gui_steps": "Computer Management -> Local Users and Groups -> Groups -> Administrators.",
                "rationale": "Unauthorized additions to privileged groups represent privilege escalation or adversary persistence.",
                "reference": "MITRE ATT&CK T1078 (Valid Accounts); T1098 (Account Manipulation)",
            }

    # 4. Software vulnerability (CVE) findings
    if finding.module == "software":
        return {
            "summary": "Update the affected software package to the latest security patch release.",
            "command": "winget upgrade --all",
            "gui_steps": "Open the vendor's official website or software updater utility to install latest security patches.",
            "rationale": "Unpatched third-party software contains known vulnerabilities documented in the NVD with public exploit code.",
            "reference": "NIST SP 800-40 (Guide to Enterprise Patch Management Planning)",
        }

    # 5. Default generic guidance
    return {
        "summary": finding.remediation or "Review configuration against hardening guidelines.",
        "command": "N/A (Review specific finding details)",
        "gui_steps": "Consult Windows Security or Computer Management console.",
        "rationale": "Maintains defense-in-depth posture.",
        "reference": "CIS Microsoft Windows Benchmark",
    }
