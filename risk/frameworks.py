"""
WinSentinel - Security Framework Mapping (MITRE ATT&CK and CIS Controls v8).

Tags each finding or alert with the attacker technique it relates to (MITRE ATT&CK for
Enterprise) and the defensive control group it supports (CIS Critical Security Controls v8),
so results speak the language of SOC and GRC teams.

Mappings are rule-based on the finding title and are guidance for triage, not a formal
benchmark assessment. Control numbers refer to CIS Controls v8 safeguards.
"""

import re
from typing import Dict, List, Optional, Tuple

Tag = Tuple[str, str]  # (id, name)

# (title regex, CIS safeguards, ATT&CK techniques). First matching rules are all applied.
_RULES: List[Tuple[str, List[Tag], List[Tag]]] = [
    (r"password length|password history|lockout threshold",
     [("5.2", "Use Unique Passwords"), ("4.1", "Secure Configuration Process")],
     [("T1110", "Brute Force")]),
    (r"guest account|administrators",
     [("5.1", "Inventory of Accounts"), ("5.4", "Restrict Administrator Privileges")],
     [("T1078.003", "Valid Accounts: Local Accounts")]),
    (r"firewall",
     [("4.5", "Firewall on End-User Devices")],
     [("T1562.004", "Impair Defenses: Disable or Modify System Firewall")]),
    (r"defender|antivirus|signatures",
     [("10.1", "Deploy Anti-Malware Software"), ("10.2", "Automatic Anti-Malware Signature Updates")],
     [("T1562.001", "Impair Defenses: Disable or Modify Tools")]),
    (r"rdp|remote desktop",
     [("4.8", "Disable Unnecessary Services"), ("12.2", "Secure Network Architecture")],
     [("T1021.001", "Remote Services: Remote Desktop Protocol")]),
    (r"smbv1|listening port|netbios|smb\)",
     [("4.8", "Uninstall or Disable Unnecessary Services")],
     [("T1210", "Exploitation of Remote Services"), ("T1021.002", "Remote Services: SMB/Windows Admin Shares")]),
    (r"network share",
     [("3.3", "Configure Data Access Control Lists")],
     [("T1021.002", "Remote Services: SMB/Windows Admin Shares")]),
    (r"windows update|reboot pending|end of support|supported windows",
     [("7.3", "Automated Operating System Patch Management")],
     [("T1190", "Exploit Public-Facing Application")]),
    (r"bitlocker|drive is not encrypted",
     [("3.6", "Encrypt Data on End-User Devices")],
     [("T1006", "Direct Volume Access")]),
    (r"uac|user account control",
     [("4.1", "Secure Configuration Process"), ("5.4", "Restrict Administrator Privileges")],
     [("T1548.002", "Abuse Elevation Control: Bypass UAC")]),
    (r"secure boot",
     [("4.1", "Secure Configuration Process")],
     [("T1542.003", "Pre-OS Boot: Bootkit")]),
    (r"lsa protection|wdigest",
     [("4.1", "Secure Configuration Process")],
     [("T1003.001", "OS Credential Dumping: LSASS Memory")]),
    (r"auto-logon",
     [("5.2", "Use Unique Passwords"), ("3.11", "Encrypt Sensitive Data at Rest")],
     [("T1552.002", "Unsecured Credentials: Credentials in Registry")]),
    (r"startup entr",
     [("2.3", "Address Unauthorized Software")],
     [("T1547.001", "Persistence: Registry Run Keys / Startup Folder")]),
    (r"vulnerability detected|cve",
     [("7.1", "Vulnerability Management Process"), ("7.4", "Automated Application Patch Management")],
     [("T1203", "Exploitation for Client Execution"), ("T1190", "Exploit Public-Facing Application")]),
    (r"possible account compromise",
     [("8.2", "Collect Audit Logs"), ("13.1", "Centralize Security Event Alerting")],
     [("T1078", "Valid Accounts"), ("T1110", "Brute Force")]),
    (r"brute-force|brute force|lockout \(|account lockout",
     [("8.2", "Collect Audit Logs"), ("13.1", "Centralize Security Event Alerting")],
     [("T1110", "Brute Force")]),
    (r"account created",
     [("5.1", "Inventory of Accounts"), ("8.2", "Collect Audit Logs")],
     [("T1136.001", "Create Account: Local Account")]),
    (r"privileged group",
     [("5.4", "Restrict Administrator Privileges"), ("8.2", "Collect Audit Logs")],
     [("T1098", "Account Manipulation")]),
    (r"security log|event log",
     [("8.2", "Collect Audit Logs")],
     []),
]

_COMPILED = [(re.compile(pat, re.IGNORECASE), cis, attack) for pat, cis, attack in _RULES]


def map_frameworks(title: str, extra: Optional[str] = None) -> Dict[str, List[Dict[str, str]]]:
    """
    Return the ATT&CK techniques and CIS safeguards related to a finding or alert.

    Args:
        title: Finding title or alert type.
        extra: Optional extra text (for example the alert type) to match against as well.

    Returns:
        Dict with 'attack' and 'cis' lists of {"id", "name"} dicts (duplicates removed).
    """
    text = f"{title} {extra or ''}"
    attack: Dict[str, str] = {}
    cis: Dict[str, str] = {}
    for pattern, cis_tags, attack_tags in _COMPILED:
        if pattern.search(text):
            for tid, name in attack_tags:
                attack.setdefault(tid, name)
            for cid, name in cis_tags:
                cis.setdefault(cid, name)
    return {
        "attack": [{"id": k, "name": v} for k, v in attack.items()],
        "cis": [{"id": k, "name": v} for k, v in cis.items()],
    }
