"""
WinSentinel - Windows Installed Software Inventory Collector.

This module inspects the Windows Registry Uninstall keys to enumerate
installed 64-bit and 32-bit software packages:
  - HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall
  - HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall
  - HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall

Filters out system components and sub-installers, extracting application names,
versions, and publishers, and filters against the approved CVE allowlist.
"""

import sys
import re
from typing import List, Dict, Any, Optional, Tuple, Set

try:
    import winreg
except ImportError:
    winreg = None

from config import get_config
from db.models import SoftwareItem


REGISTRY_LOCATIONS = [
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall") if winreg else (None, ""),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall") if winreg else (None, ""),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall") if winreg else (None, ""),
]


def clean_version_string(ver_str: str) -> str:
    """
    Clean and normalize software version strings.

    Args:
        ver_str: Raw version string from registry.

    Returns:
        str: Cleaned version string or 'Unknown'.
    """
    if not ver_str or not isinstance(ver_str, str):
        return "Unknown"
    cleaned = ver_str.strip()
    return cleaned if cleaned else "Unknown"


def is_system_component(key_handle: Any) -> bool:
    """
    Check if a registry subkey is marked as a Windows internal component.

    Args:
        key_handle: Open winreg key handle.

    Returns:
        bool: True if key is a system component or sub-installer.
    """
    if winreg is None:
        return False

    try:
        val, _ = winreg.QueryValueEx(key_handle, "SystemComponent")
        if val == 1:
            return True
    except Exception:
        pass

    try:
        val, _ = winreg.QueryValueEx(key_handle, "ParentKeyName")
        if val:
            return True
    except Exception:
        pass

    return False


def enumerate_registry_keys(
    root_key: Any,
    sub_path: str,
    scan_id: Optional[int] = None,
) -> List[SoftwareItem]:
    """
    Safely enumerate software entries under a specific registry path.

    Args:
        root_key: HKEY_LOCAL_MACHINE or HKEY_CURRENT_USER.
        sub_path: Path string to the Uninstall key.
        scan_id: Associated scan ID.

    Returns:
        List[SoftwareItem]: Discovered software packages.
    """
    items: List[SoftwareItem] = []
    if winreg is None or root_key is None or not sub_path:
        return items

    try:
        with winreg.OpenKey(root_key, sub_path, 0, winreg.KEY_READ) as parent_key:
            num_subkeys = winreg.QueryInfoKey(parent_key)[0]

            for i in range(num_subkeys):
                try:
                    subkey_name = winreg.EnumKey(parent_key, i)
                    with winreg.OpenKey(parent_key, subkey_name, 0, winreg.KEY_READ) as subkey:
                        if is_system_component(subkey):
                            continue

                        display_name = ""
                        try:
                            val, _ = winreg.QueryValueEx(subkey, "DisplayName")
                            display_name = str(val).strip()
                        except Exception:
                            continue

                        if not display_name:
                            continue

                        display_version = "Unknown"
                        try:
                            val, _ = winreg.QueryValueEx(subkey, "DisplayVersion")
                            display_version = clean_version_string(str(val))
                        except Exception:
                            pass

                        publisher = "Unknown"
                        try:
                            val, _ = winreg.QueryValueEx(subkey, "Publisher")
                            publisher = str(val).strip() or "Unknown"
                        except Exception:
                            pass

                        items.append(SoftwareItem(
                            scan_id=scan_id,
                            name=display_name,
                            version=display_version,
                            publisher=publisher,
                        ))
                except Exception:
                    continue
    except Exception:
        pass

    return items


def get_installed_software(scan_id: Optional[int] = None) -> List[SoftwareItem]:
    """
    Enumerate installed applications across all standard Windows Registry Uninstall locations.

    Deduplicates entries by (name, version).

    Args:
        scan_id: Associated scan ID.

    Returns:
        List[SoftwareItem]: Deduplicated list of installed software.
    """
    if sys.platform != "win32" or winreg is None:
        return []

    discovered: List[SoftwareItem] = []
    seen: Set[Tuple[str, str]] = set()

    for root_key, path in REGISTRY_LOCATIONS:
        if root_key and path:
            results = enumerate_registry_keys(root_key, path, scan_id=scan_id)
            for item in results:
                key = (item.name.lower().strip(), item.version.lower().strip())
                if key not in seen:
                    seen.add(key)
                    discovered.append(item)

    # Sort alphabetically by application name
    discovered.sort(key=lambda x: x.name.lower())
    return discovered


def match_allowed_software(
    software_list: List[SoftwareItem],
    allowlist: Optional[List[str]] = None,
) -> List[Tuple[SoftwareItem, str]]:
    """
    Filter discovered software against the allowed products for CVE scanning.

    Args:
        software_list: Full list of installed software.
        allowlist: List of approved software product keywords.

    Returns:
        List[Tuple[SoftwareItem, str]]: Pairs of (SoftwareItem, matched_keyword).
    """
    cfg = get_config()
    allowed = [p.lower().strip() for p in (allowlist or cfg.SOFTWARE_ALLOWLIST)]
    matched: List[Tuple[SoftwareItem, str]] = []

    for item in software_list:
        name_lower = item.name.lower()
        for kw in allowed:
            # Whole-word match so "java" does not match "JavaScript Tools"
            pattern = r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])"
            if re.search(pattern, name_lower):
                matched.append((item, kw))
                break

    return matched
