"""
WinSentinel - Privilege detection.

Several checks (Security event log, BitLocker, Defender exclusions) need Administrator rights.
This helper tells the CLI, the dashboard banner and the live monitor whether the process is elevated.
"""

import ctypes
import os
import sys


def is_elevated() -> bool:
    """
    Return True if the current process has Administrator (elevated) rights.

    Returns:
        bool: True on an elevated Windows token (or root on POSIX), False otherwise or on error.
    """
    try:
        if sys.platform == "win32":
            return bool(ctypes.windll.shell32.IsUserAnAdmin() != 0)
        return hasattr(os, "getuid") and os.getuid() == 0
    except Exception:
        return False
