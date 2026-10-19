"""
WinSentinel - Failed Login Generator Demo Script.

Simulates failed logon attempts against a local user account on the current Windows host
using the native Windows LogonUserW API (advapi32.dll).
Each failed attempt causes Windows LSASS to record an authentic Event ID 4625 in the
Windows Security Event Log, allowing verification of WinSentinel's brute-force detection
rules without requiring actual network attacks.

Legal & Ethical Scope:
  - This script operates ONLY on the local machine (host: . / localhost).
  - No network traffic, exploitation, or credential dumping is performed.
  - For educational and lab demonstration purposes only.
"""

import sys
import time
import argparse
import ctypes
from ctypes import wintypes


def simulate_failed_logon(
    username: str,
    domain: str = ".",
    count: int = 6,
    delay_seconds: float = 0.5,
) -> int:
    """
    Trigger failed logon attempts against a local account using advapi32.LogonUserW.

    Args:
        username: Name of the local account to target.
        domain: Domain name (defaults to '.' for local machine).
        count: Number of failed logon attempts to generate.
        delay_seconds: Pause in seconds between attempts.

    Returns:
        int: Number of simulated failed attempts successfully executed.
    """
    if sys.platform != "win32":
        print("[-] Error: This script is only supported on Windows.", file=sys.stderr)
        return 0

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    # Windows Logon Constants
    LOGON32_LOGON_INTERACTIVE = 2
    LOGON32_PROVIDER_DEFAULT = 0

    print("=" * 65)
    print("WinSentinel - Failed Login Generator (Event 4625 Simulation)")
    print(f"Target Account : {username}")
    print(f"Domain         : {domain} (Local)")
    print(f"Attempt Count  : {count}")
    print(f"Delay          : {delay_seconds}s")
    print("=" * 65)

    success_count = 0
    token_handle = wintypes.HANDLE()

    for idx in range(1, count + 1):
        bogus_password = f"SimulatedWrongPassword_{idx}_{int(time.time())}!"
        print(f"[*] [{idx}/{count}] Simulating failed logon for '{username}'...", end=" ")

        result = advapi32.LogonUserW(
            username,
            domain,
            bogus_password,
            LOGON32_LOGON_INTERACTIVE,
            LOGON32_PROVIDER_DEFAULT,
            ctypes.byref(token_handle),
        )

        win_err = ctypes.get_last_error()
        # Error 1326 = ERROR_LOGON_FAILURE (Bad username or bad password)
        # Error 1327 = ERROR_ACCOUNT_RESTRICTION
        # Error 1331 = ERROR_ACCOUNT_DISABLED
        if result == 0 and win_err in (1326, 1327, 1331, 1909):
            print(f"Logged 4625 (Win32 Error: {win_err})")
            success_count += 1
        else:
            print(f"Result: {result}, Error: {win_err}")

        if idx < count and delay_seconds > 0:
            time.sleep(delay_seconds)

    print("-" * 65)
    print(f"[+] Completed: Generated {success_count} failed logon attempts.")
    print("[*] These events will be logged under Windows Security Log as Event ID 4625.")
    print("[*] Re-run 'python main.py scan' to verify WinSentinel detects the brute-force pattern.")
    print("=" * 65)

    return success_count


def main() -> None:
    """Parse arguments and execute simulation."""
    parser = argparse.ArgumentParser(
        prog="generate_failed_logins",
        description="Simulate local failed logon attempts (Event 4625) for brute-force detection testing.",
    )
    parser.add_argument(
        "--account",
        "-a",
        default="LocalTestAccount",
        help="Local account name to target (default: LocalTestAccount)",
    )
    parser.add_argument(
        "--count",
        "-c",
        type=int,
        default=6,
        help="Number of failed logon attempts to simulate (default: 6)",
    )
    parser.add_argument(
        "--delay",
        "-d",
        type=float,
        default=0.5,
        help="Delay in seconds between attempts (default: 0.5)",
    )

    args = parser.parse_args()
    simulate_failed_logon(
        username=args.account,
        count=args.count,
        delay_seconds=args.delay,
    )


if __name__ == "__main__":
    main()
