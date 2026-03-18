"""
PyGuard-IDS-IPS — Firewall / IPS Module

Blocks detected malicious IP addresses using Linux `iptables`.

Creates a dedicated chain (`PYGUARD_BLOCK`) to keep rules isolated,
making cleanup and rollback easier.
"""

from __future__ import annotations

import subprocess
import threading
from typing import Optional

import config


class Firewall:
    """
    iptables-based IP blocking manager.

    Creates a custom iptables chain and adds malicious IPs into it.
    Supports timed (temporary) blocking.

    Attributes:
        chain: Name of the iptables chain
    """

    def __init__(self) -> None:
        self.chain: str = config.IPTABLES_CHAIN
        self._lock = threading.Lock()
        self._unblock_timers: dict[str, threading.Timer] = {}
        self._setup_chain()

    # Chain management

    def _setup_chain(self) -> None:

        # Creates a dedicated iptables chain and links it to INPUT.

        # If the chain already exists, the error is ignored.

        # Create chain (ignore error if it already exists)
        self._run_iptables(["-N", self.chain], check=False)

        # Ensure INPUT jumps to our chain (avoid duplicate rule)
        result = self._run_iptables(
            ["-C", "INPUT", "-j", self.chain], check=False
        )
        if result is not None and result.returncode != 0:
            self._run_iptables(["-I", "INPUT", "1", "-j", self.chain], check=True)

        print(f"[*] iptables chain ready: {self.chain}")

    def block_ip(self, ip: str) -> bool:
        """
        Blocks the given IP address using iptables.

        Args:
            ip: IP address to block

        Returns:
            True if successful, False otherwise
        """
        if ip in config.WHITELISTED_IPS:
            print(f"[i] {ip} is whitelisted — not blocked.")
            return False

        with self._lock:
            # Check if rule already exists
            check = self._run_iptables(
                ["-C", self.chain, "-s", ip, "-j", "DROP"], check=False
            )
            if check is not None and check.returncode == 0:
                return True  # already blocked

            result = self._run_iptables(
                ["-A", self.chain, "-s", ip, "-j", "DROP"], check=True
            )
            if result is None or result.returncode != 0:
                print(f"[!] Failed to block {ip}.")
                return False

            print(f"[+] BLOCKED: {ip}")

            # Timed blocking — automatically remove after duration
            if config.BLOCK_DURATION_SEC > 0:
                timer = threading.Timer(
                    config.BLOCK_DURATION_SEC,
                    self._auto_unblock,
                    args=(ip,),
                )
                timer.daemon = True
                timer.start()
                self._unblock_timers[ip] = timer

            return True

    def unblock_ip(self, ip: str) -> bool:
        """
        Removes the block for the given IP address.

        Args:
            ip: IP address to unblock

        Returns:
            True if successful, False otherwise
        """
        with self._lock:
            result = self._run_iptables(
                ["-D", self.chain, "-s", ip, "-j", "DROP"], check=False
            )
            if result is not None and result.returncode == 0:
                print(f"[-] Unblocked: {ip}")

                # Cancel timer if exists
                timer = self._unblock_timers.pop(ip, None)
                if timer:
                    timer.cancel()

                return True

            return False

    def flush_chain(self) -> None:
        """
        Clears all rules in the PyGuard chain.

        Typically called on program shutdown.
        """
        self._run_iptables(["-F", self.chain], check=False)
        print(f"[*] {self.chain} chain flushed.")

        # Cancel all timers
        for timer in self._unblock_timers.values():
            timer.cancel()
        self._unblock_timers.clear()

    def cleanup(self) -> None:
        """
        Completely removes the PyGuard chain (rules + chain).

        Should be called on program shutdown.
        """
        # First clear rules
        self.flush_chain()

        # Remove jump from INPUT
        self._run_iptables(
            ["-D", "INPUT", "-j", self.chain], check=False
        )

        # Delete chain
        self._run_iptables(["-X", self.chain], check=False)

        print(f"[*] {self.chain} chain removed.")


    # Internal helpers

    def _auto_unblock(self, ip: str) -> None:
        """Automatically removes block when timer expires."""
        print(f"[i] Block expired — removing: {ip}")
        self.unblock_ip(ip)

    @staticmethod
    def _run_iptables(
        args: list[str], check: bool = True
    ) -> Optional[subprocess.CompletedProcess[str]]:
        """
        Executes an iptables command.

        Args:
            args: iptables arguments (command is added automatically)
            check: if True, raises exception on failure

        Returns:
            subprocess.CompletedProcess or None on error
        """
        cmd = ["iptables"] + args
        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=check,
                timeout=10,
            )
        except subprocess.CalledProcessError as exc:
            print(f"[!] iptables error: {' '.join(cmd)} → {exc.stderr.strip()}")
            return None
        except FileNotFoundError:
            print("[!] iptables not found — IPS disabled.")
            return None
        except subprocess.TimeoutExpired:
            print("[!] iptables timeout.")
            return None