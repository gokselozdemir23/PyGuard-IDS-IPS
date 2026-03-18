#!/usr/bin/env python3
"""
PyGuard-IDS-IPS — Main Orchestration File

Starts all subsystems (Sniffer, Detection Engine, Firewall, Dashboard)
concurrently and manages their lifecycle.

Usage::

    sudo python3 main.py              # All components
    sudo python3 main.py --no-dash    # Without dashboard
    sudo python3 main.py --no-ips     # Without IPS (iptables)
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time

import config
from core.engine import DetectionEngine
from core.firewall import Firewall
from core.sniffer import PacketSniffer
from core.state import SharedState


# Global references (used by signal handler)

_sniffer: PacketSniffer | None = None
_firewall: Firewall | None = None
_dashboard_proc: subprocess.Popen | None = None
_shutdown_event = threading.Event()


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="PyGuard-IDS-IPS — Network Intrusion Detection and Prevention System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-i", "--interface",
        default=config.INTERFACE,
        help=f"Network interface to listen on (default: {config.INTERFACE})",
    )
    parser.add_argument(
        "--no-dash",
        action="store_true",
        help="Do not start the dashboard",
    )
    parser.add_argument(
        "--no-ips",
        action="store_true",
        help="Disable IPS (iptables blocking)",
    )
    return parser.parse_args()


def check_root() -> None:
    """Check for root privileges."""
    if os.geteuid() != 0:
        print("[!] ERROR: PyGuard must be run with root privileges.")
        print("    Usage: sudo python3 main.py")
        sys.exit(1)


def stats_writer(state: SharedState) -> None:
    """
    Periodically writes shared state to a JSON file.

    Since the dashboard runs as a separate Streamlit process,
    statistics are shared via an intermediate file.
    """
    stats_path = os.path.join(config.LOG_DIR, "stats.json")
    while not _shutdown_event.is_set():
        state.snapshot_pps()
        snapshot = state.get_stats_snapshot()
        try:
            tmp_path = stats_path + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as fh:
                json.dump(snapshot, fh, ensure_ascii=False)
            os.replace(tmp_path, stats_path)
        except OSError:
            pass
        _shutdown_event.wait(timeout=config.DASHBOARD_REFRESH_SEC)


def launch_dashboard() -> subprocess.Popen:
    """Start the Streamlit dashboard in a separate process."""
    dashboard_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "gui", "dashboard.py"
    )
    cmd = [
        sys.executable, "-m", "streamlit", "run",
        dashboard_path,
        "--server.port", str(config.DASHBOARD_PORT),
        "--server.address", config.DASHBOARD_HOST,
        "--server.headless", "true",
        "--theme.base", "dark",
        "--theme.primaryColor", "#00d4ff",
        "--browser.gatherUsageStats", "false",
    ]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(
        f"[*] Dashboard started → "
        f"http://localhost:{config.DASHBOARD_PORT}"
    )
    return proc


def shutdown_handler(signum: int, frame) -> None:
    """Handle graceful shutdown on Ctrl+C or SIGTERM."""
    global _sniffer, _firewall, _dashboard_proc

    print("\n[*] Shutdown signal received — cleaning up...")
    _shutdown_event.set()

    if _sniffer:
        _sniffer.stop()

    if _firewall:
        _firewall.cleanup()

    if _dashboard_proc:
        _dashboard_proc.terminate()
        _dashboard_proc.wait(timeout=5)
        print("[*] Dashboard stopped.")

    print("[*] PyGuard stopped. Stay safe!")
    sys.exit(0)


def print_banner() -> None:
    """Print startup banner."""
    banner = r"""
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║     ██████╗ ██╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗  ║
    ║     ██╔══██╗╚██╗ ██╔╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗ ║
    ║     ██████╔╝ ╚████╔╝ ██║  ███╗██║   ██║███████║██████╔╝██║  ██║ ║
    ║     ██╔═══╝   ╚██╔╝  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║ ║
    ║     ██║        ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝ ║
    ║     ╚═╝        ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ║
    ║                                                              ║
    ║          IDS / IPS  —  Network Intrusion Detection           ║
    ║                    & Prevention System                       ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main() -> None:
    """Main entry point — starts all components."""
    global _sniffer, _firewall, _dashboard_proc

    args = parse_args()
    check_root()
    print_banner()

    # Register signal handlers
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    # --- Shared state ---
    state = SharedState()
    print("[*] Shared state initialized.")

    # --- Firewall (IPS) ---
    if args.no_ips:
        config.ENABLE_AUTO_BLOCK = False
        print("[i] IPS disabled — running in detection-only mode.")

    _firewall = Firewall()
    print("[*] Firewall module ready.")

    # --- Detection Engine ---
    engine = DetectionEngine(state=state, firewall=_firewall)
    print("[*] Detection engine loaded — 4 rules active.")

    # --- Sniffer ---
    config.INTERFACE = args.interface
    _sniffer = PacketSniffer(
        interface=args.interface,
        packet_callback=engine.analyze,
        state=state,
    )
    _sniffer.start()

    # --- Stats writer thread ---
    writer_thread = threading.Thread(
        target=stats_writer,
        args=(state,),
        name="PyGuard-StatsWriter",
        daemon=True,
    )
    writer_thread.start()
    print("[*] Stats writer active.")

    # --- Dashboard ---
    if not args.no_dash:
        _dashboard_proc = launch_dashboard()

    # --- Main loop ---
    print("\n[*] PyGuard is running — listening for packets...")
    print("[*] Press Ctrl+C to stop\n")

    try:
        while not _shutdown_event.is_set():
            _shutdown_event.wait(timeout=1)
    except KeyboardInterrupt:
        shutdown_handler(signal.SIGINT, None)


if __name__ == "__main__":
    main()