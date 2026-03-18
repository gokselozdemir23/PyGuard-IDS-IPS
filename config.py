"""
PyGuard-IDS-IPS Configuration File

All detection thresholds, network interface settings, and system parameters
are managed centrally from this file.
"""

import os


# Network Interface Settings
INTERFACE: str = os.getenv("PYGUARD_IFACE", ")")


# Attack Detection Thresholds

# TCP SYN Flood:
# If the number of SYN packets from a single source exceeds this threshold
# within a given time window, an alert is triggered.
SYN_FLOOD_THRESHOLD: int = 100
SYN_FLOOD_WINDOW_SEC: int = 10  # seconds

# UDP Flood:
# If the number of UDP packets from a single source exceeds this threshold
# within a given time window, an alert is triggered.
UDP_FLOOD_THRESHOLD: int = 150
UDP_FLOOD_WINDOW_SEC: int = 10  # seconds

# ARP Spoofing:
# If multiple MAC addresses are observed for the same IP
# within a short time window, an alert is triggered.
ARP_SPOOF_WINDOW_SEC: int = 30  # seconds
ARP_SPOOF_MAX_MACS: int = 2     # maximum allowed MACs per IP

# XMAS Port Scan:
# Packets with FIN + PSH + URG flags set are treated as XMAS scan packets.
# If the count from a single source exceeds this threshold, an alert is triggered.
XMAS_SCAN_THRESHOLD: int = 5
XMAS_SCAN_WINDOW_SEC: int = 15  # seconds


# Prevention (IPS) Settings

ENABLE_AUTO_BLOCK: bool = True  # Automatically block detected IPs if True
BLOCK_DURATION_SEC: int = 3600  # Block duration in seconds (0 = permanent)

# iptables chain name used by PyGuard for managing blocked IPs.
IPTABLES_CHAIN: str = "PYGUARD_BLOCK"

# IP addresses excluded from blocking (whitelist).
WHITELISTED_IPS: list[str] = [
    "127.0.0.1",
    "::1",
]


# Logging Settings

# Directory where log files are stored.
LOG_DIR: str = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")

# File path for storing alert logs.
ALERT_LOG_FILE: str = os.path.join(LOG_DIR, "alerts.json")


# Dashboard Settings

# Host address for the dashboard server.
DASHBOARD_HOST: str = "0.0.0.0"

# Port used by the dashboard.
DASHBOARD_PORT: int = 8501

# Auto-refresh interval for the dashboard (in seconds).
DASHBOARD_REFRESH_SEC: int = 2