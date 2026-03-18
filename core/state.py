"""
PyGuard-IDS-IPS — Shared State

Provides thread-safe data sharing between Sniffer, Engine, and Dashboard.
All counters and lists are stored here and accessed via this object.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any

import config


@dataclass
class Alert:
    """Represents a single alert record."""

    timestamp: str
    alert_type: str
    severity: str
    source_ip: str
    detail: str
    action_taken: str = "logged"

    def to_dict(self) -> dict[str, str]:
        """Converts the alert into a JSON-serializable dictionary."""
        return {
            "timestamp": self.timestamp,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "detail": self.detail,
            "action_taken": self.action_taken,
        }


class SharedState:
    """
    Thread-safe shared state object.

    Attributes:
        packet_count: Total number of captured packets
        protocol_stats: Packet counts per protocol
        alerts: List of triggered alerts
        blocked_ips: Set of blocked IP addresses
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()

        # Total packet counter
        self.packet_count: int = 0

        # Packet count per protocol
        self.protocol_stats: dict[str, int] = {
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "ARP": 0,
            "Other": 0,
        }

        # Alert storage
        self.alerts: list[dict[str, str]] = []

        # Blocked IPs
        self.blocked_ips: set[str] = set()

        # Packets per second tracking
        self.packets_per_second: list[dict[str, Any]] = []
        self._pps_counter: int = 0
        self._pps_last_ts: float = time.time()

        # Create log directory if not exists
        os.makedirs(config.LOG_DIR, exist_ok=True)

    # Packet statistics
    def increment_packet(self, protocol: str) -> None:
        """Increments packet counters and protocol statistics."""
        with self._lock:
            self.packet_count += 1
            self._pps_counter += 1

            key = protocol if protocol in self.protocol_stats else "Other"
            self.protocol_stats[key] = self.protocol_stats.get(key, 0) + 1

    def snapshot_pps(self) -> None:
        """Calculates and stores packets per second (called by dashboard)."""
        with self._lock:
            now = time.time()
            elapsed = now - self._pps_last_ts

            if elapsed > 0:
                pps = self._pps_counter / elapsed
            else:
                pps = 0.0

            self.packets_per_second.append({
                "time": now,
                "pps": round(pps, 1)
            })

            # Keep last 120 samples (~4 minutes at 2s interval)
            if len(self.packets_per_second) > 120:
                self.packets_per_second = self.packets_per_second[-120:]

            self._pps_counter = 0
            self._pps_last_ts = now

    # Alert management
    def add_alert(self, alert: Alert) -> None:
        """Adds a new alert and writes it to the log file."""
        alert_dict = alert.to_dict()

        with self._lock:
            self.alerts.append(alert_dict)

        self._write_alert_log(alert_dict)

    def _write_alert_log(self, alert_dict: dict[str, str]) -> None:
        """Writes alert to file in JSON Lines format."""
        try:
            with open(config.ALERT_LOG_FILE, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(alert_dict, ensure_ascii=False) + "\n")
        except OSError as exc:
            print(f"[!] Log write error: {exc}")


    # Blocked IP management
    def add_blocked_ip(self, ip: str) -> None:
        """Stores a blocked IP address."""
        with self._lock:
            self.blocked_ips.add(ip)

    def is_blocked(self, ip: str) -> bool:
        """Checks if an IP is already blocked."""
        with self._lock:
            return ip in self.blocked_ips


    # Dashboard helpers
    def get_stats_snapshot(self) -> dict[str, Any]:
        """Returns a snapshot of current statistics for the dashboard."""
        with self._lock:
            return {
                "packet_count": self.packet_count,
                "protocol_stats": dict(self.protocol_stats),
                "alert_count": len(self.alerts),
                "blocked_count": len(self.blocked_ips),
                "alerts": list(self.alerts[-50:]),  # last 50 alerts
                "blocked_ips": list(self.blocked_ips),
                "packets_per_second": list(self.packets_per_second),
            }