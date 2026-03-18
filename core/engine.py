"""
PyGuard-IDS-IPS — Detection Engine

Analyzes incoming packets using rule-based detection and identifies:

* TCP SYN Flood — Excessive SYN packets in a short time
* UDP Flood — Excessive UDP packets in a short time
* ARP Spoofing — Multiple MAC addresses for the same IP
* XMAS Port Scan — FIN+PSH+URG flags set together

Each rule reads its window and threshold values from the `config` module.
"""

from __future__ import annotations

import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from scapy.all import Packet  # type: ignore[import-untyped]

import config
from core.state import Alert

if TYPE_CHECKING:
    from core.firewall import Firewall
    from core.state import SharedState


class DetectionEngine:
    """
    Rule-based attack detection engine.

    Each packet is passed to `analyze()`. If a threshold is exceeded,
    an alert is added to SharedState and the source IP may be blocked.

    Args:
        state: Shared state object
        firewall: Firewall instance for IPS actions
    """

    def __init__(self, state: "SharedState", firewall: "Firewall") -> None:
        self.state = state
        self.firewall = firewall

        # Track SYN packets per source IP
        self._syn_tracker: dict[str, list[float]] = defaultdict(list)

        # Track UDP packets per source IP
        self._udp_tracker: dict[str, list[float]] = defaultdict(list)

        # Track ARP mappings: {ip: {mac: first_seen_timestamp}}
        self._arp_table: dict[str, dict[str, float]] = defaultdict(dict)

        # Track XMAS scan packets per source IP
        self._xmas_tracker: dict[str, list[float]] = defaultdict(list)


    # Main analysis entry point

    def analyze(self, packet: Packet, state: "SharedState") -> None:
        """
        Runs all detection rules on the given packet.

        Args:
            packet: Scapy Packet object
            state: Shared state (kept for callback compatibility)
        """
        self._check_syn_flood(packet)
        self._check_udp_flood(packet)
        self._check_arp_spoof(packet)
        self._check_xmas_scan(packet)


    # RULE 1 — TCP SYN Flood Detection

    def _check_syn_flood(self, packet: Packet) -> None:

        # Counts SYN packets per source IP.

        # Triggers alert if count exceeds threshold within time window.

        if not packet.haslayer("TCP") or not packet.haslayer("IP"):
            return

        tcp_layer = packet["TCP"]

        # Check if only SYN flag is set (0x02)
        if tcp_layer.flags != 0x02:
            return

        src_ip: str = packet["IP"].src
        now = time.time()
        cutoff = now - config.SYN_FLOOD_WINDOW_SEC

        timestamps = self._syn_tracker[src_ip]

        # Remove old timestamps outside the window
        self._syn_tracker[src_ip] = [ts for ts in timestamps if ts > cutoff]
        self._syn_tracker[src_ip].append(now)

        if len(self._syn_tracker[src_ip]) >= config.SYN_FLOOD_THRESHOLD:
            self._trigger_alert(
                alert_type="SYN_FLOOD",
                severity="CRITICAL",
                source_ip=src_ip,
                detail=(
                    f"{len(self._syn_tracker[src_ip])} SYN packets / "
                    f"{config.SYN_FLOOD_WINDOW_SEC}s (threshold: {config.SYN_FLOOD_THRESHOLD})"
                ),
            )

            # Reset counter to avoid duplicate alerts
            self._syn_tracker[src_ip].clear()


    # RULE 2 — UDP Flood Detection

    def _check_udp_flood(self, packet: Packet) -> None:
        """
        Counts UDP packets per source IP.

        Triggers alert if count exceeds threshold within time window.
        """
        if not packet.haslayer("UDP") or not packet.haslayer("IP"):
            return

        src_ip: str = packet["IP"].src
        now = time.time()
        cutoff = now - config.UDP_FLOOD_WINDOW_SEC

        timestamps = self._udp_tracker[src_ip]

        # Remove old timestamps
        self._udp_tracker[src_ip] = [ts for ts in timestamps if ts > cutoff]
        self._udp_tracker[src_ip].append(now)

        if len(self._udp_tracker[src_ip]) >= config.UDP_FLOOD_THRESHOLD:
            self._trigger_alert(
                alert_type="UDP_FLOOD",
                severity="HIGH",
                source_ip=src_ip,
                detail=(
                    f"{len(self._udp_tracker[src_ip])} UDP packets / "
                    f"{config.UDP_FLOOD_WINDOW_SEC}s (threshold: {config.UDP_FLOOD_THRESHOLD})"
                ),
            )

            # Reset counter
            self._udp_tracker[src_ip].clear()

    # RULE 3 — ARP Spoofing Detection

    def _check_arp_spoof(self, packet: Packet) -> None:

        # Detects multiple MAC addresses for the same IP.

        # Triggers alert if MAC count exceeds limit within time window.

        if not packet.haslayer("ARP"):
            return

        arp_layer = packet["ARP"]

        # Only process ARP replies (op=2)
        if arp_layer.op != 2:
            return

        src_ip: str = arp_layer.psrc
        src_mac: str = arp_layer.hwsrc
        now = time.time()
        cutoff = now - config.ARP_SPOOF_WINDOW_SEC

        mac_map = self._arp_table[src_ip]

        # Remove expired MAC entries
        expired = [m for m, ts in mac_map.items() if ts < cutoff]
        for m in expired:
            del mac_map[m]

        mac_map[src_mac] = now

        if len(mac_map) > config.ARP_SPOOF_MAX_MACS:
            macs = ", ".join(mac_map.keys())

            self._trigger_alert(
                alert_type="ARP_SPOOF",
                severity="CRITICAL",
                source_ip=src_ip,
                detail=f"{len(mac_map)} different MACs detected for IP {src_ip}: {macs}",
            )

            # Reset ARP table for this IP
            self._arp_table[src_ip].clear()


    # RULE 4 — XMAS Port Scan Detection

    def _check_xmas_scan(self, packet: Packet) -> None:

        # Detects TCP packets with FIN + PSH + URG flags set.

        # Triggers alert if repeated within time window.

        if not packet.haslayer("TCP") or not packet.haslayer("IP"):
            return

        tcp_flags = packet["TCP"].flags

        # Check FIN(0x01) + PSH(0x08) + URG(0x20) = 0x29
        if (tcp_flags & 0x29) != 0x29:
            return

        src_ip: str = packet["IP"].src
        now = time.time()
        cutoff = now - config.XMAS_SCAN_WINDOW_SEC

        timestamps = self._xmas_tracker[src_ip]

        # Remove old timestamps
        self._xmas_tracker[src_ip] = [ts for ts in timestamps if ts > cutoff]
        self._xmas_tracker[src_ip].append(now)

        if len(self._xmas_tracker[src_ip]) >= config.XMAS_SCAN_THRESHOLD:
            self._trigger_alert(
                alert_type="XMAS_SCAN",
                severity="HIGH",
                source_ip=src_ip,
                detail=(
                    f"{len(self._xmas_tracker[src_ip])} XMAS packets / "
                    f"{config.XMAS_SCAN_WINDOW_SEC}s (threshold: {config.XMAS_SCAN_THRESHOLD})"
                ),
            )

            # Reset counter
            self._xmas_tracker[src_ip].clear()


    # Alert handling and IPS action

    def _trigger_alert(
        self,
        alert_type: str,
        severity: str,
        source_ip: str,
        detail: str,
    ) -> None:

        # Creates alert, logs it, and blocks IP if needed

        timestamp = datetime.now(timezone.utc).isoformat()
        action = "logged"

        # Block IP if enabled and not whitelisted
        if (
            config.ENABLE_AUTO_BLOCK
            and source_ip not in config.WHITELISTED_IPS
            and not self.state.is_blocked(source_ip)
        ):
            success = self.firewall.block_ip(source_ip)
            if success:
                action = "blocked"
                self.state.add_blocked_ip(source_ip)

        alert = Alert(
            timestamp=timestamp,
            alert_type=alert_type,
            severity=severity,
            source_ip=source_ip,
            detail=detail,
            action_taken=action,
        )

        self.state.add_alert(alert)

        icon = "🔴" if severity == "CRITICAL" else "🟠"

        print(
            f"  {icon} [{severity}] {alert_type} — "
            f"Source: {source_ip} | Action: {action}"
        )
        print(f"     └─ {detail}")