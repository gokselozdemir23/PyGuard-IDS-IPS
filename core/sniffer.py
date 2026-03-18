"""
PyGuard-IDS-IPS — Packet Sniffer Module

Captures network packets in real-time from a specified interface using
Scapy and forwards each packet to the detection engine.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Callable

from scapy.all import sniff, Packet  # type: ignore[import-untyped]

import config

if TYPE_CHECKING:
    from core.state import SharedState


class PacketSniffer:
    """
    Captures packets from a network interface.

    Each captured packet is passed to the `packet_callback` function.
    Runs in its own thread. Use `start()` to begin and `stop()` to stop.

    Args:
        interface: Network interface name (e.g., `eth0`)
        packet_callback: Function called for each captured packet
        state: Shared state object
    """

    def __init__(
        self,
        interface: str,
        packet_callback: Callable[[Packet, "SharedState"], None],
        state: "SharedState",
    ) -> None:
        self.interface = interface
        self.packet_callback = packet_callback
        self.state = state
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    # Lifecycle management

    def start(self) -> None:
        """Starts packet capturing in a separate thread."""
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._sniff_loop,
            name="PyGuard-Sniffer",
            daemon=True,
        )
        self._thread.start()
        print(f"[*] Sniffer started — interface: {self.interface}")

    def stop(self) -> None:
        """Stops packet capturing."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        print("[*] Sniffer stopped.")

    @property
    def is_running(self) -> bool:
        """Returns whether the sniffer is currently running."""
        return self._thread is not None and self._thread.is_alive()


    # Internal sniffing loop

    def _sniff_loop(self) -> None:
        """Runs the Scapy sniff() loop."""
        try:
            sniff(
                iface=self.interface,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except PermissionError:
            print(
                "[!] ERROR: Root privileges are required for packet capture.\n"
                "    Please run with 'sudo'."
            )
        except OSError as exc:
            print(f"[!] Interface error ({self.interface}): {exc}")

    def _handle_packet(self, packet: Packet) -> None:
        """
        Called for each captured packet.

        Classifies the protocol and forwards the packet to the callback.
        """
        protocol = self._classify_protocol(packet)
        self.state.increment_packet(protocol)
        self.packet_callback(packet, self.state)

    # Protocol classification

    @staticmethod
    def _classify_protocol(packet: Packet) -> str:
        """
        Classifies the packet based on its highest-level protocol.

        Returns:
            "TCP", "UDP", "ICMP", "ARP", or "Other"
        """
        if packet.haslayer("TCP"):
            return "TCP"
        if packet.haslayer("UDP"):
            return "UDP"
        if packet.haslayer("ICMP"):
            return "ICMP"
        if packet.haslayer("ARP"):
            return "ARP"
        return "Other"