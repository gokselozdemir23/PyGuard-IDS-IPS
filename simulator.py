#!/usr/bin/env python3
"""
PyGuard-IDS-IPS — Attack Simulator (Testing Tool)

Generates synthetic packets to test PyGuard's detection engine
without requiring real attack tools (e.g., hping3, nmap).

Usage::

    sudo python3 simulator.py --attack syn_flood --target 192.168.1.1
    sudo python3 simulator.py --attack all --target 192.168.1.1
    sudo python3 simulator.py --attack xmas_scan --target 192.168.1.1 --count 20

⚠️  This tool should only be used for testing within your own network.
    Sending packets to external networks without permission is illegal.
"""

from __future__ import annotations

import argparse
import random
import sys
import time

try:
    from scapy.all import (  # type: ignore[import-untyped]
        IP,
        TCP,
        UDP,
        ARP,
        Ether,
        RandShort,
        send,
        sendp,
    )
except ImportError:
    print("[!] scapy is not installed. Install it using 'pip install scapy'.")
    sys.exit(1)


def syn_flood(target: str, count: int, delay: float) -> None:
    """
    TCP SYN Flood simulation.

    Sends many SYN packets to the target using random source ports.

    Args:
        target: Target IP address.
        count: Number of packets to send.
        delay: Delay between packets (seconds).
    """
    print(f"[▶] Starting SYN Flood → {target} ({count} packets)")
    src_ip = f"10.0.0.{random.randint(2, 254)}"
    for i in range(count):
        pkt = IP(src=src_ip, dst=target) / TCP(
            sport=RandShort(),
            dport=random.choice([80, 443, 8080, 22]),
            flags="S",
        )
        send(pkt, verbose=False)
        if (i + 1) % 25 == 0:
            print(f"    ├─ {i + 1}/{count} packets sent")
        time.sleep(delay)
    print(f"[✓] SYN Flood completed — {count} packets sent.")


def udp_flood(target: str, count: int, delay: float) -> None:
    """
    UDP Flood simulation.

    Sends many UDP packets to random ports.

    Args:
        target: Target IP address.
        count: Number of packets to send.
        delay: Delay between packets (seconds).
    """
    print(f"[▶] Starting UDP Flood → {target} ({count} packets)")
    src_ip = f"10.0.0.{random.randint(2, 254)}"
    payload = b"X" * 64
    for i in range(count):
        pkt = IP(src=src_ip, dst=target) / UDP(
            sport=RandShort(),
            dport=random.choice([53, 123, 161, 5060]),
        ) / payload
        send(pkt, verbose=False)
        if (i + 1) % 25 == 0:
            print(f"    ├─ {i + 1}/{count} packets sent")
        time.sleep(delay)
    print(f"[✓] UDP Flood completed — {count} packets sent.")


def arp_spoof(target: str, count: int, delay: float) -> None:
    """
    ARP Spoofing simulation.

    Sends ARP reply packets with different MAC addresses for the same IP.

    Args:
        target: IP address to impersonate.
        count: Number of fake MAC addresses.
        delay: Delay between packets (seconds).
    """
    print(f"[▶] Starting ARP Spoofing → {target} ({count} fake MACs)")
    for i in range(count):
        fake_mac = ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=fake_mac) / ARP(
            op=2,  # ARP Reply
            psrc=target,
            hwsrc=fake_mac,
            pdst="255.255.255.255",
        )
        sendp(pkt, verbose=False)
        print(f"    ├─ MAC #{i + 1}: {fake_mac}")
        time.sleep(delay)
    print(f"[✓] ARP Spoofing completed — {count} fake MACs sent.")


def xmas_scan(target: str, count: int, delay: float) -> None:
    """
    XMAS Port Scan simulation.

    Sends TCP packets with FIN + PSH + URG flags set.

    Args:
        target: Target IP address.
        count: Number of packets to send.
        delay: Delay between packets (seconds).
    """
    print(f"[▶] Starting XMAS Scan → {target} ({count} packets)")
    src_ip = f"10.0.0.{random.randint(2, 254)}"
    ports = list(range(20, 1025))
    random.shuffle(ports)
    for i in range(count):
        pkt = IP(src=src_ip, dst=target) / TCP(
            sport=RandShort(),
            dport=ports[i % len(ports)],
            flags="FPU",  # FIN + PSH + URG
        )
        send(pkt, verbose=False)
        if (i + 1) % 5 == 0:
            print(f"    ├─ {i + 1}/{count} packets sent")
        time.sleep(delay)
    print(f"[✓] XMAS Scan completed — {count} packets sent.")


def run_all(target: str, count: int, delay: float) -> None:
    """Run all attack simulations sequentially."""
    print("=" * 60)
    print("  PyGuard Simulator — All Attacks")
    print("=" * 60)

    syn_flood(target, count, delay)
    print()
    time.sleep(1)

    udp_flood(target, int(count * 1.5), delay)
    print()
    time.sleep(1)

    arp_spoof(target, max(count // 20, 5), delay * 5)
    print()
    time.sleep(1)

    xmas_scan(target, max(count // 10, 10), delay)
    print()

    print("=" * 60)
    print("  All simulations completed.")
    print("  → Check PyGuard dashboard: http://localhost:8501")
    print("=" * 60)


# CLI

ATTACKS = {
    "syn_flood": syn_flood,
    "udp_flood": udp_flood,
    "arp_spoof": arp_spoof,
    "xmas_scan": xmas_scan,
    "all": run_all,
}


def main() -> None:
    """Start attack simulation from command line."""
    parser = argparse.ArgumentParser(
        description="PyGuard-IDS-IPS Test Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python3 simulator.py --attack syn_flood --target 192.168.1.1\n"
            "  sudo python3 simulator.py --attack all --target 192.168.1.1 --count 200\n"
            "  sudo python3 simulator.py --attack xmas_scan --target 10.0.0.1 --delay 0.05\n"
        ),
    )
    parser.add_argument(
        "-a", "--attack",
        choices=list(ATTACKS.keys()),
        required=True,
        help="Attack type to simulate",
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target IP address (your own machine or test environment)",
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=120,
        help="Number of packets to send (default: 120)",
    )
    parser.add_argument(
        "-d", "--delay",
        type=float,
        default=0.01,
        help="Delay between packets in seconds (default: 0.01)",
    )
    args = parser.parse_args()

    if args.target.startswith("127.") or args.target == "localhost":
        print("[i] Localhost target — packets will use loopback.")
        print("    Make sure PyGuard listens on 'lo' interface.")
        print("    → sudo python3 main.py -i lo\n")

    attack_fn = ATTACKS[args.attack]
    try:
        attack_fn(args.target, args.count, args.delay)
    except KeyboardInterrupt:
        print("\n[!] Simulation interrupted.")
    except PermissionError:
        print("[!] Root privileges required — run with 'sudo'.")


if __name__ == "__main__":
    main()