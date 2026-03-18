#!/usr/bin/env python3
"""
PyGuard-IDS-IPS — Birim Testleri
==================================
Tespit motoru, paylaşımlı durum ve güvenlik duvarı modüllerinin
doğru çalıştığını kontrol eden test paketi.

Çalıştırma::

    python3 -m pytest tests/ -v
    python3 -m pytest tests/ -v --tb=short
"""

from __future__ import annotations

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Proje kök dizinini Python yoluna ekle
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import config
from core.state import Alert, SharedState


# ======================================================================
# Fixtures
# ======================================================================

@pytest.fixture(autouse=True)
def _temp_log_dir(tmp_path, monkeypatch):
    """Her test için geçici bir log dizini kullanır."""
    log_dir = str(tmp_path / "logs")
    os.makedirs(log_dir, exist_ok=True)
    monkeypatch.setattr(config, "LOG_DIR", log_dir)
    monkeypatch.setattr(
        config, "ALERT_LOG_FILE", os.path.join(log_dir, "alerts.json")
    )


@pytest.fixture
def state() -> SharedState:
    """Temiz bir SharedState nesnesi döndürür."""
    return SharedState()


@pytest.fixture
def mock_firewall():
    """Mock Firewall nesnesi."""
    fw = MagicMock()
    fw.block_ip.return_value = True
    return fw


@pytest.fixture
def engine(state, mock_firewall):
    """DetectionEngine nesnesi (mock firewall ile)."""
    from core.engine import DetectionEngine
    return DetectionEngine(state=state, firewall=mock_firewall)


# ======================================================================
# SharedState Testleri
# ======================================================================

class TestSharedState:
    """SharedState sınıfının testleri."""

    def test_initial_state(self, state: SharedState) -> None:
        """Başlangıç durumu doğru olmalı."""
        assert state.packet_count == 0
        assert state.protocol_stats["TCP"] == 0
        assert len(state.alerts) == 0
        assert len(state.blocked_ips) == 0

    def test_increment_packet_known_protocol(self, state: SharedState) -> None:
        """Bilinen protokoller doğru sayılmalı."""
        state.increment_packet("TCP")
        state.increment_packet("TCP")
        state.increment_packet("UDP")
        assert state.packet_count == 3
        assert state.protocol_stats["TCP"] == 2
        assert state.protocol_stats["UDP"] == 1

    def test_increment_packet_unknown_protocol(self, state: SharedState) -> None:
        """Bilinmeyen protokoller 'Other' altında sayılmalı."""
        state.increment_packet("SCTP")
        assert state.protocol_stats["Other"] == 1

    def test_add_alert_persists_to_file(self, state: SharedState) -> None:
        """Alarm JSON dosyasına yazılmalı."""
        alert = Alert(
            timestamp="2026-03-14T12:00:00",
            alert_type="SYN_FLOOD",
            severity="CRITICAL",
            source_ip="10.0.0.1",
            detail="Test alarm",
        )
        state.add_alert(alert)

        assert len(state.alerts) == 1
        assert state.alerts[0]["alert_type"] == "SYN_FLOOD"

        # Dosyada da olmalı
        with open(config.ALERT_LOG_FILE, "r") as fh:
            lines = fh.readlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["source_ip"] == "10.0.0.1"

    def test_blocked_ip_tracking(self, state: SharedState) -> None:
        """Bloklanan IP'ler doğru takip edilmeli."""
        assert not state.is_blocked("192.168.1.100")
        state.add_blocked_ip("192.168.1.100")
        assert state.is_blocked("192.168.1.100")

    def test_snapshot_returns_copy(self, state: SharedState) -> None:
        """Snapshot verisi orijinal durumdan bağımsız olmalı."""
        state.increment_packet("TCP")
        snap = state.get_stats_snapshot()
        assert snap["packet_count"] == 1
        state.increment_packet("TCP")
        assert snap["packet_count"] == 1

    def test_snapshot_pps(self, state: SharedState) -> None:
        """PPS snapshot'ı veri üretmeli."""
        state.increment_packet("TCP")
        state.increment_packet("TCP")
        state.snapshot_pps()
        assert len(state.packets_per_second) == 1
        assert state.packets_per_second[0]["pps"] >= 0


# ======================================================================
# Alert Veri Sınıfı Testleri
# ======================================================================

class TestAlert:
    """Alert dataclass testleri."""

    def test_to_dict(self) -> None:
        """to_dict() doğru sözlük döndürmeli."""
        alert = Alert(
            timestamp="2026-01-01T00:00:00",
            alert_type="ARP_SPOOF",
            severity="HIGH",
            source_ip="10.0.0.5",
            detail="Sahte MAC tespit edildi",
            action_taken="blocked",
        )
        d = alert.to_dict()
        assert d["alert_type"] == "ARP_SPOOF"
        assert d["action_taken"] == "blocked"
        assert isinstance(d, dict)

    def test_default_action(self) -> None:
        """Varsayılan aksiyon 'logged' olmalı."""
        alert = Alert(
            timestamp="t",
            alert_type="X",
            severity="LOW",
            source_ip="1.1.1.1",
            detail="d",
        )
        assert alert.action_taken == "logged"


# ======================================================================
# Detection Engine Testleri
# ======================================================================

class TestDetectionEngine:
    """DetectionEngine tespit kurallarının testleri."""

    @staticmethod
    def _make_syn_packet(src_ip: str = "10.0.0.50", dst_ip: str = "192.168.1.1"):
        """Sahte SYN paketi oluşturur."""
        from scapy.all import IP, TCP
        return IP(src=src_ip, dst=dst_ip) / TCP(flags="S", dport=80)

    @staticmethod
    def _make_udp_packet(src_ip: str = "10.0.0.60", dst_ip: str = "192.168.1.1"):
        """Sahte UDP paketi oluşturur."""
        from scapy.all import IP, UDP
        return IP(src=src_ip, dst=dst_ip) / UDP(dport=53)

    @staticmethod
    def _make_xmas_packet(src_ip: str = "10.0.0.70", dst_ip: str = "192.168.1.1"):
        """Sahte XMAS paketi oluşturur."""
        from scapy.all import IP, TCP
        return IP(src=src_ip, dst=dst_ip) / TCP(flags="FPU", dport=80)

    @staticmethod
    def _make_arp_reply(src_ip: str = "192.168.1.1", src_mac: str = "aa:bb:cc:dd:ee:ff"):
        """Sahte ARP Reply paketi oluşturur."""
        from scapy.all import ARP, Ether
        return Ether(src=src_mac) / ARP(
            op=2, psrc=src_ip, hwsrc=src_mac, pdst="255.255.255.255"
        )

    def test_syn_flood_triggers_alert(self, engine, state, monkeypatch) -> None:
        """Eşik aşılınca SYN Flood alarmı tetiklenmeli."""
        monkeypatch.setattr(config, "SYN_FLOOD_THRESHOLD", 5)
        monkeypatch.setattr(config, "SYN_FLOOD_WINDOW_SEC", 60)

        pkt = self._make_syn_packet()
        for _ in range(6):
            engine.analyze(pkt, state)

        syn_alerts = [a for a in state.alerts if a["alert_type"] == "SYN_FLOOD"]
        assert len(syn_alerts) >= 1

    def test_syn_flood_no_alert_below_threshold(self, engine, state, monkeypatch) -> None:
        """Eşik altında SYN Flood alarmı tetiklenmemeli."""
        monkeypatch.setattr(config, "SYN_FLOOD_THRESHOLD", 100)

        pkt = self._make_syn_packet()
        for _ in range(10):
            engine.analyze(pkt, state)

        syn_alerts = [a for a in state.alerts if a["alert_type"] == "SYN_FLOOD"]
        assert len(syn_alerts) == 0

    def test_udp_flood_triggers_alert(self, engine, state, monkeypatch) -> None:
        """Eşik aşılınca UDP Flood alarmı tetiklenmeli."""
        monkeypatch.setattr(config, "UDP_FLOOD_THRESHOLD", 5)
        monkeypatch.setattr(config, "UDP_FLOOD_WINDOW_SEC", 60)

        pkt = self._make_udp_packet()
        for _ in range(6):
            engine.analyze(pkt, state)

        udp_alerts = [a for a in state.alerts if a["alert_type"] == "UDP_FLOOD"]
        assert len(udp_alerts) >= 1

    def test_xmas_scan_triggers_alert(self, engine, state, monkeypatch) -> None:
        """Eşik aşılınca XMAS Scan alarmı tetiklenmeli."""
        monkeypatch.setattr(config, "XMAS_SCAN_THRESHOLD", 3)
        monkeypatch.setattr(config, "XMAS_SCAN_WINDOW_SEC", 60)

        pkt = self._make_xmas_packet()
        for _ in range(4):
            engine.analyze(pkt, state)

        xmas_alerts = [a for a in state.alerts if a["alert_type"] == "XMAS_SCAN"]
        assert len(xmas_alerts) >= 1

    def test_arp_spoof_triggers_alert(self, engine, state, monkeypatch) -> None:
        """Aynı IP'den farklı MAC'ler gelince ARP Spoofing alarmı tetiklenmeli."""
        monkeypatch.setattr(config, "ARP_SPOOF_MAX_MACS", 2)
        monkeypatch.setattr(config, "ARP_SPOOF_WINDOW_SEC", 60)

        target_ip = "192.168.1.1"
        for i in range(4):
            mac = f"aa:bb:cc:dd:ee:{i:02x}"
            pkt = self._make_arp_reply(src_ip=target_ip, src_mac=mac)
            engine.analyze(pkt, state)

        arp_alerts = [a for a in state.alerts if a["alert_type"] == "ARP_SPOOF"]
        assert len(arp_alerts) >= 1

    def test_whitelisted_ip_not_blocked(self, engine, state, mock_firewall, monkeypatch) -> None:
        """Whitelist'teki IP'ler bloklanmamalı."""
        monkeypatch.setattr(config, "SYN_FLOOD_THRESHOLD", 3)
        monkeypatch.setattr(config, "WHITELISTED_IPS", ["10.0.0.50"])

        pkt = self._make_syn_packet(src_ip="10.0.0.50")
        for _ in range(5):
            engine.analyze(pkt, state)

        for alert in state.alerts:
            assert alert.get("action_taken") != "blocked"

    def test_auto_block_disabled(self, engine, state, mock_firewall, monkeypatch) -> None:
        """ENABLE_AUTO_BLOCK=False ise IP bloklanmamalı."""
        monkeypatch.setattr(config, "SYN_FLOOD_THRESHOLD", 3)
        monkeypatch.setattr(config, "ENABLE_AUTO_BLOCK", False)

        pkt = self._make_syn_packet()
        for _ in range(5):
            engine.analyze(pkt, state)

        mock_firewall.block_ip.assert_not_called()

    def test_already_blocked_ip_not_reblocked(self, engine, state, mock_firewall, monkeypatch) -> None:
        """Zaten bloklanan IP tekrar bloklanmamalı."""
        monkeypatch.setattr(config, "SYN_FLOOD_THRESHOLD", 3)
        state.add_blocked_ip("10.0.0.50")

        pkt = self._make_syn_packet(src_ip="10.0.0.50")
        for _ in range(5):
            engine.analyze(pkt, state)

        mock_firewall.block_ip.assert_not_called()


# ======================================================================
# Firewall Testleri (iptables mock'lanmış)
# ======================================================================

class TestFirewall:
    """Firewall sınıfının testleri (iptables subprocess mock ile)."""

    @patch("core.firewall.subprocess.run")
    def test_block_ip_calls_iptables(self, mock_run, monkeypatch) -> None:
        """block_ip() doğru iptables komutunu çalıştırmalı."""
        from core.firewall import Firewall

        mock_run.return_value = MagicMock(returncode=1)
        monkeypatch.setattr(config, "BLOCK_DURATION_SEC", 0)

        fw = Firewall()

        mock_run.side_effect = [
            MagicMock(returncode=1),  # -C → kural yok
            MagicMock(returncode=0),  # -A → eklendi
        ]
        result = fw.block_ip("192.168.1.100")
        assert result is True

        calls = mock_run.call_args_list
        add_call = calls[-1]
        cmd = add_call[0][0]
        assert "PYGUARD_BLOCK" in cmd
        assert "-A" in cmd
        assert "192.168.1.100" in cmd

    @patch("core.firewall.subprocess.run")
    def test_whitelisted_ip_not_blocked(self, mock_run, monkeypatch) -> None:
        """Whitelist'teki IP'ler bloklanmamalı."""
        from core.firewall import Firewall

        mock_run.return_value = MagicMock(returncode=0)
        monkeypatch.setattr(config, "WHITELISTED_IPS", ["10.0.0.1"])

        fw = Firewall()
        result = fw.block_ip("10.0.0.1")
        assert result is False
