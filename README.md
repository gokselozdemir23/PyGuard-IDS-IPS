# 🛡️ PyGuard-IDS-IPS

**Network-Based Intrusion Detection and Prevention System**

A modular IDS/IPS that analyzes network traffic in real-time, detects and blocks suspicious activities,
and presents the data graphically.

---

## Project Directory Structure

```
PyGuard-IDS-IPS/
├── main.py                 # Main orchestration file to start the entire system
├── config.py               # Central configuration (thresholds, interface, settings)
├── requirements.txt        # Python dependencies
├── simulator.py            # Attack simulator (testing tool)
├── Makefile                # Shortcut commands (make run, make test, etc.)
├── core/
│   ├── __init__.py         # Core package definition and exports
│   ├── sniffer.py          # Real-time packet capture using Scapy
│   ├── engine.py           # Rule-based intrusion detection engine (IDS)
│   ├── firewall.py         # Automatic IP blocking using iptables (IPS)
│   └── state.py            # Thread-safe shared state management
├── gui/
│   ├── __init__.py         # GUI package definition
│   └── dashboard.py        # Streamlit live dashboard
├── tests/
│   ├── __init__.py         # Test package definition
│   └── test_engine.py      # Unit tests (15 tests)
└── logs/
    └── alerts.json         # Alert logs in JSON format (auto-generated)
```

---

## Detected Attack Types

| Attack             | Description                                  | Default Threshold         |
| ------------------ | -------------------------------------------- | ------------------------- |
| **TCP SYN Flood**  | Excessive SYN packets sent in a short period | 100 packets / 10 sec      |
| **UDP Flood**      | Excessive UDP packets sent in a short period | 150 packets / 10 sec      |
| **ARP Spoofing**   | Multiple MAC addresses for the same IP       | 2 different MACs / 30 sec |
| **XMAS Port Scan** | FIN+PSH+URG flags sent together              | 5 packets / 15 sec        |

---

## Installation and Running

### Prerequisites

* **Operating System:** Linux (Ubuntu, Arch Linux, or Fedora recommended)
* **Python:** 3.10 or higher
* **Privileges:** root (required for packet capture and iptables)
* **iptables:** Installed and active

### Step 1 — Clone the project and navigate to the directory

```bash
git clone https://github.com/gokselozdemir23/PyGuard-IDS-IPS.git
cd PyGuard-IDS-IPS
```

### Step 2 — Create a virtual environment and install dependencies

```bash
source .venv/bin/activate
source .venv/bin/activate.fish # If you use fish terminal, use this command
pip install -r requirements.txt
```

### Step 3 — Edit the configuration

```bash
nano config.py
```

At minimum, set the `INTERFACE` variable to match your network interface:

```python
INTERFACE = "eth0"   # or "ens33", "wlan0", etc.
```

To list available interfaces:

```bash
ip link show
```

### Step 4 — Start the system

```bash
# Start all components (Sniffer + IDS + IPS + Dashboard)
sudo $(which python3) main.py -i eth0

# IDS mode only (without IPS)
sudo $(which python3) main.py -i eth0 --no-ips

# Without dashboard (terminal output only)
sudo $(which python3) main.py -i eth0 --no-dash
```

Or using Makefile shortcuts:

```bash
make install        # Install dependencies
make run            # Start with all components
make run-ids        # IDS mode only
make test           # Run unit tests
make simulate       # Start attack simulation
make flush          # Flush iptables chains
make clean          # Remove log files
```

### Step 5 — Access the dashboard

Open in your browser:

```
http://localhost:8501
```

### Step 6 — To stop

```
Ctrl + C
```

The system shuts down cleanly: iptables chains are flushed, sniffer stops, dashboard closes.

---

## Testing

### Built-in Simulator (Recommended)

```bash
# Terminal 1: Start PyGuard on loopback
sudo $(which python3) main.py -i lo

# Terminal 2: Run the simulator
sudo .venv/bin/python3 simulator.py --attack all --target 127.0.0.1
sudo .venv/bin/python3 simulator.py --attack syn_flood --target 127.0.0.1 --count 150
sudo .venv/bin/python3 simulator.py --attack xmas_scan --target 127.0.0.1 --count 20
```

### Using External Tools

```bash
# SYN Flood (requires hping3)
sudo apt install hping3
sudo hping3 -S --flood -p 80 <target-ip>

# XMAS Scan (nmap)
sudo nmap -sX -T4 <target-ip>

# UDP Flood
sudo hping3 --udp --flood -p 53 <target-ip>

# ARP Spoofing (requires dsniff)
sudo apt install dsniff
sudo arpspoof -i eth0 -t <target-ip> <gateway-ip>
```

### Unit Tests

```bash
python3 -m pytest tests/ -v
```

---

## Log Format (alerts.json)

Each line is an independent JSON object (JSON Lines):

```json
{
  "timestamp": "2026-03-14T12:30:45.123456+00:00",
  "alert_type": "SYN_FLOOD",
  "severity": "CRITICAL",
  "source_ip": "192.168.1.105",
  "detail": "120 SYN packets / 10s (threshold: 100)",
  "action_taken": "blocked"
}
```

---

## Environment Variables

| Variable        | Description            | Default |
| --------------- | ---------------------- | ------- |
| `PYGUARD_IFACE` | Network interface name | `eth0`  |

---

## License

This project is for educational and research purposes.
Extensive testing is recommended before deploying in a production environment.

