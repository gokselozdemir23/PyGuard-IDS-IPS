"""
PyGuard-IDS-IPS — Live Dashboard

Visualizes real-time network traffic statistics, protocol distribution,
alert history, and blocked IPs using Streamlit.

This file can be started with `streamlit run gui/dashboard.py`
or launched as a separate process by `main.py`.
"""

from __future__ import annotations

import json
import os
import sys
import time

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Add project root directory to Python path
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import config  # noqa: E402


# Helper functions

def load_alerts() -> list[dict]:
    """
    Reads the alert log file in JSON Lines format.

    Returns:
        List of alert dictionaries
    """
    alerts: list[dict] = []
    log_path = config.ALERT_LOG_FILE

    if not os.path.exists(log_path):
        return alerts

    try:
        with open(log_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    alerts.append(json.loads(line))
    except (json.JSONDecodeError, OSError):
        pass

    return alerts


def load_packet_stats() -> dict:
    """
    Reads packet statistics from a shared file.

    Since sniffer and engine run in separate processes,
    stats are exchanged via an intermediate file.

    Returns:
        Statistics dictionary
    """
    stats_path = os.path.join(config.LOG_DIR, "stats.json")

    default = {
        "packet_count": 0,
        "protocol_stats": {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "Other": 0},
        "blocked_ips": [],
        "packets_per_second": [],
    }

    if not os.path.exists(stats_path):
        return default

    try:
        with open(stats_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return default


# Streamlit page configuration
st.set_page_config(
    page_title="PyGuard IDS/IPS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS styling
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Outfit:wght@400;600;700&display=swap');

    .stApp {
        font-family: 'Outfit', sans-serif;
    }
    code, .stCode {
        font-family: 'JetBrains Mono', monospace !important;
    }
    .metric-card {
        background: linear-gradient(135deg, #0f0f23 0%, #1a1a3e 100%);
        border: 1px solid #2d2d5e;
        border-radius: 12px;
        padding: 1.2rem;
        text-align: center;
    }
    .metric-value {
        font-size: 2.4rem;
        font-weight: 700;
        color: #00d4ff;
        font-family: 'JetBrains Mono', monospace;
    }
    .metric-label {
        font-size: 0.85rem;
        color: #8888aa;
        text-transform: uppercase;
        letter-spacing: 0.08em;
    }
    .alert-critical { border-left: 4px solid #ff4444; padding-left: 0.8rem; }
    .alert-high { border-left: 4px solid #ff8800; padding-left: 0.8rem; }
    </style>
    """,
    unsafe_allow_html=True,
)

# Sidebar
with st.sidebar:
    st.image(
        "https://img.icons8.com/fluency/96/shield.png",
        width=64,
    )
    st.title("PyGuard IDS/IPS")
    st.caption("Real-Time Network Security Monitor")

    st.divider()

    st.markdown(f"**Interface:** `{config.INTERFACE}`")
    st.markdown(f"**SYN Flood Threshold:** `{config.SYN_FLOOD_THRESHOLD}`")
    st.markdown(f"**UDP Flood Threshold:** `{config.UDP_FLOOD_THRESHOLD}`")
    st.markdown(f"**XMAS Scan Threshold:** `{config.XMAS_SCAN_THRESHOLD}`")
    st.markdown(f"**Auto Block:** `{'Enabled' if config.ENABLE_AUTO_BLOCK else 'Disabled'}`")

    st.divider()

    refresh_rate = st.slider(
        "Refresh Interval (sec)",
        min_value=1,
        max_value=10,
        value=config.DASHBOARD_REFRESH_SEC,
    )

# Load data
stats = load_packet_stats()
alerts = load_alerts()


# Top metric cards

st.markdown("## 🛡️ PyGuard — Live Dashboard")
st.markdown("---")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown(
        f"""<div class="metric-card">
            <div class="metric-value">{stats['packet_count']:,}</div>
            <div class="metric-label">Total Packets</div>
        </div>""",
        unsafe_allow_html=True,
    )

with col2:
    st.markdown(
        f"""<div class="metric-card">
            <div class="metric-value" style="color: #ff4444;">{len(alerts)}</div>
            <div class="metric-label">Alerts</div>
        </div>""",
        unsafe_allow_html=True,
    )

with col3:
    st.markdown(
        f"""<div class="metric-card">
            <div class="metric-value" style="color: #ff8800;">{len(stats.get('blocked_ips', []))}</div>
            <div class="metric-label">Blocked IPs</div>
        </div>""",
        unsafe_allow_html=True,
    )

with col4:
    proto = stats.get("protocol_stats", {})
    dominant = max(proto, key=proto.get) if proto and any(proto.values()) else "—"

    st.markdown(
        f"""<div class="metric-card">
            <div class="metric-value" style="color: #00ff88; font-size: 1.8rem;">{dominant}</div>
            <div class="metric-label">Top Protocol</div>
        </div>""",
        unsafe_allow_html=True,
    )

st.markdown("")


# Charts — Top row

chart_col1, chart_col2 = st.columns(2)

# Protocol distribution (donut chart)
with chart_col1:
    st.subheader("📊 Protocol Distribution")

    proto_data = stats.get("protocol_stats", {})

    if any(proto_data.values()):
        df_proto = pd.DataFrame(
            {"Protocol": list(proto_data.keys()), "Packets": list(proto_data.values())}
        )

        fig_proto = px.pie(
            df_proto,
            names="Protocol",
            values="Packets",
            hole=0.45,
            color_discrete_sequence=["#00d4ff", "#ff4444", "#00ff88", "#ffaa00", "#8888cc"],
        )

        fig_proto.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#ccccdd"),
            margin=dict(t=20, b=20, l=20, r=20),
            height=320,
        )

        st.plotly_chart(fig_proto, use_container_width=True)
    else:
        st.info("No packets captured yet — data will appear after sniffer starts.")

# Packets per second (time series)
with chart_col2:
    st.subheader("📈 Packets / Second")

    pps_data = stats.get("packets_per_second", [])

    if pps_data:
        df_pps = pd.DataFrame(pps_data)
        df_pps["time"] = pd.to_datetime(df_pps["time"], unit="s")

        fig_pps = go.Figure()
        fig_pps.add_trace(
            go.Scatter(
                x=df_pps["time"],
                y=df_pps["pps"],
                mode="lines",
                fill="tozeroy",
                line=dict(color="#00d4ff", width=2),
                fillcolor="rgba(0, 212, 255, 0.15)",
            )
        )

        fig_pps.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#ccccdd"),
            xaxis=dict(showgrid=False),
            yaxis=dict(showgrid=True, gridcolor="rgba(100,100,150,0.2)"),
            margin=dict(t=20, b=20, l=40, r=20),
            height=320,
        )

        st.plotly_chart(fig_pps, use_container_width=True)
    else:
        st.info("No packets-per-second data available yet.")


# Alert table

st.markdown("---")
st.subheader("🚨 Recent Alerts")

if alerts:
    df_alerts = pd.DataFrame(alerts[-30:][::-1])

    display_cols = ["timestamp", "alert_type", "severity", "source_ip", "detail", "action_taken"]
    available = [c for c in display_cols if c in df_alerts.columns]

    st.dataframe(
        df_alerts[available],
        use_container_width=True,
        height=350,
        column_config={
            "timestamp": st.column_config.TextColumn("Time", width="medium"),
            "alert_type": st.column_config.TextColumn("Type", width="small"),
            "severity": st.column_config.TextColumn("Severity", width="small"),
            "source_ip": st.column_config.TextColumn("Source IP", width="medium"),
            "detail": st.column_config.TextColumn("Detail", width="large"),
            "action_taken": st.column_config.TextColumn("Action", width="small"),
        },
    )
else:
    st.success("No alerts triggered — system is clean. ✅")


# Blocked IP list

blocked = stats.get("blocked_ips", [])

if blocked:
    st.markdown("---")
    st.subheader("🔒 Blocked IP Addresses")

    cols = st.columns(min(len(blocked), 6))

    for idx, ip in enumerate(blocked):
        with cols[idx % len(cols)]:
            st.code(ip, language=None)


# Auto refresh

time.sleep(refresh_rate)
st.rerun()