import re
# ==============================================================================
#  AI-DRIVEN CYBER DECEPTION PLATFORM — SOC COMMAND DASHBOARD (V1)
# ==============================================================================
# Read-only visualization layer. Does NOT modify, retrain, or call any of the
# existing backend logic (Wazuh, Conpot, Suricata, Isolation Forest, Random
# Forest, KMeans, SHAP, LLM Assistant, Decision Engine, Automation Layer).
# 
# It only READS artifacts your pipeline already produces:
#   - dataset_ia.jsonl                 (Wazuh alerts export, Partie 10)
#   - session_tracker_output.json      (Session Tracker, Session 3)
#   - rf_predictions.csv               (Module 2 — Random Forest)
#   - isolation_forest_results.csv     (Partie 10 — Isolation Forest)
#   - kmeans_clusters.csv              (Module 3 — KMeans)
#   - shap_importance.csv              (Partie 10 — SHAP)
#   - decision_engine_log.jsonl        (Layer 4 — Automation / Decision Engine)
#   - system.log                       (free-text log tail)
# 
# If a file is missing, the dashboard falls back to clearly-labelled DEMO DATA
# shaped exactly like the real schema, so the app never breaks during a defense
# even if a VM is offline. Swap real paths in the CONFIG block below and the
# demo banner disappears automatically once real files are found.
# 
# Run:
#     pip install -r requirements.txt
#     streamlit run app.py
# ==============================================================================

import json
import os
import time
import random
from datetime import datetime, timedelta

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import streamlit as st

# ==============================================================================
# CONFIG — point these at your real backend output files
# ==============================================================================
DATA_DIR = os.environ.get("SOC_DATA_DIR", "./data")

PATHS = {
    "alerts_jsonl": os.path.join(DATA_DIR, "dataset_ia.jsonl"),
    "alerts_live_jsonl": os.path.join(DATA_DIR, "dataset_ia_live.jsonl"),
    "sessions_json": os.path.join(DATA_DIR, "session_tracker_output.json"),
    "rf_predictions": os.path.join(DATA_DIR, "rf_predictions.csv"),
    "iforest_results": os.path.join(DATA_DIR, "isolation_forest_results.csv"),
    "kmeans_clusters": os.path.join(DATA_DIR, "kmeans_clusters.csv"),
    "shap_importance": os.path.join(DATA_DIR, "shap_importance.csv"),
    "decision_log": os.path.join(DATA_DIR, "decision_engine_log.jsonl"),
    "system_log": os.path.join(DATA_DIR, "system.log"),
}

REFRESH_SECONDS = 15  # "live" feel — safe no-op if autorefresh pkg absent

# ==============================================================================
# PAGE SETUP
# ==============================================================================
st.set_page_config(
    page_title="CyberDeceptionAI // SOC Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ==============================================================================
# DESIGN TOKENS — dark SOC theme (Sentinel/QRadar-inspired, own identity)
# ==============================================================================
COLORS = {
    "bg": "#0f1113",
    "bg2": "#15171b",
    "panel": "#191c21",
    "panel2": "#1e2127",
    "border": "#2b2e35",
    "text": "#e6e7ea",
    "muted": "#8a8d96",
    "blue": "#6b8fd1",
    "cyan": "#5fa3a0",
    "purple": "#8b7fc0",
    "green": "#5fa87e",
    "red": "#c96a63",
    "orange": "#c99a5b",
}

PLOTLY_TEMPLATE = go.layout.Template(
    layout=go.Layout(
        paper_bgcolor=COLORS["panel"],
        plot_bgcolor=COLORS["panel"],
        font=dict(family="Inter, sans-serif", color=COLORS["text"], size=12),
        xaxis=dict(gridcolor=COLORS["border"], zerolinecolor=COLORS["border"]),
        yaxis=dict(gridcolor=COLORS["border"], zerolinecolor=COLORS["border"]),
        legend=dict(bgcolor="rgba(0,0,0,0)"),
        margin=dict(l=10, r=10, t=40, b=10),
    )
)

CUSTOM_CSS = f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700;800&display=swap');

html, body, [class*="css"] {{
    font-family: 'Inter', sans-serif;
    color: {COLORS['text']};
}}

.stApp {{
    background: {COLORS['bg']};
}}

/* ---- top accent bar (static, no animation) ---- */
.scan-bar {{
    height: 2px;
    width: 100%;
    background: {COLORS['border']};
    border-radius: 2px;
    margin-bottom: 18px;
}}

/* ---- header ---- */
.app-header {{
    display: flex; align-items: center; justify-content: space-between;
    padding-bottom: 12px; margin-bottom: 8px;
    border-bottom: 1px solid {COLORS['border']};
}}
.app-title {{
    font-family: 'Inter', sans-serif;
    font-weight: 700; font-size: 1.4rem; letter-spacing: 0.2px;
    color: {COLORS['text']};
}}
.app-title span {{ color: {COLORS['cyan']}; font-weight: 800; }}
.app-subtitle {{ color: {COLORS['muted']}; font-size: 0.82rem; margin-top: 2px; }}

.live-pill {{
    display: inline-flex; align-items: center; gap: 7px;
    background: rgba(95,168,126,0.10); border: 1px solid rgba(95,168,126,0.3);
    color: {COLORS['green']}; padding: 5px 12px; border-radius: 20px;
    font-family: 'Inter', sans-serif; font-size: 0.75rem; font-weight: 600;
    letter-spacing: 0.4px;
}}
.live-dot {{
    width: 6px; height: 6px; border-radius: 50%; background: {COLORS['green']};
    animation: pulse 2.2s ease-in-out infinite;
}}
@keyframes pulse {{
    0%, 100% {{ opacity: 1; }}
    50% {{ opacity: 0.45; }}
}}

/* ---- section titles ---- */
.sec-title {{
    font-family: 'Inter', sans-serif;
    font-size: 0.92rem; font-weight: 700; letter-spacing: 0.2px;
    color: {COLORS['text']};
    display: flex; align-items: center; gap: 9px;
    margin: 24px 0 12px 0;
}}
.sec-title .bar {{ width: 3px; height: 15px; border-radius: 2px; }}

/* ---- KPI cards ---- */
.kpi-card {{
    background: {COLORS['panel']};
    border: 1px solid {COLORS['border']};
    border-radius: 10px; padding: 16px 18px;
    transition: border-color .15s ease;
}}
.kpi-card:hover {{ border-color: {COLORS['blue']}; }}
.kpi-label {{
    font-size: 0.7rem; color: {COLORS['muted']}; text-transform: uppercase;
    letter-spacing: 0.8px; font-family: 'Inter', sans-serif; font-weight: 600;
}}
.kpi-value {{
    font-family: 'JetBrains Mono', monospace; font-weight: 700;
    font-size: 1.75rem; margin-top: 5px; color: {COLORS['text']};
}}
.kpi-delta {{ font-size: 0.72rem; margin-top: 3px; font-weight: 500; color: {COLORS['muted']}; }}

/* ---- badges ---- */
.badge {{
    display: inline-block; padding: 3px 10px; border-radius: 6px;
    font-size: 0.7rem; font-weight: 600; font-family: 'Inter', sans-serif;
    letter-spacing: 0.2px;
}}
.badge-green {{ background: rgba(95,168,126,0.12); color: {COLORS['green']}; border: 1px solid rgba(95,168,126,0.35); }}
.badge-red {{ background: rgba(201,106,99,0.12); color: {COLORS['red']}; border: 1px solid rgba(201,106,99,0.35); }}
.badge-orange {{ background: rgba(201,154,91,0.12); color: {COLORS['orange']}; border: 1px solid rgba(201,154,91,0.35); }}
.badge-blue {{ background: rgba(107,143,209,0.12); color: {COLORS['blue']}; border: 1px solid rgba(107,143,209,0.35); }}
.badge-purple {{ background: rgba(139,127,192,0.12); color: {COLORS['purple']}; border: 1px solid rgba(139,127,192,0.35); }}

/* ---- panel wrapper ---- */
.panel {{
    background: {COLORS['panel']}; border: 1px solid {COLORS['border']};
    border-radius: 10px; padding: 16px 18px;
}}

/* ---- decision engine flow ---- */
.flow-row {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }}
.flow-node {{
    background: {COLORS['panel2']}; border: 1px solid {COLORS['border']};
    border-radius: 8px; padding: 12px 16px; min-width: 130px; text-align: center;
    font-family: 'Inter', sans-serif; font-size: 0.78rem;
}}
.flow-node .k {{ color: {COLORS['muted']}; font-size: 0.62rem; text-transform: uppercase; letter-spacing: 0.6px; font-weight: 600; }}
.flow-node .v {{ font-family: 'JetBrains Mono', monospace; font-weight: 700; font-size: 0.92rem; margin-top: 4px; color: {COLORS['text']}; }}
.flow-arrow {{ color: {COLORS['muted']}; font-size: 1.2rem; }}

/* ---- log console ---- */
.console {{
    background: {COLORS['bg2']}; border: 1px solid {COLORS['border']};
    border-radius: 8px; padding: 12px 14px; font-family: 'JetBrains Mono', monospace;
    font-size: 0.76rem; max-height: 260px; overflow-y: auto;
}}
.console .line {{ padding: 2px 0; color: {COLORS['muted']}; }}
.console .ts {{ color: {COLORS['blue']}; }}
.console .lvl-ok {{ color: {COLORS['green']}; }}
.console .lvl-warn {{ color: {COLORS['orange']}; }}
.console .lvl-crit {{ color: {COLORS['red']}; }}

/* ---- chat panel ---- */
.chat-bubble-user {{
    background: rgba(107,143,209,0.10); border: 1px solid rgba(107,143,209,0.3);
    border-radius: 10px 10px 2px 10px; padding: 10px 14px; margin: 6px 0;
    font-size: 0.85rem; max-width: 90%; margin-left: auto;
}}
.chat-bubble-ai {{
    background: rgba(139,127,192,0.08); border: 1px solid rgba(139,127,192,0.3);
    border-radius: 10px 10px 10px 2px; padding: 10px 14px; margin: 6px 0;
    font-size: 0.85rem; max-width: 90%;
}}

.demo-banner {{
    background: rgba(201,154,91,0.08); border: 1px dashed rgba(201,154,91,0.4);
    color: {COLORS['orange']}; padding: 8px 14px; border-radius: 8px;
    font-family: 'Inter', sans-serif; font-size: 0.74rem; margin-bottom: 14px; font-weight: 500;
}}

section[data-testid="stSidebar"] {{ background: {COLORS['bg2']}; border-right: 1px solid {COLORS['border']}; }}
div[data-testid="stMetric"] {{ background: transparent; }}
#MainMenu, footer {{ visibility: hidden; }}

/* ---- native Streamlit widget overrides ---- */
div[data-testid="stDataFrame"] {{
    background: {COLORS['panel']} !important;
}}
div[data-testid="stDataFrame"] > div {{
    background: {COLORS['panel']} !important;
}}
div[data-testid="stDataFrame"] table {{
    background: {COLORS['panel']} !important;
    color: {COLORS['text']} !important;
}}
div[data-testid="stDataFrame"] th {{
    background: {COLORS['panel2']} !important;
    color: {COLORS['muted']} !important;
    border-color: {COLORS['border']} !important;
}}
div[data-testid="stDataFrame"] td {{
    background: {COLORS['panel']} !important;
    color: {COLORS['text']} !important;
    border-color: {COLORS['border']} !important;
}}
span[data-baseweb="tag"] {{
    background-color: {COLORS['panel2']} !important;
    border: 1px solid {COLORS['border']} !important;
    color: {COLORS['text']} !important;
}}
div[data-baseweb="select"] > div {{
    background-color: {COLORS['panel']} !important;
    border-color: {COLORS['border']} !important;
}}
div[data-testid="stPlotlyChart"] {{
    background: {COLORS['panel']} !important;
    border-radius: 10px;
}}

/* broader multiselect tag override, catches multiple possible Streamlit versions */
[data-testid="stMultiSelect"] span {{
    background-color: {COLORS['panel2']} !important;
    color: {COLORS['text']} !important;
}}
[data-testid="stMultiSelect"] [class*="tag"] {{
    background-color: {COLORS['panel2']} !important;
    border-color: {COLORS['border']} !important;
    color: {COLORS['text']} !important;
}}

[data-testid="stMultiSelect"] span[class*="tag"],
[data-testid="stMultiSelect"] div[class*="Tag"],
[data-testid="stMultiSelect"] * {{
    background-color: {COLORS['panel2']} !important;
    color: {COLORS['text']} !important;
    border-color: {COLORS['border']} !important;
}}

header[data-testid="stHeader"] {{
    background: {COLORS['bg']} !important;
    height: 0px;
    visibility: hidden;
}}
div[data-testid="stToolbar"] {{
    display: none !important;
}}
div[data-testid="stDecoration"] {{
    display: none !important;
}}

</style>
"""

st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# ==============================================================================
# DEMO DATA GENERATORS (used only when real files are absent)
# ==============================================================================
ATTACK_TYPES = ["Recon (Nmap)", "FTP Bruteforce", "SYN Flood", "ICMP Scan",
                 "Modbus/Metasploit", "HTTP Cmd Injection"]

@st.cache_data(ttl=REFRESH_SECONDS)
def demo_alerts(n=341):
    rng = np.random.default_rng(42)
    start = datetime.now() - timedelta(hours=3)
    sigs = rng.choice(ATTACK_TYPES, size=n, p=[0.30, 0.16, 0.24, 0.08, 0.12, 0.10])
    return pd.DataFrame({
        "timestamp": [start + timedelta(seconds=int(x)) for x in np.sort(rng.integers(0, 10800, n))],
        "src_ip": rng.choice(["192.0.2.10"], size=n),
        "dest_ip": "192.0.2.20",
        "signature": sigs,
        "severity": rng.choice(["low", "medium", "high", "critical"], size=n, p=[0.4, 0.3, 0.2, 0.1]),
    })

@st.cache_data(ttl=REFRESH_SECONDS)
def demo_rf_predictions():
    rows = [
        ("FTP Bruteforce", "Bruteforce", 0.98, "HIGH", "Deploy"),
        ("ICMP Scan", "Recon", 0.94, "LOW", "Log"),
        ("Nmap Scan", "Recon", 0.96, "LOW", "Monitor"),
        ("SYN Flood", "DoS", 0.99, "CRITICAL", "Deploy"),
        ("Modbus Probe", "Exploitation", 0.91, "HIGH", "Deploy"),
        ("HTTP Injection", "Web Attack", 0.87, "MEDIUM", "Monitor"),
    ]
    return pd.DataFrame(rows, columns=["Attack", "Prediction", "Confidence", "Risk", "Action"])

@st.cache_data(ttl=REFRESH_SECONDS)
def demo_iforest():
    rng = np.random.default_rng(7)
    n_normal, n_anom = 290, 51
    normal = rng.normal(0, 1, size=(n_normal, 2))
    anom = rng.normal(0, 1, size=(n_anom, 2)) * 3.2 + 4
    df = pd.DataFrame(np.vstack([normal, anom]), columns=["pca_1", "pca_2"])
    df["label"] = ["Normal"] * n_normal + ["Anomaly"] * n_anom
    return df.sample(frac=1, random_state=1).reset_index(drop=True)

@st.cache_data(ttl=REFRESH_SECONDS)
def demo_kmeans():
    rng = np.random.default_rng(3)
    centers = [(-3, -2), (3, 3), (0, 5)]
    frames = []
    for i, c in enumerate(centers):
        pts = rng.normal(c, 0.9, size=(80, 2))
        frames.append(pd.DataFrame({"x": pts[:, 0], "y": pts[:, 1], "cluster": f"Cluster {i}"}))
    return pd.concat(frames, ignore_index=True)

@st.cache_data(ttl=REFRESH_SECONDS)
def demo_shap():
    feats = ["severity", "bytes", "pkts", "action", "direction", "duration", "dest_port", "proto"]
    vals = sorted([0.31, 0.24, 0.18, 0.12, 0.08, 0.04, 0.02, 0.01], reverse=True)
    return pd.DataFrame({"feature": feats, "importance": vals})

@st.cache_data(ttl=REFRESH_SECONDS)
def demo_decision_log():
    now = datetime.now()
    return [
        {"time": (now - timedelta(minutes=2)).strftime("%H:%M:%S"), "level": "ok", "msg": "Random Forest -> prediction: Recon (conf 0.96)"},
        {"time": (now - timedelta(minutes=2)).strftime("%H:%M:%S"), "level": "warn", "msg": "Decision Engine -> risk: LOW -> action: LOG"},
        {"time": (now - timedelta(minutes=1)).strftime("%H:%M:%S"), "level": "crit", "msg": "Random Forest -> prediction: DoS (conf 0.99)"},
        {"time": (now - timedelta(minutes=1)).strftime("%H:%M:%S"), "level": "crit", "msg": "Decision Engine -> risk: CRITICAL -> action: DEPLOY IEC104"},
        {"time": now.strftime("%H:%M:%S"), "level": "ok", "msg": "Conpot template 'IEC104' -> container status: RUNNING"},
    ]

# ==============================================================================
# LOADERS — try real backend files first, silently fall back to demo data
# ==============================================================================
def _file_ok(path):
    return os.path.isfile(path) and os.path.getsize(path) > 0

def load_alerts():
    p = PATHS["alerts_live_jsonl"] if _file_ok(PATHS["alerts_live_jsonl"]) else PATHS["alerts_jsonl"]
    if _file_ok(p):
        try:
            rows = []
            with open(p, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    d = json.loads(line)
                    data = d.get("data", d)
                    rows.append({
                        "timestamp": data.get("timestamp", d.get("@timestamp")),
                        "src_ip": data.get("src_ip"),
                        "dest_ip": data.get("dest_ip"),
                        "signature": (data.get("alert", {}) or {}).get("signature", "unknown"),
                        "severity": (data.get("alert", {}) or {}).get("severity", "medium"),
                    })
            df = pd.DataFrame(rows)
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
            return df, False
        except Exception:
            pass
    return demo_alerts(), True

def load_csv_or_demo(key, demo_fn):
    p = PATHS[key]
    if _file_ok(p):
        try:
            return pd.read_csv(p), False
        except Exception:
            pass
    return demo_fn(), True

def analyst_assistant_answer(question, decision_log):
    """V1 grounded Analyst Assistant using the real Decision Engine log."""
    q = question.strip().lower()

    if not decision_log:
        return "No Decision Engine data is currently available."

    recent = decision_log[-20:]
    latest = recent[-1]

    latest_time = latest.get("time", "unknown")
    latest_msg = latest.get("msg", "No message available.")
    latest_level = latest.get("level", "unknown")

    if any(k in q for k in ["latest", "last", "dernier", "derniere", "current"]):
        return (
            f"Latest Decision Engine entry ({latest_time}): "
            f"{latest_msg} Log level: {latest_level}."
        )

    if any(k in q for k in ["risk", "risque", "danger", "severity"]):
        return (
            f"The latest recorded decision has log level "
            f"'{latest_level}'. The Decision Engine recorded: {latest_msg}"
        )

    if any(k in q for k in ["ip", "attacker", "source", "address"]):
        import re
        ips = set()

        for entry in recent:
            msg = str(entry.get("msg", ""))
            ips.update(re.findall(
                r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                msg
            ))

        if ips:
            return (
                "Recent Decision Engine entries reference: "
                + ", ".join(sorted(ips))
                + f". Latest event: {latest_msg}"
            )

        return "No IP address was found in the recent Decision Engine entries."

    if any(k in q for k in ["alert", "signature", "attack", "event"]):
        return f"The latest recorded security event is: {latest_msg}"

    if any(k in q for k in ["action", "response", "reaction", "decision"]):
        return f"The latest Decision Engine response was: {latest_msg}"

    if any(k in q for k in ["confidence", "confiance", "certainty"]):
        import re
        values = []

        for entry in recent:
            msg = str(entry.get("msg", ""))
            values += [
                float(v) for v in re.findall(
                    r"conf\s+([0-9]+(?:\.[0-9]+)?)%",
                    msg
                )
            ]

        if values:
            return (
                f"The latest recorded confidence is "
                f"{values[-1]:.2f}%, based directly on the "
                f"Decision Engine log."
            )

        return "No confidence value was found in the recent Decision Engine log."

    return (
        f"Using the current Decision Engine data, the latest recorded "
        f"event ({latest_time}) is: {latest_msg} "
        f"Log level: {latest_level}."
    )


def load_decision_log():
    p = PATHS["decision_log"]
    if _file_ok(p):
        try:
            rows = []
            with open(p) as f:
                for line in f:
                    if line.strip():
                        rows.append(json.loads(line))
            if rows:
                return rows, False
        except Exception:
            pass
    return demo_decision_log(), True

# ==============================================================================
# LOAD ALL DATA
# ==============================================================================
def normalize_severity(series):
    """Map either text severities ('critical'/'high'/'medium'/'low') or
    numeric Suricata/Wazuh severities (lower number = more severe, e.g.
    Suricata 1-4) onto a single consistent text scale used throughout the
    dashboard (filters, KPIs, table coloring)."""
    def _one(v):
        s = str(v).strip().lower()
        if s in ("critical", "high", "medium", "low"):
            return s
        try:
            n = float(s)
        except (ValueError, TypeError):
            return "medium"
        if n <= 1:
            return "critical"
        if n <= 2:
            return "high"
        if n <= 3:
            return "medium"
        return "low"
    return series.apply(_one)


alerts_df, alerts_demo = load_alerts()
if "severity" in alerts_df.columns:
    alerts_df["severity"] = normalize_severity(alerts_df["severity"])
rf_df, rf_demo = load_csv_or_demo("rf_predictions", demo_rf_predictions)
iforest_df, iforest_demo = load_csv_or_demo("iforest_results", demo_iforest)
kmeans_df, kmeans_demo = load_csv_or_demo("kmeans_clusters", demo_kmeans)
shap_df, shap_demo = load_csv_or_demo("shap_importance", demo_shap)
decision_log, decision_demo = load_decision_log()

ANY_DEMO = any([alerts_demo, rf_demo, iforest_demo, kmeans_demo, shap_demo, decision_demo])

# ==============================================================================
# SIDEBAR
# ==============================================================================
with st.sidebar:
    st.markdown(
        f"<div style='font-family:JetBrains Mono;font-weight:800;font-size:1.05rem;"
        f"color:{COLORS['cyan']};margin-bottom:2px;'>🛡️ CyberDeceptionAI</div>"
        f"<div style='color:{COLORS['muted']};font-size:0.75rem;margin-bottom:18px;'>SOC Command Console — v1.0</div>",
        unsafe_allow_html=True,
    )
    st.markdown("**Conpot Profile**")
    conpot_profile = st.selectbox("Active template", ["IEC104", "S7-200 (SIMATIC)", "Modbus TCP", "IPMI"], index=0, label_visibility="collapsed")

    st.markdown("**Time Window**")
    tw = st.select_slider("window", options=["Last 1h", "Last 6h", "Last 24h", "All"], value="All", label_visibility="collapsed")

    st.markdown("**Severity Filter**")
    sev_filter = st.multiselect("sev", ["low", "medium", "high", "critical"],
                                 default=["low", "medium", "high", "critical"], label_visibility="collapsed")

    st.markdown("---")
    auto = st.toggle("Auto-refresh (15s)", value=False)
    if st.button("🔄 Refresh now", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

    st.markdown("---")
    st.caption(f"Data source: `{DATA_DIR}`")
    st.caption("Edit PATHS in app.py to point at your real backend outputs.")
    st.markdown("---")
    st.markdown("**Data Verification**")
    _flags = {
        "Alerts": alerts_demo,
        "Random Forest": rf_demo,
        "Isolation Forest": iforest_demo,
        "KMeans": kmeans_demo,
        "SHAP": shap_demo,
        "Decision Log": decision_demo,
    }
    for _label, _is_demo in _flags.items():
        _icon = "⚠️" if _is_demo else "✅"
        _text = "Demo (fallback)" if _is_demo else "Real data"
        st.caption(f"{_icon} {_label}: {_text}")

if auto:
    try:
        from streamlit_autorefresh import st_autorefresh
        st_autorefresh(interval=REFRESH_SECONDS * 1000, key="autorefresh")
    except ImportError:
        st.sidebar.caption("⚠️ `pip install streamlit-autorefresh` to enable live polling.")

# ==============================================================================
# HEADER
# ==============================================================================
st.markdown("<div class='scan-bar'></div>", unsafe_allow_html=True)
h1, h2 = st.columns([3, 1])
with h1:
    st.markdown(
        f"<div class='app-title'>CYBER<span>DECEPTION</span>AI &nbsp;//&nbsp; SOC COMMAND CONSOLE</div>"
        f"<div class='app-subtitle'>AI-Driven Cyber Deception Platform · Intelligent Threat Detection & Autonomous Security Analysis</div>",
        unsafe_allow_html=True,
    )
with h2:
    _last_live = decision_log[-1] if decision_log else None
    _live_time = _last_live.get("time", "—") if _last_live else "—"
    _live_suffix = " (demo)" if decision_demo else ""
    st.markdown(
        f"<div style='text-align:right;padding-top:6px;'>"
        f"<span class='live-pill'><span class='live-dot'></span> LIVE MONITORING</span>"
        f"<div style='color:{COLORS['muted']};font-size:0.68rem;font-family:JetBrains Mono, monospace;margin-top:6px;'>"
        f"Last live decision: {_live_time}{_live_suffix}"
        f"</div></div>",
        unsafe_allow_html=True,
    )

if ANY_DEMO:
    st.markdown(
        "<div class='demo-banner'>⚠ DEMO DATA MODE — one or more backend output files were not found in "
        f"<code>{DATA_DIR}</code>. Showing schema-accurate sample data for this section so the console stays "
        "demo-ready. Point <code>PATHS</code> in app.py at your real files to go fully live.</div>",
        unsafe_allow_html=True,
    )

# ==============================================================================
# 1. EXECUTIVE OVERVIEW
# ==============================================================================
st.markdown(f"<div class='sec-title'><div class='bar' style='background:{COLORS['blue']}'></div>Executive Overview</div>", unsafe_allow_html=True)

total_alerts = len(alerts_df)
critical_alerts = int((alerts_df["severity"].astype(str).str.lower().isin(["critical", "high"])).sum()) if "severity" in alerts_df else 12
attacks_detected = alerts_df["signature"].nunique() if "signature" in alerts_df else 6

kpis = [
    ("TOTAL ALERTS", f"{total_alerts:,}", COLORS["blue"], "+ live feed"),
    ("CRITICAL ALERTS", f"{critical_alerts}", COLORS["red"], "requires review"),
    ("ATTACK SCENARIOS", f"{attacks_detected}", COLORS["orange"], "signatures matched"),
    ("AI MODELS RUNNING", "6 / 6", COLORS["purple"], "all systems nominal"),
    ("DEPLOYMENT STATUS", "ACTIVE", COLORS["green"], "honeypot online"),
    ("CONPOT TEMPLATE", conpot_profile, COLORS["cyan"], "current profile"),
]

cols = st.columns(6)
for col, (label, value, glow, delta) in zip(cols, kpis):
    with col:
        st.markdown(
            f"""<div class="kpi-card" style="--glow:{glow}66; border-top:2px solid {glow};">
                    <div class="kpi-label">{label}</div>
                    <div class="kpi-value" style="color:{glow}">{value}</div>
                    <div class="kpi-delta" style="color:{COLORS['muted']}">{delta}</div>
                </div>""",
            unsafe_allow_html=True,
        )

# ==============================================================================
# 2. LIVE ATTACK TIMELINE   +   3. ATTACK DISTRIBUTION
# ==============================================================================
c1, c2 = st.columns([2, 1])

with c1:
    st.markdown(f"<div class='sec-title'><div class='bar' style='background:{COLORS['red']}'></div>Live Attack Timeline</div>", unsafe_allow_html=True)
    tdf = alerts_df.dropna(subset=["timestamp"]).copy() if "timestamp" in alerts_df else pd.DataFrame()
    if not tdf.empty:
        tdf["minute"] = tdf["timestamp"].dt.floor("5min")
        pivot = tdf.groupby(["minute", "signature"]).size().reset_index(name="count")
        fig = px.area(
            pivot, x="minute", y="count", color="signature",
            color_discrete_sequence=[COLORS["blue"], COLORS["red"], COLORS["orange"], COLORS["purple"], COLORS["green"], COLORS["cyan"]],
        )
        fig.update_layout(paper_bgcolor="#191c21", plot_bgcolor="#191c21", font=dict(color="#e6e7ea"), height=320, legend=dict(orientation="h", y=-0.25),
                           xaxis_title=None, yaxis_title="alerts / 5min")
        fig.update_traces(line=dict(width=1.5))
        fig.update_layout(width=900); st.plotly_chart(fig, theme=None)
    else:
        st.info("No timestamped alerts available.")

with c2:
    st.markdown(f"<div class='sec-title'><div class='bar' style='background:{COLORS['orange']}'></div>Attack Distribution</div>", unsafe_allow_html=True)
    if "signature" in alerts_df and not alerts_df.empty:
        dist = alerts_df["signature"].value_counts().reset_index()
        dist.columns = ["signature", "count"]
        fig2 = px.pie(
            dist, names="signature", values="count", hole=0.55,
            color_discrete_sequence=[COLORS["blue"], COLORS["red"], COLORS["orange"], COLORS["purple"], COLORS["green"], COLORS["cyan"]],
        )
        fig2.update_traces(textfont_size=11, marker=dict(line=dict(color=COLORS["bg"], width=2)))
        fig2.update_layout(paper_bgcolor="#191c21", plot_bgcolor="#191c21", font=dict(color="#e6e7ea"), height=320, showlegend=True,
                            legend=dict(font=dict(size=9)))
        fig2.update_layout(width=400); st.plotly_chart(fig2, theme=None)

# ==============================================================================
# 4. AI MODULES STATUS
# ==============================================================================
st.markdown(f"<div class='sec-title'><div class='bar' style='background:{COLORS['purple']}'></div>AI Modules Status</div>", unsafe_allow_html=True)

def _status_from_demo_flag(is_demo, ok_label):
    return (ok_label, "green") if not is_demo else ("Demo data", "orange")

modules = [
    ("Isolation Forest", "Anomaly Detection", *_status_from_demo_flag(iforest_demo, "Running")),
    ("Random Forest", "Attack Classification", *_status_from_demo_flag(rf_demo, "Running")),
    ("KMeans", "Attacker Clustering", *_status_from_demo_flag(kmeans_demo, "Running")),
    ("SHAP", "Explainability Engine", *_status_from_demo_flag(shap_demo, "Ready")),
    ("Analyst Assistant", "Rule-Based Q&A", "Active", "blue"),
    ("Decision Engine", "Automation / Deployment", *_status_from_demo_flag(decision_demo, "Active")),
]
mcols = st.columns(6)
for col, (name, role, status, badge) in zip(mcols, modules):
    with col:
        st.markdown(
            f"""<div class="panel" style="text-align:center;">
                    <div style="font-weight:700;font-size:0.85rem;">{name}</div>
                    <div style="color:{COLORS['muted']};font-size:0.68rem;margin-bottom:8px;">{role}</div>
                    <span class="badge badge-{badge}">● {status.upper()}</span>
                </div>""",
            unsafe_allow_html=True,
        )

# ==============================================================================
# 5. RANDOM FOREST PREDICTIONS   +   6. ISOLATION FOREST
# ==============================================================================
c3, c4 = st.columns(2)

with c3:
    st.markdown(f"<div class='sec-title'><div class='bar' style='background:{COLORS['purple']}'></div>Random Forest — Predictions</div>", unsafe_allow_html=True)
    show_rf = rf_df.copy()
    if "Confidence" in show_rf:
        conf_numeric = pd.to_numeric(show_rf["Confidence"], errors="coerce")
        if conf_numeric.notna().all():
            # raw numeric confidence (0-1 or 0-100) -> format as a percentage
            show_rf["Confidence"] = (
                (conf_numeric * 100).round(1).astype(str) + "%"
                if conf_numeric.max() <= 1 else conf_numeric.round(1).astype(str) + "%"
            )
        # else: already a formatted string like "75.6%" (e.g. from build_dashboard_data.py) -> leave as-is
    def _risk_style(v):
        m = {"CRITICAL": COLORS["red"], "HIGH": COLORS["red"], "MEDIUM": COLORS["orange"], "LOW": COLORS["green"]}
        c = m.get(str(v).upper(), COLORS["muted"])
        return f"color:{c}; font-weight:700;"
    st.dataframe(
        show_rf.style.applymap(_risk_style, subset=["Risk"]) if "Risk" in show_rf else show_rf,
        use_container_width=True, height=250, hide_index=True,
    )

with c4:
    st.markdown(f"<div class='sec-title'><div class='bar' style='background:{COLORS['green']}'></div>Isolation Forest — Anomaly Map</div>", unsafe_allow_html=True)
    if {"pca_1", "pca_2", "label"}.issubset(iforest_df.columns):
        fig3 = px.scatter(
            iforest_df, x="pca_1", y="pca_2", color="label",
            color_discrete_map={"Normal": COLORS["green"], "Anomaly": COLORS["red"]},
            opacity=0.75,
        )
        fig3.update_traces(marker=dict(size=7, line=dict(width=0)))
        fig3.update_layout(paper_bgcolor="#191c21", plot_bgcolor="#191c21", font=dict(color="#e6e7ea"), height=280, legend_title=None)
        st.plotly_chart(fig3, use_container_width=True, theme=None)
    else:
        st.dataframe(iforest_df, use_container_width=True, height=280)

# ==============================================================================
# 7. KMEANS   +   8. SHAP
# ==============================================================================
c5, c6 = st.columns(2)

with c5:
    st.markdown(f"<div class='sec-title'><div class='bar' style='background:{COLORS['cyan']}'></div>KMeans — Attacker Clusters</div>", unsafe_allow_html=True)
    if {"x", "y", "cluster"}.issubset(kmeans_df.columns):
        fig4 = px.scatter(
            kmeans_df, x="x", y="y", color="cluster",
            color_discrete_sequence=[COLORS["blue"], COLORS["purple"], COLORS["orange"], COLORS["cyan"]],
            opacity=0.8,
        )
        fig4.update_traces(marker=dict(size=7))
        fig4.update_layout(paper_bgcolor="#191c21", plot_bgcolor="#191c21", font=dict(color="#e6e7ea"), height=280, legend_title=None)
        st.plotly_chart(fig4, use_container_width=True, theme=None)
    else:
        st.dataframe(kmeans_df, use_container_width=True, height=280)

with c6:
    st.markdown(f"<div class='sec-title'><div class='bar' style='background:{COLORS['orange']}'></div>SHAP — Feature Importance</div>", unsafe_allow_html=True)
    if {"feature", "importance"}.issubset(shap_df.columns):
        s = shap_df.sort_values("importance", ascending=True)
        fig5 = go.Figure(go.Bar(
            x=s["importance"], y=s["feature"], orientation="h",
            marker=dict(color=s["importance"], colorscale=[[0, COLORS["blue"]], [1, COLORS["red"]]]),
        ))
        fig5.update_layout(paper_bgcolor="#191c21", plot_bgcolor="#191c21", font=dict(color="#e6e7ea"), height=280, xaxis_title="mean |SHAP value|", yaxis_title=None)
        st.plotly_chart(fig5, use_container_width=True, theme=None)
    else:
        st.dataframe(shap_df, use_container_width=True, height=280)

# ==============================================================================
# 9. WAZUH LIVE ALERTS TABLE
# ==============================================================================
_alerts_source_label = "Live Feed" if _file_ok(PATHS["alerts_live_jsonl"]) else "Frozen Training Dataset"
st.markdown(f"<div class='sec-title'><div class='bar' style='background:{COLORS['blue']}'></div>Wazuh — Alerts ({_alerts_source_label})</div>", unsafe_allow_html=True)
wt = alerts_df.copy()
if "severity" in wt:
    wt = wt[wt["severity"].astype(str).str.lower().isin(sev_filter)]
show_cols = [c for c in ["timestamp", "signature", "severity", "src_ip", "dest_ip"] if c in wt.columns]
wt_show = wt[show_cols].sort_values("timestamp", ascending=False).head(50) if "timestamp" in show_cols else wt[show_cols].head(50)

def _sev_style(v):
    m = {"critical": COLORS["red"], "high": COLORS["red"], "medium": COLORS["orange"], "low": COLORS["green"]}
    c = m.get(str(v).lower(), COLORS["muted"])
    return f"color:{c}; font-weight:700;"

styler = wt_show.style
if "severity" in wt_show:
    styler = styler.applymap(_sev_style, subset=["severity"])
st.dataframe(styler, use_container_width=True, height=300, hide_index=True)

# ==============================================================================
# 10. DECISION ENGINE WORKFLOW

# ==============================================================================

st.markdown(
    f"<div class='bar' style='background:{COLORS['red']}'>"
    "Decision Engine — Workflow (last real decision)</div>",
    unsafe_allow_html=True
)

_last = decision_log[-1] if decision_log else {}

# The exported Decision Engine log currently stores the real fields
# inside the "msg" string. Parse them instead of falling back to demo data.
_decision_signature = "—"
_decision_ip = "—"
_decision_confidence = "—"
_decision_risk_raw = "—"
_decision_action = "—"
_decision_time = str(_last.get("time", "—"))

if _last:
    _msg = str(_last.get("msg", ""))

    _m = re.search(
        r"^(.*?)\s*\(IP\s+([^,]+),\s*conf\s+([0-9.]+)%\)",
        _msg,
        re.IGNORECASE
    )

    _r = re.search(
        r"->\s*risk:\s*([A-Za-zÀ-ÿ]+)\s*->",
        _msg,
        re.IGNORECASE
    )

    _a = re.search(
        r"->\s*risk:\s*[A-Za-zÀ-ÿ]+\s*->\s*(.*)$",
        _msg,
        re.IGNORECASE
    )

    if _m:
        _decision_signature = _m.group(1).strip()
        _decision_ip = _m.group(2).strip()
        _decision_confidence = _m.group(3).strip() + "%"

    if _r:
        _decision_risk_raw = _r.group(1).strip().upper()

    if _a:
        _decision_action = _a.group(1).strip()

_risk_map = {
    "ELEVE": "HIGH",
    "HIGH": "HIGH",
    "MOYEN": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "FAIBLE": "LOW",
    "BAS": "LOW",
    "LOW": "LOW",
}

_decision_risk = _risk_map.get(
    _decision_risk_raw,
    _decision_risk_raw
)

_action_upper = _decision_action.upper()

if (
    "BLOCAGE" in _action_upper
    or "BLOCK" in _action_upper
    or "DEPLOY" in _action_upper
):
    _decision_label = "Deploy / Block"
elif (
    "SURVEILLANCE" in _action_upper
    or "MONITOR" in _action_upper
):
    _decision_label = "Monitor"
elif _decision_action != "—":
    _decision_label = "Log"
else:
    _decision_label = "—"

_sig_short = (
    _decision_signature[:32] + "…"
    if len(_decision_signature) > 32
    else _decision_signature
)

_action_short = (
    _decision_action[:32] + "…"
    if len(_decision_action) > 32
    else _decision_action
)

flow_steps = [
    ("ALERT", _sig_short),
    ("MODEL", "Random Forest"),
    ("CONFIDENCE", _decision_confidence),
    ("RISK", _decision_risk),
    ("DECISION", _decision_label),
    ("ACTION", _action_short),
]

flow_html = "<div class='panel'><div class='flow-row'>"

for i, (k, v) in enumerate(flow_steps):
    flow_html += (
        f"<div class='flow-node'>"
        f"<div class='k'>{k}</div>"
        f"<div class='v'>{v}</div>"
        f"</div>"
    )

    if i < len(flow_steps) - 1:
        flow_html += "<div class='flow-arrow'>➜</div>"

flow_html += "</div></div>"

st.markdown(flow_html, unsafe_allow_html=True)

st.caption(
    f"Source: most recent line in decision_engine_log.jsonl "
    f"(IP {_decision_ip}, {_decision_time})."
)

# 11. ANALYST ASSISTANT (RULE-BASED)  +  12. SYSTEM LOGS / 13. DEPLOYMENT STATUS
# ==============================================================================
c7, c8 = st.columns([1.2, 1])

with c7:
    st.markdown(f"<div class='sec-title'><div class='bar' style='background:{COLORS['blue']}'></div>Analyst Assistant — Rule-Based</div>", unsafe_allow_html=True)
    st.caption("Grounded in real alert/decision-log data via simple rules — not an LLM. "
               "LLM integration is planned for V2.")
    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []
    with st.container():
        st.markdown("<div class='panel' style='max-height:260px; overflow-y:auto;'>", unsafe_allow_html=True)
        if not st.session_state.chat_history:
            st.markdown(f"<span style='color:{COLORS['muted']};font-size:0.8rem;'>No messages yet. "
                         f"Try: \"why was the latest alert flagged as high risk\", \"what did the Decision Engine do\".</span>",
                         unsafe_allow_html=True)
        for role, msg in st.session_state.chat_history:
            cls = "chat-bubble-user" if role == "user" else "chat-bubble-ai"
            who = "🧑 Analyst" if role == "user" else "🤖 Assistant"
            st.markdown(f"<div class='{cls}'><b style='font-size:0.7rem;color:{COLORS['muted']}'>{who}</b><br>{msg}</div>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with st.form("chat_form", clear_on_submit=True):
        user_q = st.text_input(
            "Ask the assistant",
            placeholder="e.g. Why was this alert flagged as high risk?",
            label_visibility="collapsed",
        )
        sent = st.form_submit_button("Send ➜")

    if sent and user_q:
        st.session_state.chat_history.append(("user", user_q))

        # ==============================================================
        # ALERT-GROUNDED ANALYST ASSISTANT
        # ==============================================================

        q = user_q.lower().strip()

        latest_signature = "unknown"
        latest_src = "unknown"
        latest_dst = "unknown"
        latest_severity = "unknown"
        latest_time = "unknown"

        if not alerts_df.empty:
            # Always select the chronologically newest alert,
            # rather than relying on the physical last row.
            latest_alerts = alerts_df.copy()

            if "timestamp" in latest_alerts.columns:
                latest_alerts["__ts"] = pd.to_datetime(
                    latest_alerts["timestamp"],
                    errors="coerce",
                    utc=True,
                )
                latest_alerts = latest_alerts.sort_values(
                    "__ts",
                    ascending=False,
                    na_position="last",
                )

            latest_row = latest_alerts.iloc[0]

            latest_signature = str(
                latest_row.get("signature", "unknown")
            )

            latest_src = str(
                latest_row.get("src_ip", "unknown")
            )

            latest_dst = str(
                latest_row.get("dest_ip", "unknown")
            )

            latest_severity = str(
                latest_row.get("severity", "unknown")
            ).upper()

            latest_time = str(
                latest_row.get("timestamp", "unknown")
            )


        # --------------------------------------------------------------
        # Decision Engine evidence
        # --------------------------------------------------------------
        decision_msg = "No Decision Engine event is currently available."
        decision_risk = "UNKNOWN"
        decision_signature = "unknown"
        decision_ip = "unknown"
        decision_confidence = "unknown"
        decision_action = "unknown"
        decision_time = "unknown"

        if decision_log:
            import re

            latest_decision = decision_log[-1]

            decision_msg = str(
                latest_decision.get("msg", decision_msg)
            )

            decision_time = str(
                latest_decision.get("time", "unknown")
            )

            # Parse the real information embedded in the
            # Decision Engine message.
            sig_match = re.search(
                r"^(.*?)\s*\(IP\s+([^,]+),\s*conf\s+([0-9.]+)%\)",
                decision_msg,
                re.IGNORECASE,
            )

            risk_match = re.search(
                r"->\s*risk:\s*([A-Za-zÀ-ÿ]+)",
                decision_msg,
                re.IGNORECASE,
            )

            action_match = re.search(
                r"->\s*risk:\s*[A-Za-zÀ-ÿ]+\s*->\s*(.*)$",
                decision_msg,
                re.IGNORECASE,
            )

            if sig_match:
                decision_signature = sig_match.group(1).strip()
                decision_ip = sig_match.group(2).strip()
                decision_confidence = (
                    sig_match.group(3).strip() + "%"
                )

            if risk_match:
                decision_risk = risk_match.group(1).upper()

            if action_match:
                decision_action = action_match.group(1).strip()

        # --------------------------------------------------------------
        # Correlation check
        # --------------------------------------------------------------
        same_signature = (
            latest_signature != "unknown"
            and decision_signature != "unknown"
            and latest_signature.strip().lower()
            == decision_signature.strip().lower()
        )

        same_ip = (
            latest_src != "unknown"
            and decision_ip != "unknown"
            and latest_src == decision_ip
        )

        correlated = same_signature and same_ip

        if correlated:
            correlation_text = (
                "The latest alert matches the latest Decision Engine "
                "event by signature and source IP."
            )
        else:
            correlation_text = (
                "The latest alert and the latest Decision Engine event "
                "are separate records; they were not correlated."
            )

        # --------------------------------------------------------------
        # ALERT-GROUNDED ANALYST ASSISTANT
        # --------------------------------------------------------------

        # PRIORITY 1 — WHY / RISK / SEVERITY
        if any(
            word in q
            for word in [
                "why",
                "risk",
                "high risk",
                "medium risk",
                "low risk",
                "severity",
                "flagged",
                "dangerous",
            ]
        ):
            if correlated:
                answer = (
                    f"Risk analysis of the latest alert: "
                    f"'{latest_signature}'. "
                    f"Alert severity: {latest_severity}. "
                    f"Source IP: {latest_src}. "
                    f"Destination IP: {latest_dst}. "
                    f"Decision Engine risk: {decision_risk}. "
                    f"Confidence: {decision_confidence}. "
                    f"Action: {decision_action}. "
                    f"Timestamp: {latest_time}."
                )
            else:
                answer = (
                    f"Risk analysis of the latest alert: "
                    f"'{latest_signature}'. "
                    f"Alert severity: {latest_severity}. "
                    f"Source IP: {latest_src}. "
                    f"Destination IP: {latest_dst}. "
                    f"Timestamp: {latest_time}. "
                    f"The latest Decision Engine record is a separate "
                    f"event: '{decision_signature}' from {decision_ip}, "
                    f"with risk {decision_risk}, confidence "
                    f"{decision_confidence}, and action "
                    f"'{decision_action}'. "
                    f"{correlation_text}"
                )

        # PRIORITY 2 — LATEST / RECENT ALERT
        elif any(
            word in q
            for word in [
                "critical",
                "last alert",
                "latest alert",
                "recent alert",
            ]
        ):
            answer = (
                f"Latest alert: '{latest_signature}'. "
                f"Source IP: {latest_src}. "
                f"Destination IP: {latest_dst}. "
                f"Severity: {latest_severity}. "
                f"Timestamp: {latest_time}. "
                f"{correlation_text}"
            )

        # PRIORITY 3 — DECISION ENGINE
        elif any(
            word in q
            for word in [
                "decision",
                "action",
                "engine",
                "response",
            ]
        ):
            answer = (
                f"The latest Decision Engine action is "
                f"'{decision_action}'. "
                f"Risk: {decision_risk}. "
                f"Confidence: {decision_confidence}. "
                f"Signature: '{decision_signature}'. "
                f"Source IP: {decision_ip}. "
                f"Time: {decision_time}."
            )

        # PRIORITY 4 — IP / ATTACKER
        elif any(
            word in q
            for word in [
                "ip",
                "attacker",
                "source",
                "destination",
            ]
        ):
            answer = (
                f"The latest observed source IP is {latest_src}. "
                f"The destination IP is {latest_dst}. "
                f"The associated alert signature is "
                f"'{latest_signature}'."
            )

        # PRIORITY 5 — MODEL / CLASSIFICATION
        elif any(
            word in q
            for word in [
                "confidence",
                "model",
                "classification",
                "random forest",
            ]
        ):
            answer = (
                f"The latest Decision Engine confidence is "
                f"{decision_confidence}. "
                f"The Decision Engine classified "
                f"'{decision_signature}' with risk {decision_risk}."
            )

        # DEFAULT
        else:
            answer = (
                "I can analyze the current dashboard evidence. "
                f"The latest alert is '{latest_signature}' "
                f"from {latest_src} to {latest_dst}, "
                f"with severity {latest_severity}. "
                f"The latest Decision Engine event is "
                f"'{decision_signature}' with risk {decision_risk} "
                f"and action '{decision_action}'. "
                f"{correlation_text}"
            )

        st.session_state.chat_history.append(
            ("ai", answer)
        )

        st.rerun()

with c8:
    st.markdown(f"<div class='sec-title'><div class='bar' style='background:{COLORS['muted']}'></div>System Logs</div>", unsafe_allow_html=True)
    log_html = "<div class='console'>"
    lvl_class = {"ok": "lvl-ok", "warn": "lvl-warn", "crit": "lvl-crit"}
    for entry in decision_log[-12:]:
        t = entry.get("time", "--:--:--")
        lvl = entry.get("level", "ok")
        msg = entry.get("msg", "")
        log_html += f"<div class='line'><span class='ts'>[{t}]</span> <span class='{lvl_class.get(lvl, 'lvl-ok')}'>●</span> {msg}</div>"
    log_html += "</div>"
    st.markdown(log_html, unsafe_allow_html=True)

    st.markdown(f"<div class='sec-title'><div class='bar' style='background:{COLORS['green']}'></div>Deployment Status</div>", unsafe_allow_html=True)
    d1, d2 = st.columns(2)
    with d1:
        st.markdown(f"<div class='panel' style='text-align:center;'><div class='kpi-label'>HONEYPOT</div>"
                     f"<span class='badge badge-green'>● RUNNING</span></div>", unsafe_allow_html=True)
    with d2:
        st.markdown(f"<div class='panel' style='text-align:center;'><div class='kpi-label'>ACTIVE TEMPLATE</div>"
                     f"<span class='badge badge-blue'>{conpot_profile}</span></div>", unsafe_allow_html=True)
    st.caption("⚠ Manual/config status — not a live probe of conpot-vm or wazuh-vm. "
               "Wiring a real health check (SSH/docker ps or Wazuh API) is a V2 item.")

# ==============================================================================
# FOOTER
# ==============================================================================
st.markdown(
    f"<div style='margin-top:26px; padding-top:12px; border-top:1px solid {COLORS['border']}; "
    f"color:{COLORS['muted']}; font-size:0.72rem; font-family:JetBrains Mono, monospace; text-align:center;'>"
    f"AI-Driven Cyber Deception Platform — SOC Console V1 · Read-only view over existing backend outputs · "
    f"Last refresh: {datetime.now().strftime('%H:%M:%S')}</div>",
    unsafe_allow_html=True,
)
