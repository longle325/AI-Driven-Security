from __future__ import annotations

import plotly.express as px
import streamlit as st

from dashboard.common import SEVERITY_COLORS, latest_value, load_alerts, load_events, load_metrics


st.set_page_config(
    page_title="AI Cyber Defense Lab",
    page_icon="shield",
    layout="wide",
)

st.markdown(
    """
    <style>
      .block-container { padding-top: 1.5rem; }
      [data-testid="stMetric"] {
        border: 1px solid #d0d7de;
        border-radius: 8px;
        padding: 14px 16px;
        background: #ffffff;
      }
      .pipeline {
        border: 1px solid #d0d7de;
        border-radius: 8px;
        padding: 16px;
        background: #f6f8fa;
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
        line-height: 1.8;
      }
    </style>
    """,
    unsafe_allow_html=True,
)

events = load_events()
alerts = load_alerts()
metrics = load_metrics()

st.title("AI-Driven Cyber Defense Lab")

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Events", len(events))
col2.metric("Alerts", len(alerts))
critical_high = 0 if alerts.empty else alerts["severity"].isin(["critical", "high"]).sum()
col3.metric("High/Critical", int(critical_high))
col4.metric("Macro F1", metrics.get("macro_f1", "n/a"))
col5.metric("Last Detection", latest_value(alerts, "timestamp"))

left, right = st.columns([1.1, 1])
with left:
    st.subheader("Detection Pipeline")
    st.markdown(
        """
        <div class="pipeline">
        Lab Web App + Simulator -> JSONL Logs -> Preprocessing<br>
        -> Rule Detector + Random Forest -> Alert Manager<br>
        -> Streamlit Dashboard + Evidence Export
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.subheader("Latest Alerts")
    if alerts.empty:
        st.info("No alerts generated yet. Run `make simulate-mixed` and `make detect`.")
    else:
        st.dataframe(alerts.tail(10), use_container_width=True, hide_index=True)

with right:
    st.subheader("Alerts by Severity")
    if alerts.empty:
        st.info("No severity data available.")
    else:
        severity_counts = alerts["severity"].value_counts().reset_index()
        severity_counts.columns = ["severity", "count"]
        fig = px.bar(
            severity_counts,
            x="severity",
            y="count",
            color="severity",
            color_discrete_map=SEVERITY_COLORS,
        )
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Alerts by Threat Type")
    if alerts.empty:
        st.info("No threat data available.")
    else:
        threat_counts = alerts["threat_type"].value_counts().reset_index()
        threat_counts.columns = ["threat_type", "count"]
        st.plotly_chart(px.pie(threat_counts, names="threat_type", values="count"), use_container_width=True)
