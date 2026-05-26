from __future__ import annotations

import plotly.express as px
import streamlit as st

from dashboard.common import (
    SEVERITY_COLORS,
    THREAT_COLORS,
    compute_soc_metrics,
    inject_console_theme,
    load_alerts,
    load_events,
    load_metrics,
    metric_card,
    percent,
)


inject_console_theme()
st.title("Overview")
events = load_events()
alerts = load_alerts()
soc = compute_soc_metrics(events, alerts, load_metrics())

cards = [
    metric_card("Events Processed", soc["event_count"], f"Normal baseline: {percent(soc['normal_ratio'])}", "risk-ok"),
    metric_card("Alerts Generated", soc["alert_count"], f"Event alert rate: {percent(soc['alert_rate'])}", "risk-medium"),
    metric_card("Incidents", soc["incident_count"], "Grouped analyst workload", "risk-medium"),
    metric_card("Critical Events", soc["critical_count"], f"Escalation rate: {percent(soc['escalation_rate'])}", "risk-critical" if soc["critical_count"] else "risk-ok"),
]
st.markdown(f"<div class='metric-grid'>{''.join(cards)}</div>", unsafe_allow_html=True)

if events.empty:
    st.info("No events available.")
else:
    st.subheader("Telemetry Timeline")
    time_frame = events.copy()
    time_frame["timestamp"] = time_frame["timestamp"].astype("datetime64[ns, UTC]", errors="ignore")
    fig = px.histogram(
        time_frame,
        x="timestamp",
        color="label",
        color_discrete_map=THREAT_COLORS,
        nbins=32,
    )
    fig.update_layout(bargap=0.08, margin=dict(l=0, r=0, t=16, b=0), height=360)
    st.plotly_chart(fig, use_container_width=True)

if not alerts.empty:
    left, right = st.columns(2)
    left.subheader("Severity Distribution")
    counts = alerts["severity"].value_counts().reset_index()
    counts.columns = ["severity", "count"]
    fig = px.bar(counts, x="severity", y="count", color="severity", color_discrete_map=SEVERITY_COLORS)
    fig.update_layout(showlegend=False, margin=dict(l=0, r=0, t=16, b=0), height=320)
    left.plotly_chart(fig, use_container_width=True)
    right.subheader("Threat Distribution")
    threat_counts = alerts["threat_type"].value_counts().reset_index()
    threat_counts.columns = ["threat_type", "count"]
    right.plotly_chart(
        px.treemap(threat_counts, path=["threat_type"], values="count", color="threat_type", color_discrete_map=THREAT_COLORS),
        use_container_width=True,
    )
