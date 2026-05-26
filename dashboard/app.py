from __future__ import annotations

import plotly.express as px
import streamlit as st

from dashboard.common import (
    SEVERITY_COLORS,
    THREAT_COLORS,
    alert_worklist,
    compute_soc_metrics,
    incident_frame,
    inject_console_theme,
    metric_card,
    percent,
    quality_notices,
    load_alerts,
    load_events,
    load_metrics,
)


st.set_page_config(
    page_title="AI Cyber Defense Lab",
    page_icon="shield",
    layout="wide",
)

inject_console_theme()

events = load_events()
alerts = load_alerts()
metrics = load_metrics()
soc = compute_soc_metrics(events, alerts, metrics)
incidents = incident_frame(alerts)

st.markdown(
    """
    <section class="console-header">
      <div class="console-title">AI-Driven Cyber Defense Lab</div>
      <div class="console-subtitle">SOC analyst console for synthetic lab telemetry, model validation, evidence, and defensive recommendations.</div>
    </section>
    """,
    unsafe_allow_html=True,
)

cards = [
    metric_card("Telemetry", soc["event_count"], f"{soc['normal_count']} normal baseline events", "risk-ok"),
    metric_card("Event Alerts", soc["alert_count"], f"{percent(soc['alert_rate'])} event-level detection rate", "risk-high" if soc["alert_rate"] > 0.5 else "risk-medium"),
    metric_card("Incidents", soc["incident_count"], "Grouped by source, threat, and severity", "risk-medium"),
    metric_card("Critical", soc["critical_count"], f"{percent(soc['escalation_rate'])} of generated alerts", "risk-critical" if soc["critical_count"] else "risk-ok"),
    metric_card("Sources", soc["source_count"], "Distinct suspicious local IPs", "risk-medium" if soc["source_count"] else "risk-ok"),
    metric_card("Macro F1", metrics.get("macro_f1", "n/a"), "Synthetic validation benchmark", "risk-ok"),
]
st.markdown(f"<div class='metric-grid'>{''.join(cards)}</div>", unsafe_allow_html=True)

for notice in quality_notices(soc):
    st.markdown(f"<div class='notice'>{notice}</div>", unsafe_allow_html=True)

st.markdown(
    f"""
    <div class="pipeline-row">
      <div class="pipeline-node"><b>Ingest</b>{soc['event_count']} JSONL records</div>
      <div class="pipeline-node"><b>Engineer</b>13 model features</div>
      <div class="pipeline-node"><b>Rules</b>R001-R006 transparent logic</div>
      <div class="pipeline-node"><b>ML</b>Random Forest classifier</div>
      <div class="pipeline-node"><b>Evidence</b>{soc['alert_count']} alert records</div>
    </div>
    """,
    unsafe_allow_html=True,
)

left, center, right = st.columns([1.15, 1, 1])
with left:
    st.subheader("Incident Workload")
    if incidents.empty:
        st.info("No incidents available.")
    else:
        st.dataframe(incidents.head(12), use_container_width=True, hide_index=True)

with center:
    st.subheader("Class Mix")
    if events.empty or "label" not in events:
        st.info("No event labels available.")
    else:
        class_counts = events["label"].value_counts().reset_index()
        class_counts.columns = ["label", "count"]
        fig = px.bar(
            class_counts,
            x="count",
            y="label",
            orientation="h",
            color="label",
            color_discrete_map=THREAT_COLORS,
        )
        fig.update_layout(showlegend=False, margin=dict(l=0, r=0, t=12, b=0), height=330)
        st.plotly_chart(fig, use_container_width=True)

with right:
    st.subheader("Severity Mix")
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
        fig.update_layout(showlegend=False, margin=dict(l=0, r=0, t=12, b=0), height=330)
        st.plotly_chart(fig, use_container_width=True)

st.subheader("Alert Worklist")
worklist = alert_worklist(alerts)
if worklist.empty:
    st.info("No alerts available.")
else:
    st.dataframe(worklist.tail(25), use_container_width=True, hide_index=True)
