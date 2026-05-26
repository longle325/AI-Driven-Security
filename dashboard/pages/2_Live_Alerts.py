from __future__ import annotations

import streamlit as st

from dashboard.common import alert_worklist, incident_frame, inject_console_theme, load_alerts


inject_console_theme()
st.title("Live Alerts")
alerts = load_alerts()

if alerts.empty:
    st.info("No alerts generated yet.")
    st.stop()

threats = ["All", *sorted(alerts["threat_type"].dropna().unique().tolist())]
severities = ["All", *sorted(alerts["severity"].dropna().unique().tolist())]
threat = st.selectbox("Threat Type", threats)
severity = st.selectbox("Severity", severities)
query = st.text_input("Search source IP or endpoint")

filtered = alerts.copy()
if threat != "All":
    filtered = filtered[filtered["threat_type"] == threat]
if severity != "All":
    filtered = filtered[filtered["severity"] == severity]
if query:
    mask = filtered["source_ip"].astype(str).str.contains(query, case=False, na=False) | filtered[
        "endpoint"
    ].astype(str).str.contains(query, case=False, na=False)
    filtered = filtered[mask]

tab1, tab2 = st.tabs(["Incident Queue", "Event Alerts"])

with tab1:
    incidents = incident_frame(filtered)
    st.dataframe(incidents, use_container_width=True, hide_index=True)

with tab2:
    st.dataframe(alert_worklist(filtered), use_container_width=True, hide_index=True)

if not filtered.empty:
    selected = st.selectbox("Alert Details", filtered["alert_id"].tolist())
    record = filtered[filtered["alert_id"] == selected].iloc[0].to_dict()
    st.json(record)
    st.markdown(f"<div class='notice'>{record.get('recommended_action', 'No recommendation available.')}</div>", unsafe_allow_html=True)
