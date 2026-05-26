from __future__ import annotations

import streamlit as st

from dashboard.common import load_alerts


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

st.dataframe(filtered, use_container_width=True, hide_index=True)

if not filtered.empty:
    selected = st.selectbox("Alert Details", filtered["alert_id"].tolist())
    record = filtered[filtered["alert_id"] == selected].iloc[0].to_dict()
    st.json(record)
    st.info(record.get("recommended_action", "No recommendation available."))
