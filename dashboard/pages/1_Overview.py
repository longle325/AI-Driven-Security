from __future__ import annotations

import plotly.express as px
import streamlit as st

from dashboard.common import SEVERITY_COLORS, load_alerts, load_events


st.title("Overview")
events = load_events()
alerts = load_alerts()

col1, col2, col3 = st.columns(3)
col1.metric("Events Processed", len(events))
col2.metric("Alerts Generated", len(alerts))
col3.metric("Threat Types", 0 if alerts.empty else alerts["threat_type"].nunique())

if events.empty:
    st.info("No events available. Generate data with `make simulate-mixed`.")
else:
    st.subheader("Events Over Time")
    time_frame = events.copy()
    time_frame["timestamp"] = time_frame["timestamp"].astype(str)
    st.plotly_chart(px.histogram(time_frame, x="timestamp", color="label"), use_container_width=True)

if not alerts.empty:
    st.subheader("Severity Distribution")
    counts = alerts["severity"].value_counts().reset_index()
    counts.columns = ["severity", "count"]
    st.plotly_chart(
        px.bar(counts, x="severity", y="count", color="severity", color_discrete_map=SEVERITY_COLORS),
        use_container_width=True,
    )
