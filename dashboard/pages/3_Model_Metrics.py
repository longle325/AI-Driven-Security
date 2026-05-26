from __future__ import annotations

from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from dashboard.common import inject_console_theme, load_alerts, load_metrics, metric_card
from src.config import MODELS_DIR


inject_console_theme()
st.title("Model Metrics")
metrics = load_metrics()

if not metrics:
    st.info("No model metrics found. Run `make train`.")
else:
    cards = [
        metric_card("Accuracy", metrics.get("accuracy", "n/a"), f"{metrics.get('test_rows', 'n/a')} held-out rows", "risk-ok"),
        metric_card("Precision", metrics.get("precision_macro", "n/a"), "Macro average", "risk-ok"),
        metric_card("Recall", metrics.get("recall_macro", "n/a"), "Macro average", "risk-ok"),
        metric_card("Macro F1", metrics.get("macro_f1", "n/a"), "Synthetic validation", "risk-ok"),
    ]
    st.markdown(f"<div class='metric-grid'>{''.join(cards)}</div>", unsafe_allow_html=True)
    if metrics.get("macro_f1") == 1.0:
        st.markdown(
            "<div class='notice'>Perfect score is expected in a separable synthetic lab. Treat it as pipeline validation, not real-world model quality.</div>",
            unsafe_allow_html=True,
        )

report_path = MODELS_DIR / "classification_report.txt"
if report_path.exists():
    st.subheader("Classification Report")
    st.code(report_path.read_text(encoding="utf-8"))

matrix_path = MODELS_DIR / "confusion_matrix.png"
if matrix_path.exists():
    st.subheader("Confusion Matrix")
    st.image(str(matrix_path))

importance_path = MODELS_DIR / "feature_importance.csv"
if importance_path.exists():
    importance = pd.read_csv(importance_path).head(10)
    st.subheader("Feature Importance")
    fig = px.bar(importance, x="importance", y="feature", orientation="h", color="importance", color_continuous_scale="Teal")
    fig.update_layout(coloraxis_showscale=False, margin=dict(l=0, r=0, t=16, b=0), height=360)
    st.plotly_chart(fig, use_container_width=True)

alerts = load_alerts()
if not alerts.empty and "ml_result" in alerts:
    st.subheader("Rule-Based vs ML Comparison")
    rows = []
    for alert in alerts.to_dict("records"):
        rows.append(
            {
                "alert_id": alert.get("alert_id"),
                "rule_threat": bool(alert.get("rule_result", {}).get("is_threat")),
                "ml_label": alert.get("ml_result", {}).get("predicted_label"),
                "ml_confidence": alert.get("ml_result", {}).get("confidence"),
            }
        )
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
