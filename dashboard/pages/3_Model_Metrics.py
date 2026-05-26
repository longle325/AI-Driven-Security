from __future__ import annotations

from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from dashboard.common import load_alerts, load_metrics
from src.config import MODELS_DIR


st.title("Model Metrics")
metrics = load_metrics()

if not metrics:
    st.info("No model metrics found. Run `make train`.")
else:
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Accuracy", metrics.get("accuracy", "n/a"))
    col2.metric("Precision", metrics.get("precision_macro", "n/a"))
    col3.metric("Recall", metrics.get("recall_macro", "n/a"))
    col4.metric("Macro F1", metrics.get("macro_f1", "n/a"))

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
    st.plotly_chart(px.bar(importance, x="importance", y="feature", orientation="h"), use_container_width=True)

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
