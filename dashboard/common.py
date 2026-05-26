from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from src.config import ALERTS_JSONL, EVENTS_JSONL, MODELS_DIR
from src.io_utils import read_jsonl


SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]
SEVERITY_COLORS = {
    "critical": "#9f1d20",
    "high": "#c24a1a",
    "medium": "#b98116",
    "low": "#176b87",
    "informational": "#697586",
}
THREAT_COLORS = {
    "normal": "#2f7d57",
    "brute_force": "#b42318",
    "web_attack": "#7a271a",
    "port_scan": "#0e7490",
    "traffic_spike": "#9a6700",
}


def load_jsonl_frame(path: Path) -> pd.DataFrame:
    rows = read_jsonl(path)
    return pd.DataFrame(rows)


def load_events() -> pd.DataFrame:
    return load_jsonl_frame(EVENTS_JSONL)


def load_alerts() -> pd.DataFrame:
    return load_jsonl_frame(ALERTS_JSONL)


def load_metrics() -> dict:
    path = MODELS_DIR / "metrics.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def latest_value(frame: pd.DataFrame, column: str, default: str = "n/a") -> str:
    if frame.empty or column not in frame:
        return default
    value = frame[column].dropna().tail(1)
    return str(value.iloc[0]) if not value.empty else default


def percent(value: float) -> str:
    return f"{value * 100:.1f}%"


def compute_soc_metrics(events: pd.DataFrame, alerts: pd.DataFrame, metrics: dict[str, Any]) -> dict[str, Any]:
    event_count = int(len(events))
    alert_count = int(len(alerts))
    normal_count = int((events.get("label") == "normal").sum()) if "label" in events else 0
    threat_event_count = max(event_count - normal_count, 0)

    if alerts.empty:
        incident_count = 0
        critical_count = 0
        high_count = 0
        source_count = 0
    else:
        group_columns = [column for column in ["source_ip", "threat_type", "severity"] if column in alerts]
        incident_count = int(alerts[group_columns].drop_duplicates().shape[0]) if group_columns else alert_count
        critical_count = int((alerts.get("severity") == "critical").sum()) if "severity" in alerts else 0
        high_count = int((alerts.get("severity") == "high").sum()) if "severity" in alerts else 0
        source_count = int(alerts["source_ip"].nunique()) if "source_ip" in alerts else 0

    alert_rate = alert_count / event_count if event_count else 0.0
    normal_ratio = normal_count / event_count if event_count else 0.0
    escalation_rate = critical_count / alert_count if alert_count else 0.0
    macro_f1 = metrics.get("macro_f1")
    synthetic_score = isinstance(macro_f1, int | float) and float(macro_f1) >= 0.99
    return {
        "event_count": event_count,
        "alert_count": alert_count,
        "incident_count": incident_count,
        "normal_count": normal_count,
        "threat_event_count": threat_event_count,
        "critical_count": critical_count,
        "high_count": high_count,
        "source_count": source_count,
        "alert_rate": alert_rate,
        "normal_ratio": normal_ratio,
        "escalation_rate": escalation_rate,
        "macro_f1": macro_f1,
        "synthetic_score": synthetic_score,
    }


def incident_frame(alerts: pd.DataFrame) -> pd.DataFrame:
    if alerts.empty:
        return pd.DataFrame(columns=["source_ip", "threat_type", "severity", "events", "max_confidence", "last_seen"])
    rows: list[dict[str, Any]] = []
    for keys, group in alerts.groupby(["source_ip", "threat_type", "severity"], dropna=False):
        source_ip, threat_type, severity = keys
        confidences = [
            float(item.get("confidence", 0.0) or 0.0)
            for item in group.get("ml_result", pd.Series(dtype=object))
            if isinstance(item, dict)
        ]
        rows.append(
            {
                "source_ip": source_ip,
                "threat_type": threat_type,
                "severity": severity,
                "events": int(len(group)),
                "max_confidence": round(max(confidences) if confidences else 0.0, 3),
                "last_seen": group["timestamp"].max() if "timestamp" in group else "n/a",
                "recommendation": group["recommended_action"].iloc[-1] if "recommended_action" in group else "",
            }
        )
    return pd.DataFrame(rows).sort_values(["severity", "events"], ascending=[True, False])


def alert_worklist(alerts: pd.DataFrame) -> pd.DataFrame:
    if alerts.empty:
        return pd.DataFrame()
    rows: list[dict[str, Any]] = []
    for alert in alerts.to_dict("records"):
        ml = alert.get("ml_result") if isinstance(alert.get("ml_result"), dict) else {}
        rule = alert.get("rule_result") if isinstance(alert.get("rule_result"), dict) else {}
        rows.append(
            {
                "alert_id": alert.get("alert_id"),
                "time": alert.get("timestamp"),
                "severity": alert.get("severity"),
                "threat": alert.get("threat_type"),
                "source": alert.get("source_ip"),
                "endpoint": alert.get("endpoint"),
                "ml_conf": ml.get("confidence"),
                "rule": ", ".join(match.get("rule_id", "") for match in rule.get("matched_rules", []))
                if isinstance(rule.get("matched_rules"), list)
                else "",
            }
        )
    return pd.DataFrame(rows)


def inject_console_theme() -> None:
    st.markdown(
        """
        <style>
          :root {
            --ink: #101820;
            --muted: #5d6975;
            --line: #cfd8df;
            --paper: #ffffff;
            --wash: #f3f6f7;
            --steel: #20333b;
            --teal: #0f6f78;
            --amber: #b98116;
            --red: #9f1d20;
          }
          .stApp { background: var(--wash); color: var(--ink); }
          .block-container { padding-top: 1.15rem; max-width: 1500px; }
          h1, h2, h3 { letter-spacing: 0; color: var(--ink); }
          div[data-testid="stMetric"] {
            border: 1px solid var(--line);
            border-radius: 6px;
            padding: 12px 14px;
            background: var(--paper);
          }
          div[data-testid="stMetric"] label { color: var(--muted); }
          .console-header {
            border: 1px solid var(--line);
            border-left: 6px solid var(--teal);
            border-radius: 6px;
            background: var(--paper);
            padding: 18px 20px;
            margin-bottom: 14px;
          }
          .console-title {
            font-size: 30px;
            font-weight: 760;
            margin: 0;
          }
          .console-subtitle {
            color: var(--muted);
            margin-top: 5px;
            font-size: 14px;
          }
          .metric-grid {
            display: grid;
            grid-template-columns: repeat(6, minmax(0, 1fr));
            gap: 10px;
            margin: 10px 0 18px;
          }
          .soc-card {
            border: 1px solid var(--line);
            border-radius: 6px;
            background: var(--paper);
            padding: 13px 14px;
            min-height: 94px;
          }
          .soc-card .label {
            color: var(--muted);
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .04em;
          }
          .soc-card .value {
            font-size: 27px;
            font-weight: 760;
            margin-top: 7px;
          }
          .soc-card .note {
            color: var(--muted);
            font-size: 12px;
            margin-top: 6px;
          }
          .risk-critical { border-top: 4px solid var(--red); }
          .risk-high { border-top: 4px solid #c24a1a; }
          .risk-medium { border-top: 4px solid var(--amber); }
          .risk-ok { border-top: 4px solid #2f7d57; }
          .pipeline-row {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 8px;
            margin: 10px 0 18px;
          }
          .pipeline-node {
            border: 1px solid var(--line);
            border-radius: 6px;
            background: #fbfcfd;
            padding: 11px;
            font-size: 13px;
          }
          .pipeline-node b { display: block; color: var(--steel); margin-bottom: 3px; }
          .notice {
            border: 1px solid #d6c48d;
            border-left: 5px solid var(--amber);
            border-radius: 6px;
            background: #fff9e7;
            padding: 10px 12px;
            color: #533f04;
            font-size: 13px;
            margin: 8px 0 14px;
          }
          @media (max-width: 1100px) {
            .metric-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
            .pipeline-row { grid-template-columns: 1fr; }
          }
        </style>
        """,
        unsafe_allow_html=True,
    )


def metric_card(label: str, value: str | int | float, note: str, risk_class: str = "risk-ok") -> str:
    return f"""
    <div class="soc-card {risk_class}">
      <div class="label">{label}</div>
      <div class="value">{value}</div>
      <div class="note">{note}</div>
    </div>
    """


def quality_notices(metrics: dict[str, Any]) -> list[str]:
    notices: list[str] = []
    if metrics.get("synthetic_score"):
        notices.append("Model score is from controlled synthetic data; present it as lab validation, not production accuracy.")
    if metrics.get("alert_rate", 0.0) > 0.5:
        notices.append("Event-level alert rate is high. Use incident count for analyst workload and explain that this is a threat-heavy demo batch.")
    if metrics.get("normal_ratio", 0.0) < 0.5 and metrics.get("event_count", 0) > 0:
        notices.append("Normal baseline is under 50%; regenerate mixed traffic after the simulator update for a more realistic distribution.")
    return notices
