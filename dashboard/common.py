from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from src.config import ALERTS_JSONL, EVENTS_JSONL, MODELS_DIR
from src.io_utils import read_jsonl


SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]
SEVERITY_COLORS = {
    "critical": "#b42318",
    "high": "#dc6803",
    "medium": "#d6a100",
    "low": "#2563eb",
    "informational": "#667085",
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
