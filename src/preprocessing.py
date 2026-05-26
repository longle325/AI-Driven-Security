from __future__ import annotations

from pathlib import Path
from typing import Iterable

import pandas as pd

from src.feature_engineering import add_temporal_features, normalize_event_record
from src.io_utils import read_jsonl


FEATURE_COLUMNS = [
    "request_count_1m",
    "failed_login_count_5m",
    "unique_endpoints_5m",
    "unique_ports_1m",
    "status_4xx_count_5m",
    "status_5xx_count_5m",
    "payload_risk_score",
    "avg_request_interval",
    "endpoint_risk_score",
    "method_encoded",
    "status_code",
    "event_type_encoded",
    "hour",
]


def events_to_dataframe(events: Iterable[dict]) -> pd.DataFrame:
    normalized = [normalize_event_record(event) for event in events]
    if not normalized:
        return pd.DataFrame(columns=["label", *FEATURE_COLUMNS])
    return pd.DataFrame(normalized)


def preprocess_events(
    events: pd.DataFrame | Iterable[dict],
    include_labels: bool = False,
) -> tuple[pd.DataFrame, pd.Series | None, pd.DataFrame]:
    frame = events.copy() if isinstance(events, pd.DataFrame) else events_to_dataframe(events)
    if frame.empty:
        features = pd.DataFrame(columns=FEATURE_COLUMNS)
        labels = pd.Series(dtype="object") if include_labels else None
        return features, labels, frame

    normalized_records = [normalize_event_record(record) for record in frame.to_dict("records")]
    processed = add_temporal_features(pd.DataFrame(normalized_records))

    for column in FEATURE_COLUMNS:
        if column not in processed:
            processed[column] = 0
    numeric = processed[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce").fillna(0)
    labels = processed["label"].fillna("normal") if include_labels and "label" in processed else None
    return numeric, labels, processed


def load_events_dataframe(path: Path) -> pd.DataFrame:
    return events_to_dataframe(read_jsonl(path))
