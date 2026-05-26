from pathlib import Path

import pandas as pd

from src.io_utils import append_jsonl, read_jsonl
from src.preprocessing import FEATURE_COLUMNS, preprocess_events


def test_preprocess_events_fills_missing_values_and_returns_stable_features():
    rows = [
        {
            "timestamp": "2026-05-26T10:00:00Z",
            "source_ip": "172.20.0.5",
            "event_type": "login_failed",
            "endpoint": "/login",
            "status_code": 401,
            "label": "brute_force",
        }
    ]

    features, labels, processed = preprocess_events(pd.DataFrame(rows), include_labels=True)

    assert list(features.columns) == FEATURE_COLUMNS
    assert labels.tolist() == ["brute_force"]
    assert processed.loc[0, "failed_login_count_5m"] == 1
    assert processed.loc[0, "status_4xx_count_5m"] == 1
    assert features.isna().sum().sum() == 0


def test_jsonl_round_trip_preserves_event_records(tmp_path: Path):
    output = tmp_path / "events.jsonl"
    event = {
        "timestamp": "2026-05-26T10:00:00Z",
        "source_ip": "172.20.0.10",
        "event_type": "search",
        "endpoint": "/search",
        "status_code": 200,
    }

    append_jsonl(output, [event])

    assert read_jsonl(output) == [event]
