from __future__ import annotations

from pathlib import Path

import pandas as pd
from pandas.errors import EmptyDataError

from lab.simulator.scenarios import generate_events
from src.config import ensure_directories, settings
from src.detect import detect_event
from src.io_utils import read_jsonl, write_jsonl
from src.schemas import LOG_COLUMNS


def _stream_source_path() -> Path:
    return settings.log_dir / "stream_source.jsonl"


def _write_csv(path: Path, records: list[dict], columns: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(records, columns=columns).to_csv(path, index=False)


def _read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        return pd.read_csv(path).fillna("").to_dict(orient="records")
    except EmptyDataError:
        return []


def reset_stream_session(scenario: str = "mixed", count: int = 80) -> dict:
    ensure_directories()
    events = generate_events(scenario=scenario, count=count)
    write_jsonl(_stream_source_path(), events)
    write_jsonl(settings.events_jsonl, [])
    write_jsonl(settings.alerts_jsonl, [])
    write_jsonl(settings.recommendations_jsonl, [])
    _write_csv(settings.live_logs_csv, [], columns=LOG_COLUMNS)
    _write_csv(settings.detected_logs_csv, [])
    _write_csv(settings.alerts_csv, [])
    return {"scenario": scenario, "total": len(events), "processed": 0, "done": len(events) == 0}


def stream_status() -> dict:
    source = read_jsonl(_stream_source_path())
    processed = len(_read_csv(settings.detected_logs_csv))
    return {
        "total": len(source),
        "processed": min(processed, len(source)),
        "remaining": max(0, len(source) - processed),
        "done": processed >= len(source) if source else True,
    }


def process_next_stream_event() -> dict:
    ensure_directories()
    source = read_jsonl(_stream_source_path())
    detected_rows = _read_csv(settings.detected_logs_csv)
    processed = len(detected_rows)
    if processed >= len(source):
        return {**stream_status(), "event": None, "detected": None, "alert": None}

    event = source[processed]
    evidence_ref = f"{settings.events_jsonl}:{processed + 1}"
    existing_alerts = read_jsonl(settings.alerts_jsonl)
    result = detect_event(event, alert_index=len(existing_alerts) + 1, evidence_ref=evidence_ref)
    detected = result["detected"]
    alert = result["alert"]

    write_jsonl(settings.events_jsonl, [event], append=True)
    live_rows = _read_csv(settings.live_logs_csv)
    _write_csv(settings.live_logs_csv, [*live_rows, event])
    _write_csv(settings.detected_logs_csv, [*detected_rows, detected])
    if alert:
        write_jsonl(settings.alerts_jsonl, [alert], append=True)
        alert_rows = _read_csv(settings.alerts_csv)
        _write_csv(settings.alerts_csv, [*alert_rows, alert])

    status = stream_status()
    return {
        **status,
        "event": event,
        "detected": detected,
        "alert": alert,
    }
