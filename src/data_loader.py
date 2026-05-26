from __future__ import annotations

from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd

from src.config import ensure_directories, settings
from src.io_utils import read_jsonl
from src.schemas import FEATURE_COLUMNS, LOG_COLUMNS, THREAT_TYPES


COLUMN_ALIASES = {
    "src_ip": "source_ip",
    "ip": "source_ip",
    "user": "user_id",
    "method": "http_method",
    "path": "endpoint",
    "uri": "endpoint",
    "target": "endpoint",
    "attack_type": "label",
    "class": "label",
    "target_label": "label",
}


def normalize_column_name(name: str) -> str:
    cleaned = name.strip().lower().replace("-", "_").replace(" ", "_")
    return COLUMN_ALIASES.get(cleaned, cleaned)


def normalize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=LOG_COLUMNS)

    df = df.rename(columns={col: normalize_column_name(str(col)) for col in df.columns}).copy()
    df = df.replace([np.inf, -np.inf], np.nan)

    defaults = {
        "timestamp": pd.Timestamp.now(tz="UTC").isoformat(),
        "source_ip": "10.0.0.10",
        "user_id": "user_00",
        "event_type": "request",
        "endpoint": "/",
        "http_method": "GET",
        "status_code": 200,
        "label": "normal",
    }

    for column in LOG_COLUMNS:
        if column not in df.columns:
            df[column] = 0 if column in FEATURE_COLUMNS else defaults.get(column, "")

    for column in FEATURE_COLUMNS + ["status_code"]:
        df[column] = pd.to_numeric(df[column], errors="coerce").fillna(0)

    for column in ("timestamp", "source_ip", "user_id", "event_type", "endpoint", "http_method"):
        df[column] = df[column].fillna(defaults[column]).astype(str)

    df["label"] = df["label"].fillna("normal").astype(str).str.lower().str.strip()
    df.loc[~df["label"].isin(THREAT_TYPES), "label"] = "normal"
    df = df.drop_duplicates().reset_index(drop=True)
    return df[LOG_COLUMNS]


def load_file(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame(columns=LOG_COLUMNS)
    if path.suffix.lower() == ".jsonl":
        return normalize_dataframe(pd.DataFrame(read_jsonl(path)))
    if path.suffix.lower() == ".csv":
        return normalize_dataframe(pd.read_csv(path))
    raise ValueError(f"Unsupported input file: {path}")


def load_many(paths: Iterable[Path]) -> pd.DataFrame:
    frames = [load_file(path) for path in paths if path.exists()]
    if not frames:
        return pd.DataFrame(columns=LOG_COLUMNS)
    return normalize_dataframe(pd.concat(frames, ignore_index=True))


def load_default_dataset() -> pd.DataFrame:
    ensure_directories()
    candidates = sorted(settings.raw_data_dir.glob("*.csv")) + sorted(settings.raw_data_dir.glob("*.jsonl"))
    if candidates:
        return load_many(candidates)
    return load_file(settings.events_jsonl)


def save_processed_dataset(df: pd.DataFrame, path: Path | None = None) -> Path:
    ensure_directories()
    destination = path or settings.processed_data_dir / "loaded_dataset.csv"
    destination.parent.mkdir(parents=True, exist_ok=True)
    normalize_dataframe(df).to_csv(destination, index=False)
    return destination
