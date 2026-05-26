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

LABEL_ALIASES = {
    "normal traffic": "normal",
    "benign": "normal",
    "normal": "normal",
    "port scanning": "port_scan",
    "portscan": "port_scan",
    "port scan": "port_scan",
    "brute force": "brute_force",
    "ftp patator": "brute_force",
    "ssh patator": "brute_force",
    "web attacks": "web_attack",
    "web attack": "web_attack",
    "dos": "traffic_spike",
    "ddos": "traffic_spike",
    "bots": "traffic_spike",
    "bot": "traffic_spike",
}


def normalize_column_name(name: str) -> str:
    cleaned = name.strip().lower().replace("-", "_").replace("/", "_").replace(" ", "_")
    while "__" in cleaned:
        cleaned = cleaned.replace("__", "_")
    return COLUMN_ALIASES.get(cleaned, cleaned)


def normalize_label(value: object) -> str:
    cleaned = str(value).lower().strip().replace("_", " ").replace("-", " ")
    return LABEL_ALIASES.get(cleaned, str(value).lower().strip())


def _numeric(df: pd.DataFrame, column: str) -> pd.Series:
    if column not in df.columns:
        return pd.Series(0.0, index=df.index)
    return pd.to_numeric(df[column], errors="coerce").fillna(0.0)


def _scaled(series: pd.Series, cap: float, maximum: float) -> pd.Series:
    clipped = series.clip(lower=0, upper=cap)
    return (np.log1p(clipped) / np.log1p(cap) * maximum).fillna(0.0)


def _derive_flow_features(df: pd.DataFrame) -> pd.DataFrame:
    if "destination_port" not in df.columns and "flow_packets_s" not in df.columns:
        return df

    enriched = df.copy()
    port = _numeric(enriched, "destination_port")
    flow_packets = _numeric(enriched, "flow_packets_s")
    total_fwd_packets = _numeric(enriched, "total_fwd_packets")
    packet_mean = _numeric(enriched, "packet_length_mean")
    packet_std = _numeric(enriched, "packet_length_std")
    packet_variance = _numeric(enriched, "packet_length_variance")
    max_packet = pd.concat(
        [
            _numeric(enriched, "fwd_packet_length_max"),
            _numeric(enriched, "bwd_packet_length_max"),
            _numeric(enriched, "max_packet_length"),
        ],
        axis=1,
    ).max(axis=1)
    flow_iat_mean = _numeric(enriched, "flow_iat_mean")
    flow_iat_std = _numeric(enriched, "flow_iat_std")
    idle_mean = _numeric(enriched, "idle_mean")
    psh_flags = _numeric(enriched, "psh_flag_count")

    login_ports = port.isin([21, 22]).astype(float)
    web_ports = port.isin([80, 443, 8080, 8443]).astype(float)
    common_ports = port.isin([20, 21, 22, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443])

    derived = {
        "request_count_1m": pd.concat(
            [
                _scaled(flow_packets, 10000, 420),
                _scaled(total_fwd_packets, 2000, 220),
            ],
            axis=1,
        ).max(axis=1),
        "failed_login_count_5m": login_ports
        * pd.concat(
            [
                _scaled(flow_packets, 2000, 50),
                _scaled(total_fwd_packets, 500, 42),
            ],
            axis=1,
        ).max(axis=1),
        "unique_ports_1m": pd.Series(
            np.where(port > 1024, _scaled(port, 65535, 90), np.where(common_ports, 2, 34)),
            index=enriched.index,
        ),
        "status_4xx_count_5m": web_ports * _scaled(packet_std + packet_mean, 5000, 40),
        "status_5xx_count_5m": _scaled(flow_iat_std + idle_mean, 10000000, 32),
        "payload_risk_score": (
            _scaled(max_packet + packet_std, 10000, 0.58)
            + _scaled(packet_variance, 10000000, 0.24)
            + (web_ports * 0.12)
            + (psh_flags.clip(0, 1) * 0.06)
        ).clip(0, 1),
        "endpoint_risk_score": pd.Series(
            np.select(
                [login_ports.astype(bool), web_ports.astype(bool), port > 1024],
                [0.76, 0.66, 0.54],
                default=0.24,
            ),
            index=enriched.index,
        ),
        "avg_request_interval": (flow_iat_mean / 1000000).clip(lower=0, upper=120),
    }

    for column, value in derived.items():
        if column not in enriched.columns or _numeric(enriched, column).eq(0).all():
            enriched[column] = value

    if "event_type" not in enriched.columns:
        enriched["event_type"] = "network_flow"
    if "endpoint" not in enriched.columns:
        enriched["endpoint"] = port.fillna(0).astype(int).map(lambda value: f"/port/{value}")
    if "http_method" not in enriched.columns:
        enriched["http_method"] = "FLOW"
    if "status_code" not in enriched.columns:
        enriched["status_code"] = 200
    if "source_ip" not in enriched.columns:
        enriched["source_ip"] = [f"10.250.{idx % 250}.{(idx % 200) + 20}" for idx in range(len(enriched))]
    if "user_id" not in enriched.columns:
        enriched["user_id"] = [f"flow_{idx:06d}" for idx in range(len(enriched))]

    return enriched


def normalize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=LOG_COLUMNS)

    df = df.rename(columns={col: normalize_column_name(str(col)) for col in df.columns}).copy()
    df = df.replace([np.inf, -np.inf], np.nan)
    df = _derive_flow_features(df)

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

    df["label"] = df["label"].fillna("normal").map(normalize_label)
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
