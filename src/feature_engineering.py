from __future__ import annotations

import pandas as pd

from src.schemas import FEATURE_COLUMNS


def endpoint_risk(endpoint: str) -> float:
    endpoint = str(endpoint).lower()
    if any(marker in endpoint for marker in ("admin", "wp-admin", "debug", "config", "backup")):
        return 0.85
    if any(marker in endpoint for marker in ("login", "search", "api")):
        return 0.45
    return 0.15


def add_security_features(df: pd.DataFrame) -> pd.DataFrame:
    enriched = df.copy()
    if "endpoint_risk_score" not in enriched.columns or enriched["endpoint_risk_score"].isna().all():
        enriched["endpoint_risk_score"] = enriched.get("endpoint", "/").map(endpoint_risk)

    if "avg_request_interval" not in enriched.columns:
        enriched["avg_request_interval"] = 6.0

    for column in FEATURE_COLUMNS:
        if column not in enriched.columns:
            enriched[column] = 0.0
        enriched[column] = pd.to_numeric(enriched[column], errors="coerce").fillna(0.0)

    enriched["payload_risk_score"] = enriched["payload_risk_score"].clip(lower=0, upper=1)
    enriched["endpoint_risk_score"] = enriched["endpoint_risk_score"].clip(lower=0, upper=1)
    enriched["avg_request_interval"] = enriched["avg_request_interval"].clip(lower=0)
    return enriched


def feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    return add_security_features(df)[FEATURE_COLUMNS].astype(float)
