from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parents[1]
load_dotenv(ROOT_DIR / ".env")


def _path(name: str, default: str) -> Path:
    value = os.getenv(name, default)
    path = Path(value)
    return path if path.is_absolute() else ROOT_DIR / path


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class Settings:
    data_dir: Path = _path("DATA_DIR", "data")
    raw_data_dir: Path = _path("RAW_DATA_DIR", "data/raw")
    processed_data_dir: Path = _path("PROCESSED_DATA_DIR", "data/processed")
    log_dir: Path = _path("LOG_DIR", "data/logs")
    model_dir: Path = _path("MODEL_DIR", "models")
    evidence_dir: Path = _path("EVIDENCE_DIR", "data/evidence/exports")

    llm_mode: str = os.getenv("LLM_MODE", "fallback").lower()
    llm_provider: str = os.getenv("LLM_PROVIDER", "openai").lower()
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-5.4-mini")
    openai_reasoning_effort: str = os.getenv("OPENAI_REASONING_EFFORT", "low")
    openai_text_verbosity: str = os.getenv("OPENAI_TEXT_VERBOSITY", "low")

    failed_login_threshold: int = _int("RULE_FAILED_LOGIN_THRESHOLD", 10)
    unique_ports_threshold: int = _int("RULE_UNIQUE_PORTS_THRESHOLD", 20)
    request_spike_threshold: int = _int("RULE_REQUEST_SPIKE_THRESHOLD", 150)
    payload_risk_threshold: float = _float("RULE_PAYLOAD_RISK_THRESHOLD", 0.70)
    error_threshold: int = _int("RULE_ERROR_THRESHOLD", 20)

    @property
    def events_jsonl(self) -> Path:
        return self.log_dir / "events.jsonl"

    @property
    def live_logs_csv(self) -> Path:
        return self.log_dir / "live_logs.csv"

    @property
    def detected_logs_csv(self) -> Path:
        return self.log_dir / "detected_logs.csv"

    @property
    def alerts_csv(self) -> Path:
        return self.log_dir / "alerts.csv"

    @property
    def alerts_jsonl(self) -> Path:
        return self.log_dir / "alerts.jsonl"

    @property
    def recommendations_jsonl(self) -> Path:
        return self.log_dir / "llm_recommendations.jsonl"

    @property
    def model_path(self) -> Path:
        return self.model_dir / "threat_model.joblib"

    @property
    def label_encoder_path(self) -> Path:
        return self.model_dir / "label_encoder.joblib"

    @property
    def scaler_path(self) -> Path:
        return self.model_dir / "scaler.joblib"

    @property
    def metrics_path(self) -> Path:
        return self.model_dir / "metrics.json"


settings = Settings()


def ensure_directories() -> None:
    for directory in (
        settings.data_dir,
        settings.raw_data_dir,
        settings.processed_data_dir,
        settings.log_dir,
        settings.model_dir,
        settings.evidence_dir,
        settings.evidence_dir.parent / "screenshots",
    ):
        directory.mkdir(parents=True, exist_ok=True)
