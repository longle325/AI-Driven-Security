from __future__ import annotations

import json
from collections import Counter
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from lab.simulator.simulate_events import simulate
from src.config import ensure_directories, settings
from src.detect import run_detection
from src.evidence_exporter import export_evidence
from src.io_utils import read_jsonl
from src.llm_advisor import advise_alert, generate_recommendations
from src.schemas import AdvisorResponse, CommandResponse, SimulationRequest
from src.streaming import process_next_stream_event, reset_stream_session, stream_status
from src.train_model import train_model

@asynccontextmanager
async def lifespan(_: FastAPI):
    ensure_directories()
    yield


app = FastAPI(title="AI-Driven Cyber Defense Lab API", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8501", "http://localhost:8501", "http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _read_csv(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return pd.read_csv(path).fillna("").to_dict(orient="records")


def _load_metrics() -> dict[str, Any]:
    if settings.metrics_path.exists():
        return json.loads(settings.metrics_path.read_text(encoding="utf-8"))
    return {}


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "llm_mode": settings.llm_mode,
        "openai_model": settings.openai_model,
        "has_openai_key": bool(settings.openai_api_key),
    }


@app.get("/api/summary")
def summary() -> dict[str, Any]:
    logs = _read_csv(settings.live_logs_csv)
    detected = _read_csv(settings.detected_logs_csv)
    alerts = read_jsonl(settings.alerts_jsonl)
    metrics = _load_metrics()

    labels = Counter(str(item.get("label", "unknown")) for item in logs)
    severity = Counter(str(item.get("severity", "unknown")) for item in alerts)
    threats = Counter(str(item.get("threat_type", "unknown")) for item in alerts)

    latest_alert = max((str(alert.get("timestamp", "")) for alert in alerts), default=None)
    return {
        "total_logs": len(logs),
        "detected_logs": len(detected),
        "total_alerts": len(alerts),
        "label_distribution": dict(labels),
        "severity_distribution": dict(severity),
        "threat_distribution": dict(threats),
        "latest_alert_time": latest_alert,
        "metrics": metrics,
        "llm": {
            "mode": settings.llm_mode,
            "provider": settings.llm_provider,
            "model": settings.openai_model,
            "has_key": bool(settings.openai_api_key),
        },
    }


@app.get("/api/logs")
def logs(limit: int = 1000) -> dict[str, Any]:
    rows = _read_csv(settings.live_logs_csv)
    return {"items": rows[-limit:], "total": len(rows)}


@app.get("/api/detected")
def detected(limit: int = 1000) -> dict[str, Any]:
    rows = _read_csv(settings.detected_logs_csv)
    return {"items": rows[-limit:], "total": len(rows)}


@app.get("/api/alerts")
def alerts(limit: int = 1000) -> dict[str, Any]:
    rows = read_jsonl(settings.alerts_jsonl)
    return {"items": rows[-limit:], "total": len(rows)}


@app.get("/api/metrics")
def metrics() -> dict[str, Any]:
    feature_importance = _read_csv(settings.model_dir / "feature_importance.csv")
    report = ""
    report_path = settings.model_dir / "classification_report.txt"
    if report_path.exists():
        report = report_path.read_text(encoding="utf-8")
    return {
        "metrics": _load_metrics(),
        "classification_report": report,
        "feature_importance": feature_importance,
    }


@app.get("/api/rule-vs-ai")
def rule_vs_ai() -> dict[str, Any]:
    rows = _read_csv(settings.detected_logs_csv)
    total = len(rows)
    agreement = [row for row in rows if row.get("rule_prediction") == row.get("ml_prediction")]
    disagreement = [row for row in rows if row.get("rule_prediction") != row.get("ml_prediction")]
    return {
        "total": total,
        "agreement": len(agreement),
        "disagreement": len(disagreement),
        "agreement_rate": round(len(agreement) / total, 4) if total else 0,
        "rule_counts": dict(Counter(str(row.get("rule_prediction", "normal")) for row in rows)),
        "ml_counts": dict(Counter(str(row.get("ml_prediction", "normal")) for row in rows)),
        "examples": disagreement[:25],
    }


@app.post("/api/simulate", response_model=CommandResponse)
def simulate_endpoint(request: SimulationRequest) -> CommandResponse:
    events = simulate(request.scenario, request.count, replace=request.replace)
    return CommandResponse(ok=True, message="Synthetic lab logs generated.", details={"events": len(events), "scenario": request.scenario})


@app.get("/api/stream/status")
def stream_status_endpoint() -> dict[str, Any]:
    return stream_status()


@app.post("/api/stream/reset", response_model=CommandResponse)
def stream_reset_endpoint(request: SimulationRequest) -> CommandResponse:
    result = reset_stream_session(request.scenario, request.count)
    return CommandResponse(ok=True, message="Stream scenario reset.", details=result)


@app.post("/api/stream/step", response_model=CommandResponse)
def stream_step_endpoint() -> CommandResponse:
    result = process_next_stream_event()
    return CommandResponse(ok=True, message="Stream event processed.", details=result)


@app.post("/api/train", response_model=CommandResponse)
def train_endpoint() -> CommandResponse:
    result = train_model()
    return CommandResponse(ok=True, message="Model trained.", details=result)


@app.post("/api/detect", response_model=CommandResponse)
def detect_endpoint() -> CommandResponse:
    result = run_detection()
    return CommandResponse(ok=True, message="Detection completed.", details=result)


@app.post("/api/advisor/generate", response_model=CommandResponse)
def generate_advisor_endpoint() -> CommandResponse:
    recommendations = generate_recommendations()
    return CommandResponse(ok=True, message="Incident recommendations generated.", details={"recommendations": len(recommendations)})


@app.post("/api/advisor/{alert_id}", response_model=AdvisorResponse)
def advisor_endpoint(alert_id: str) -> AdvisorResponse:
    alert = next((item for item in read_jsonl(settings.alerts_jsonl) if str(item.get("alert_id")) == alert_id), None)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    result = advise_alert(alert)
    return AdvisorResponse(**result)


@app.post("/api/export", response_model=CommandResponse)
def export_endpoint() -> CommandResponse:
    result = export_evidence()
    return CommandResponse(ok=True, message="Evidence exported.", details=result)


@app.get("/api/evidence")
def evidence_files() -> dict[str, Any]:
    ensure_directories()
    files = []
    for path in sorted(settings.evidence_dir.glob("*")):
        if path.is_file():
            files.append({"name": path.name, "size": path.stat().st_size})
    return {"items": files, "directory": str(settings.evidence_dir)}
