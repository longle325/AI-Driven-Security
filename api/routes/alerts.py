from __future__ import annotations

from fastapi import APIRouter

from src.config import ALERTS_JSONL
from src.evaluate_model import load_metrics
from src.evidence_exporter import export_evidence
from src.io_utils import read_jsonl


router = APIRouter(tags=["alerts"])


@router.get("/alerts")
def list_alerts() -> dict:
    alerts = read_jsonl(ALERTS_JSONL)
    return {"count": len(alerts), "alerts": alerts}


@router.get("/metrics")
def metrics() -> dict:
    return load_metrics()


@router.post("/export/evidence")
def export() -> dict:
    return export_evidence()
