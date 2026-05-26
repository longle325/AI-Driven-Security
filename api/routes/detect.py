from __future__ import annotations

from fastapi import APIRouter

from src.alert_manager import recommended_action_for
from src.detect import detect_event, load_model
from src.schemas import BatchDetectionRequest, DetectionRequest


router = APIRouter(prefix="/detect", tags=["detect"])


def _response_from_alert(alert: dict) -> dict:
    ml_result = alert.get("ml_result", {})
    return {
        "is_threat": alert["severity"] != "informational",
        "threat_type": alert["threat_type"],
        "severity": alert["severity"],
        "confidence": float(ml_result.get("confidence", 0.0) or 0.0),
        "recommended_action": alert.get("recommended_action", recommended_action_for(alert["threat_type"])),
        "evidence": alert.get("evidence"),
        "rule_result": alert.get("rule_result"),
        "ml_result": ml_result,
    }


@router.post("/event")
def detect_single_event(request: DetectionRequest) -> dict:
    model = load_model()
    alert = detect_event(request.event.model_dump(), event_index=0, model=model)
    return _response_from_alert(alert)


@router.post("/batch")
def detect_batch(request: BatchDetectionRequest) -> dict:
    model = load_model()
    alerts = [
        _response_from_alert(detect_event(event.model_dump(), event_index=index, model=model))
        for index, event in enumerate(request.events)
    ]
    return {"count": len(alerts), "results": alerts}
