from pathlib import Path

from lab.simulator.simulate_events import simulate
from src.config import settings
from src.detect import run_detection
from src.evidence_exporter import export_evidence
from src.llm_advisor import generate_recommendations
from src.train_model import train_model


def test_end_to_end_pipeline_creates_artifacts():
    simulate("mixed", 160, output=settings.events_jsonl, replace=True)
    metrics = train_model()
    detection = run_detection(settings.events_jsonl, settings.alerts_jsonl)
    recommendations = generate_recommendations(settings.alerts_jsonl, settings.recommendations_jsonl)
    evidence = export_evidence()

    assert metrics["f1_score"] > 0.8
    assert detection["events"] == 160
    assert detection["alerts"] > 0
    assert len(recommendations) == detection["alerts"]
    assert Path(evidence["export_dir"]).exists()
    assert "demo_summary.md" in evidence["files"]
