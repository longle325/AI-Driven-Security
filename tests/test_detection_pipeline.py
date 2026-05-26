from pathlib import Path

from lab.simulator.simulate_events import simulate
from src.config import settings
from src.detect import run_detection
from src.evidence_exporter import export_evidence
from src.llm_advisor import generate_recommendations
from src.train_model import train_model


def test_end_to_end_pipeline_creates_artifacts(tmp_path):
    original_paths = {
        "data_dir": settings.data_dir,
        "raw_data_dir": settings.raw_data_dir,
        "processed_data_dir": settings.processed_data_dir,
        "log_dir": settings.log_dir,
        "model_dir": settings.model_dir,
        "evidence_dir": settings.evidence_dir,
    }
    temp_paths = {
        "data_dir": tmp_path / "data",
        "raw_data_dir": tmp_path / "data" / "raw",
        "processed_data_dir": tmp_path / "data" / "processed",
        "log_dir": tmp_path / "data" / "logs",
        "model_dir": tmp_path / "models",
        "evidence_dir": tmp_path / "data" / "evidence" / "exports",
    }

    for key, value in temp_paths.items():
        object.__setattr__(settings, key, value)

    try:
        _run_end_to_end_assertions()
    finally:
        for key, value in original_paths.items():
            object.__setattr__(settings, key, value)


def _run_end_to_end_assertions():
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
