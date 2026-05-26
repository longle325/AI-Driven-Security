from pathlib import Path

from src.config import settings
from src.io_utils import read_jsonl
from src.streaming import process_next_stream_event, reset_stream_session


def test_stream_session_steps_logs_through_detector(tmp_path):
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
        session = reset_stream_session("brute_force", count=3)
        first = process_next_stream_event()
        second = process_next_stream_event()
        third = process_next_stream_event()
        done = process_next_stream_event()

        assert session["total"] == 3
        assert first["processed"] == 1
        assert second["processed"] == 2
        assert third["processed"] == 3
        assert done["done"] is True
        assert Path(first["detected"]["evidence_ref"].split(":")[0]).name == "events.jsonl"
        assert first["detected"]["ml_prediction"] in {"normal", "botnet", "brute_force", "dos_ddos", "web_attack", "infiltration"}
        assert first["alert"] is not None
        assert len(read_jsonl(settings.events_jsonl)) == 3
        assert len(read_jsonl(settings.alerts_jsonl)) >= 1
    finally:
        for key, value in original_paths.items():
            object.__setattr__(settings, key, value)
