from pathlib import Path

from dashboard.common import load_jsonl_frame


def test_dashboard_common_loads_missing_jsonl_as_empty_frame(tmp_path: Path):
    frame = load_jsonl_frame(tmp_path / "missing.jsonl")

    assert frame.empty
