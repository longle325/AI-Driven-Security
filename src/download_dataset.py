from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

import kagglehub
import pandas as pd

from src.config import ensure_directories, settings
from src.data_loader import normalize_label

DEFAULT_KAGGLE_DATASET = "ericanacletoribeiro/cicids2017-cleaned-and-preprocessed"
DEFAULT_SOURCE_FILE = "cicids2017_cleaned.csv"
DEFAULT_SAMPLE_FILE = "cicids2017_training_sample.csv"
TARGET_LABELS = {"normal", "port_scan", "brute_force", "web_attack", "traffic_spike"}


def _sample_rows(source: Path, output: Path, per_label: int, chunksize: int = 120000) -> dict:
    if per_label <= 0:
        raise ValueError("--per-label must be greater than 0")

    collected: dict[str, list[pd.DataFrame]] = {}
    counts: dict[str, int] = {}
    source_columns = pd.read_csv(source, nrows=0).columns.tolist()
    label_column = "Attack Type" if "Attack Type" in source_columns else source_columns[-1]

    for chunk in pd.read_csv(source, chunksize=chunksize):
        mapped = chunk[label_column].map(normalize_label)
        for label, group in chunk.groupby(mapped):
            if label not in TARGET_LABELS:
                continue
            remaining = per_label - counts.get(label, 0)
            if remaining <= 0:
                continue
            selected = group.sample(n=min(remaining, len(group)), random_state=42)
            collected.setdefault(label, []).append(selected)
            counts[label] = counts.get(label, 0) + len(selected)

        if TARGET_LABELS.issubset(counts) and all(counts.get(label, 0) >= per_label for label in TARGET_LABELS):
            break

    if not collected:
        raise RuntimeError(f"No rows sampled from {source}")

    sampled = pd.concat([frame for frames in collected.values() for frame in frames], ignore_index=True)
    sampled = sampled.sample(frac=1, random_state=42).reset_index(drop=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    sampled.to_csv(output, index=False)
    return {
        "rows": int(len(sampled)),
        "label_counts": {label: int(count) for label, count in sampled[label_column].map(normalize_label).value_counts().items()},
    }


def download_cicids2017(per_label: int = 12000, keep_full_pointer: bool = True) -> dict:
    ensure_directories()
    dataset_path = Path(kagglehub.dataset_download(DEFAULT_KAGGLE_DATASET))
    source = dataset_path / DEFAULT_SOURCE_FILE
    if not source.exists():
        candidates = list(dataset_path.glob("*.csv"))
        if not candidates:
            raise FileNotFoundError(f"No CSV files found in Kaggle dataset path {dataset_path}")
        source = candidates[0]

    output = settings.raw_data_dir / DEFAULT_SAMPLE_FILE
    sample_info = _sample_rows(source, output, per_label=per_label)

    kaggle_dir = settings.raw_data_dir / "kaggle"
    kaggle_dir.mkdir(parents=True, exist_ok=True)
    pointer = kaggle_dir / source.name
    if keep_full_pointer:
        if pointer.exists() or pointer.is_symlink():
            pointer.unlink()
        try:
            pointer.symlink_to(source)
        except OSError:
            shutil.copy2(source, pointer)

    manifest = {
        "dataset": DEFAULT_KAGGLE_DATASET,
        "kaggle_cache_path": str(dataset_path),
        "source_file": str(source),
        "training_sample": str(output),
        "per_label_cap": per_label,
        **sample_info,
    }
    (settings.raw_data_dir / "cicids2017_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Download CICIDS2017 from Kaggle and prepare a local training sample.")
    parser.add_argument("--per-label", type=int, default=12000)
    args = parser.parse_args()
    print(json.dumps(download_cicids2017(per_label=args.per_label), indent=2))


if __name__ == "__main__":
    main()
