from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

import kagglehub
import pandas as pd

from src.config import ensure_directories, settings
from src.data_loader import normalize_label

DEFAULT_KAGGLE_DATASET = "prantokumar/ids-dataset-2025"
DEFAULT_SOURCE_FILE = ""
DEFAULT_SAMPLE_FILE = "ids2025_training_sample.csv"
TARGET_LABELS = {"normal", "botnet", "brute_force", "dos_ddos", "web_attack", "infiltration"}


def _label_column_for(source: Path) -> str:
    source_columns = pd.read_csv(source, nrows=0).columns.tolist()
    for candidate in ("Label", "Attack Type", "label", "attack_type"):
        if candidate in source_columns:
            return candidate
    return source_columns[-1]


def _sample_rows_from_files(sources: list[Path], output: Path, per_label: int, chunksize: int = 120000) -> dict:
    if per_label <= 0:
        raise ValueError("--per-label must be greater than 0")

    collected: dict[str, list[pd.DataFrame]] = {}
    counts: dict[str, int] = {}

    for source in sources:
        label_column = _label_column_for(source)
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
        if TARGET_LABELS.issubset(counts) and all(counts.get(label, 0) >= per_label for label in TARGET_LABELS):
            break

    if not collected:
        raise RuntimeError(f"No supported IDS rows sampled from {', '.join(str(path) for path in sources)}")

    sampled = pd.concat([frame for frames in collected.values() for frame in frames], ignore_index=True)
    sampled = sampled.sample(frac=1, random_state=42).reset_index(drop=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    sampled.to_csv(output, index=False)
    final_label_column = "Label" if "Label" in sampled.columns else _label_column_for(sources[0])
    return {
        "rows": int(len(sampled)),
        "label_counts": {label: int(count) for label, count in sampled[final_label_column].map(normalize_label).value_counts().items()},
    }


def _sample_rows(source: Path, output: Path, per_label: int, chunksize: int = 120000) -> dict:
    return _sample_rows_from_files([source], output, per_label=per_label, chunksize=chunksize)


def download_ids2025(per_label: int = 12000, keep_full_pointer: bool = True) -> dict:
    ensure_directories()
    dataset_path = Path(kagglehub.dataset_download(DEFAULT_KAGGLE_DATASET))
    sources = sorted(dataset_path.glob("*.csv"))
    if not sources:
        raise FileNotFoundError(f"No CSV files found in Kaggle dataset path {dataset_path}")

    output = settings.raw_data_dir / DEFAULT_SAMPLE_FILE
    sample_info = _sample_rows_from_files(sources, output, per_label=per_label)

    kaggle_dir = settings.raw_data_dir / "kaggle"
    kaggle_dir.mkdir(parents=True, exist_ok=True)
    pointer = kaggle_dir / "ids_dataset_2025"
    if keep_full_pointer:
        if pointer.exists() or pointer.is_symlink():
            if pointer.is_dir() and not pointer.is_symlink():
                shutil.rmtree(pointer)
            else:
                pointer.unlink()
        try:
            pointer.symlink_to(dataset_path)
        except OSError:
            shutil.copytree(dataset_path, pointer)

    manifest = {
        "dataset": DEFAULT_KAGGLE_DATASET,
        "dataset_name": "IDS Dataset 2025",
        "kaggle_cache_path": str(dataset_path),
        "source_files": [str(path) for path in sources],
        "training_sample": str(output),
        "per_label_cap": per_label,
        "taxonomy": sorted(TARGET_LABELS),
        **sample_info,
    }
    (settings.raw_data_dir / "ids2025_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def download_cicids2017(per_label: int = 12000, keep_full_pointer: bool = True) -> dict:
    return download_ids2025(per_label=per_label, keep_full_pointer=keep_full_pointer)


def main() -> None:
    parser = argparse.ArgumentParser(description="Download IDS Dataset 2025 from Kaggle and prepare a local training sample.")
    parser.add_argument("--per-label", type=int, default=12000)
    args = parser.parse_args()
    print(json.dumps(download_ids2025(per_label=args.per_label), indent=2))


if __name__ == "__main__":
    main()
