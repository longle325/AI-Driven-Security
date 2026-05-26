from __future__ import annotations

import json

from src.config import settings
from src.train_model import train_model


def evaluate_model() -> dict:
    if not settings.metrics_path.exists():
        return train_model()
    return json.loads(settings.metrics_path.read_text(encoding="utf-8"))


def main() -> None:
    print(json.dumps(evaluate_model(), indent=2))


if __name__ == "__main__":
    main()
