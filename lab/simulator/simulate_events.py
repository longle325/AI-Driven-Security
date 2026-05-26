from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from lab.simulator.scenarios import SCENARIOS, generate_events
from src.config import ensure_directories, settings
from src.io_utils import write_jsonl


def simulate(scenario: str = "mixed", count: int = 500, output: Path | None = None, replace: bool = True) -> list[dict]:
    ensure_directories()
    output_path = output or settings.events_jsonl
    events = generate_events(scenario=scenario, count=count)
    write_jsonl(output_path, events, append=not replace)

    csv_path = settings.live_logs_csv
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(events).to_csv(csv_path, index=False)
    return events


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate safe synthetic lab security events.")
    parser.add_argument("--scenario", choices=SCENARIOS, default="mixed")
    parser.add_argument("--count", type=int, default=500)
    parser.add_argument("--output", type=Path, default=settings.events_jsonl)
    parser.add_argument("--replace", action="store_true", default=True)
    args = parser.parse_args()

    events = simulate(args.scenario, args.count, args.output, args.replace)
    print(f"Generated {len(events)} {args.scenario} events at {args.output}")


if __name__ == "__main__":
    main()
