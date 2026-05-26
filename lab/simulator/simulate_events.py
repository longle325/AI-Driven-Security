from __future__ import annotations

import argparse
import json
from pathlib import Path

from lab.simulator.scenarios import generate_scenario_events
from src.config import EVENTS_JSONL, ensure_project_dirs
from src.io_utils import append_jsonl, write_jsonl


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate safe synthetic cyber-defense lab events.")
    parser.add_argument("--scenario", choices=["normal", "port_scan", "brute_force", "web_attack", "traffic_spike", "mixed"], default="mixed")
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--output", type=Path, default=EVENTS_JSONL)
    parser.add_argument("--replace", action="store_true", help="Replace the output file instead of appending.")
    parser.add_argument("--seed", type=int, default=42)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    ensure_project_dirs()
    events = generate_scenario_events(args.scenario, args.count, seed=args.seed)
    if args.replace:
        write_jsonl(args.output, events)
    else:
        append_jsonl(args.output, events)
    print(json.dumps({"scenario": args.scenario, "events": len(events), "output": str(args.output)}, indent=2))


if __name__ == "__main__":
    main()
