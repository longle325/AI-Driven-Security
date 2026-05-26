from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from openai import OpenAI

from src.config import ensure_directories, settings
from src.io_utils import read_jsonl, write_jsonl
from src.prompt_templates import INCIDENT_ADVISOR_SYSTEM_PROMPT
from src.recommendation_fallback import fallback_recommendation


def _normalize_json(value: str) -> dict[str, Any]:
    cleaned = value.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        cleaned = cleaned.removeprefix("json").strip()
    return json.loads(cleaned)


def advise_alert(alert: dict, force_fallback: bool = False) -> dict:
    ensure_directories()
    mode = settings.llm_mode
    use_openai = mode in {"api", "openai"} and bool(settings.openai_api_key) and not force_fallback
    if not use_openai:
        return {
            "alert_id": alert.get("alert_id", "UNKNOWN"),
            "mode": "fallback",
            "model": None,
            "recommendation": fallback_recommendation(alert),
        }

    client = OpenAI(api_key=settings.openai_api_key)
    payload = {
        "alert_context": alert,
        "lab_boundary": "localhost, Docker network, synthetic logs, public datasets only",
    }
    try:
        response = client.responses.create(
            model=settings.openai_model,
            instructions=INCIDENT_ADVISOR_SYSTEM_PROMPT,
            input=json.dumps(payload, ensure_ascii=True),
            reasoning={"effort": settings.openai_reasoning_effort},
            text={"verbosity": settings.openai_text_verbosity},
        )
        recommendation = _normalize_json(response.output_text)
        return {
            "alert_id": alert.get("alert_id", "UNKNOWN"),
            "mode": "openai",
            "model": settings.openai_model,
            "recommendation": recommendation,
        }
    except Exception as exc:
        fallback = fallback_recommendation(alert)
        fallback["provider_error"] = str(exc)
        return {
            "alert_id": alert.get("alert_id", "UNKNOWN"),
            "mode": "fallback_after_openai_error",
            "model": settings.openai_model,
            "recommendation": fallback,
        }


def generate_recommendations(alerts_path: Path | None = None, output_path: Path | None = None) -> list[dict]:
    ensure_directories()
    alerts = read_jsonl(alerts_path or settings.alerts_jsonl)
    recommendations = [advise_alert(alert) for alert in alerts]
    write_jsonl(output_path or settings.recommendations_jsonl, recommendations)
    return recommendations


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate structured incident advisor recommendations.")
    parser.add_argument("--alerts", type=Path, default=settings.alerts_jsonl)
    parser.add_argument("--output", type=Path, default=settings.recommendations_jsonl)
    parser.add_argument("--fallback", action="store_true")
    args = parser.parse_args()

    alerts = read_jsonl(args.alerts)
    recommendations = []
    for alert in alerts:
        recommendations.append(advise_alert(alert, force_fallback=args.fallback))
    write_jsonl(args.output, recommendations)
    print(f"Generated {len(recommendations)} recommendations at {args.output}")


if __name__ == "__main__":
    main()
