# AI-Driven Cyber Defense Lab

Presentation-ready mini SOC lab for an AI-driven cyber defense demo. The system generates safe synthetic security logs, detects threats with a rule baseline and a Random Forest model, creates structured alerts, explains incidents with an LLM Advisor, and exports report-ready evidence.

The lab is defensive and educational only. It uses localhost, Docker networks, synthetic logs, public datasets, and harmless markers. It does not scan, brute-force, exploit, or attack real systems.

## Stack

- Backend: Python, FastAPI, Pandas, Scikit-learn, OpenAI SDK
- Frontend: React, TypeScript, Vite, Recharts, Lucide icons
- Lab source: Flask local web app plus synthetic simulator
- Runtime: Docker Compose or local Python/Node
- Default LLM mode: `fallback`, so the demo runs without an API key

## Model Choice

The default `.env.example` uses `OPENAI_MODEL=gpt-5.4-mini` for the optional OpenAI-backed Incident Advisor. This is the practical default for this project because the advisor task is constrained, structured, and latency-sensitive: it explains an existing alert and returns JSON recommendations. For lower cost, set `OPENAI_MODEL=gpt-5.4-nano`; for higher reasoning quality, set `OPENAI_MODEL=gpt-5.5`.

Detection is still done by rules and the ML model. The LLM only explains alerts and recommends defensive next steps.

## Quick Start With Docker

```bash
cp .env.example .env
docker compose up --build
```

Open:

- Dashboard: http://127.0.0.1:8501
- API: http://127.0.0.1:8000/docs
- Safe lab web app: http://127.0.0.1:5001

If you do not add an API key, the LLM Advisor uses deterministic fallback recommendations.

## Local Development

```bash
make setup
make frontend-install
make demo
make api
```

In a second terminal:

```bash
make frontend
```

Open the frontend at http://127.0.0.1:5173 for local Vite development.

## Demo Flow

```bash
make download-data
make train
make simulate-mixed
make detect
make advise
make export
```

The TypeScript dashboard is a live SOC scenario console. Use Reset, Step, and Auto Stream to send time-series logs through the already-trained model; abnormal predictions are escalated into the Incident Queue. The UI does not train models. Training is an offline CLI/Docker trainer step.

`make download-data` downloads `prantokumar/ids-dataset-2025` from Kaggle and writes a balanced local training sample to `data/raw/ids2025_training_sample.csv`. The full Kaggle files remain outside git under Kaggle's local cache, with a pointer recorded in `data/raw/ids2025_manifest.json`.

The IDS2025 taxonomy used by the model is `normal`, `botnet`, `brute_force`, `dos_ddos`, `web_attack`, and `infiltration`.

## Outputs

- Logs: `data/logs/events.jsonl`, `data/logs/live_logs.csv`
- Detection: `data/logs/detected_logs.csv`
- Alerts: `data/logs/alerts.csv`, `data/logs/alerts.jsonl`
- Recommendations: `data/logs/llm_recommendations.jsonl`
- Model artifacts: `models/threat_model.joblib`, `models/metrics.json`, plots and reports
- Evidence: `data/evidence/exports/`

## Environment

Create `.env` from `.env.example`:

```bash
LLM_MODE=fallback
OPENAI_API_KEY=
OPENAI_MODEL=gpt-5.4-mini
```

To enable OpenAI:

```bash
LLM_MODE=openai
OPENAI_API_KEY=sk-...
```

## Tests

```bash
make test
cd frontend && npm run build
```
