# Setup Guide

## Docker

```bash
cp .env.example .env
docker compose up --build
```

Dashboard: `http://127.0.0.1:8501`

API docs: `http://127.0.0.1:8000/docs`

Lab web app: `http://127.0.0.1:5001`

## Optional OpenAI Advisor

Default mode is `fallback`. To use OpenAI, edit `.env`:

```bash
LLM_MODE=openai
OPENAI_API_KEY=your_key_here
OPENAI_MODEL=gpt-5.4-mini
```

The LLM explains alerts only. Detection remains rule-based plus ML-based.
