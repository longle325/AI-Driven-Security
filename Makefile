PYTHON ?= python3
VENV := .venv
PIP := $(VENV)/bin/pip
PY := $(VENV)/bin/python

.PHONY: setup frontend-install train evaluate simulate simulate-mixed detect advise export api lab-web frontend test demo docker-up docker-down clean

setup:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

frontend-install:
	cd frontend && npm install

train:
	$(PY) -m src.train_model

evaluate:
	$(PY) -m src.evaluate_model

simulate:
	$(PY) -m lab.simulator.simulate_events --scenario mixed --count 500 --replace

simulate-mixed:
	$(PY) -m lab.simulator.simulate_events --scenario mixed --count 700 --replace

detect:
	$(PY) -m src.detect --input data/logs/events.jsonl --output data/logs/alerts.jsonl

advise:
	$(PY) -m src.llm_advisor --alerts data/logs/alerts.jsonl --output data/logs/llm_recommendations.jsonl

export:
	$(PY) -m src.evidence_exporter

api:
	$(PY) -m uvicorn api.main:app --host 0.0.0.0 --port 8000

lab-web:
	$(PY) -m lab.web_app.app

frontend:
	cd frontend && npm run dev -- --host 0.0.0.0

test:
	$(PY) -m pytest -q

demo: simulate-mixed train detect advise export

docker-up:
	docker compose up --build

docker-down:
	docker compose down

clean:
	rm -rf data/logs/*.jsonl data/logs/*.csv data/processed/*.csv data/evidence/exports/* models/*
