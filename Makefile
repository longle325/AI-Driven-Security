PYTHON ?= python3
VENV := .venv
BIN := $(VENV)/bin
PY := $(BIN)/python
PIP := $(BIN)/pip
EVENTS := data/logs/events.jsonl
ALERTS := data/logs/alerts.jsonl
LAB_WEB_PORT ?= 5001

.PHONY: setup train simulate-normal simulate-bruteforce simulate-portscan simulate-webattack simulate-spike simulate-mixed detect export-evidence dashboard api lab-web demo test clean-data

setup: $(BIN)/activate

$(BIN)/activate: requirements.txt
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	touch $(BIN)/activate

train: setup
	$(PY) -m src.train_model
	$(PY) -m src.evaluate_model

simulate-normal: setup
	$(PY) -m lab.simulator.simulate_events --scenario normal --count 100 --output $(EVENTS) --replace

simulate-bruteforce: setup
	$(PY) -m lab.simulator.simulate_events --scenario brute_force --count 50 --output $(EVENTS)

simulate-portscan: setup
	$(PY) -m lab.simulator.simulate_events --scenario port_scan --count 50 --output $(EVENTS)

simulate-webattack: setup
	$(PY) -m lab.simulator.simulate_events --scenario web_attack --count 50 --output $(EVENTS)

simulate-spike: setup
	$(PY) -m lab.simulator.simulate_events --scenario traffic_spike --count 50 --output $(EVENTS)

simulate-mixed: setup
	$(PY) -m lab.simulator.simulate_events --scenario mixed --count 300 --output $(EVENTS) --replace

detect: setup
	$(PY) -m src.detect --input $(EVENTS) --output $(ALERTS)

export-evidence: setup
	$(PY) -m src.evidence_exporter

dashboard: setup
	$(BIN)/streamlit run dashboard/app.py --server.headless=true --browser.gatherUsageStats=false

api: setup
	$(BIN)/uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

lab-web: setup
	PORT=$(LAB_WEB_PORT) $(PY) -m lab.web_app.app

demo: train simulate-mixed detect export-evidence dashboard

test: setup
	$(PY) -m pytest -v

clean-data:
	rm -f data/logs/events.jsonl data/logs/alerts.jsonl data/logs/alerts.csv
	rm -rf data/evidence/exports/*
