# Demo Script

Target duration: 5-7 minutes.

## 1. Introduce the Project

This is a local AI-driven cyber defense lab. It simulates security events, detects suspicious behavior with rules and machine learning, shows alerts in a dashboard, and exports evidence for a report.

## 2. Show Architecture

Open `docs/architecture.md` and explain:

```text
Lab Web App / Simulator -> Logs -> Preprocessing -> Rules + ML -> Alerts -> Dashboard/Evidence
```

## 3. Start the Lab

Option A:

```bash
docker compose up --build
```

Option B:

```bash
make train
make simulate-mixed
make detect
make export-evidence
make dashboard
```

## 4. Open the Dashboard

Open:

```text
http://localhost:8501
```

Show total events, alerts, high/critical alerts, model F1-score, and latest detection time.

## 5. Generate Normal Traffic

```bash
make simulate-normal
make detect
```

Show that normal traffic does not create critical alerts.

## 6. Generate Brute Force Scenario

```bash
make simulate-bruteforce
make detect
```

Open Live Alerts and show a `brute_force` alert, rule match `R001`, ML result, severity, and recommendation.

## 7. Generate Mixed Scenario

```bash
make simulate-mixed
make detect
```

Show alerts by severity and threat type.

## 8. Show Model Metrics

Open Model Metrics and explain accuracy, precision, recall, F1-score, confusion matrix, and feature importance.

## 9. Export Evidence

```bash
make export-evidence
```

Open:

```text
data/evidence/exports/
```

Show `alerts.csv`, `metrics.json`, `classification_report.txt`, and `demo_summary.md`.

## 10. Explain Ethics and Legal Scope

State that all activity is local and synthetic, no external targets are scanned or attacked, and the model is for defensive monitoring and education.
