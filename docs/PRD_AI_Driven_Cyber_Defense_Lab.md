# PRD.md — AI-Driven Cyber Defense Lab Demo

## 1. Product Overview

### 1.1 Project Name

**AI-Driven Cyber Defense Lab: Revolutionizing Threat Detection in 2025**

### 1.2 Short Description

Build a high-quality lab demo for a final project in **Software and System Security**. The demo must show an end-to-end AI-driven cyber defense pipeline that collects security logs from a controlled lab environment, detects suspicious behavior using both rule-based and machine learning approaches, displays alerts on a dashboard, and provides clear evidence for analysis, reporting, and presentation.

The system must be safe, educational, and fully runnable on a local machine using Docker Compose.

### 1.3 Core Idea

The demo should look and feel like a mini **AI-powered Security Operations Center (AI-SOC)**:

```text
Lab Web App + Simulated Security Events
        ↓
Log Collection
        ↓
Preprocessing + Feature Engineering
        ↓
Rule-Based Detection + AI/ML Detection
        ↓
Alert Generation
        ↓
Dashboard + Evidence Export
        ↓
Defense Recommendations
```

### 1.4 Primary Goal

Create a polished, runnable, and visually convincing demo that satisfies the A4 final project criteria:

- **G2.2:** show deep understanding of software/system security and produce a complete working product.
- **G4.3:** identify threats, use testing/simulation tools, analyze logs, and propose improvements.
- **G8.1:** demonstrate professional ethics, legal awareness, and safe lab-only testing.

---

## 2. Target Users

### 2.1 Primary Users

- Student team members who need to run and present the demo.
- Lecturer/evaluator who will review the system, report, and presentation.
- Coding agent that will implement the system from this PRD.

### 2.2 User Needs

The final user must be able to:

1. Run the entire lab locally with one or a few commands.
2. Generate normal and suspicious events safely.
3. See logs being processed.
4. See rule-based and AI-based threat detection results.
5. View a dashboard with alerts, charts, severity, model confidence, and evidence.
6. Export results for the final report and slides.
7. Explain the system clearly during presentation.

---

## 3. Success Criteria

The demo is considered successful if it satisfies all of the following:

### 3.1 Product Success

- The system runs locally using Docker Compose.
- The lab does not attack any real external target.
- The demo has a clear web dashboard.
- The system generates or ingests logs.
- The system produces alerts for at least 4 threat types.
- The system compares rule-based detection and ML-based detection.
- The system exports evidence files for the report.

### 3.2 Academic Success

The demo must provide enough evidence for a high score:

- Source code is organized and readable.
- README explains how to run everything.
- Dashboard screenshots can be used in the report.
- Metrics are generated: Accuracy, Precision, Recall, F1-score, confusion matrix.
- Test cases are documented.
- Ethical and legal scope is explicitly stated.
- The lab can be demonstrated within 5–7 minutes.

### 3.3 Demo Success

A presenter should be able to show this flow:

```text
1. Start Docker lab.
2. Open dashboard.
3. Generate normal traffic.
4. Show that normal traffic is not flagged as critical.
5. Generate simulated suspicious events.
6. Show alert creation.
7. Compare rule-based and AI-based detection.
8. Open evidence export.
9. Explain defense recommendations.
```

---

## 4. Project Scope

### 4.1 In Scope

The system must include:

1. A vulnerable/simplified web application for safe lab testing.
2. A log generator or event simulator.
3. A log collector.
4. A preprocessing and feature extraction pipeline.
5. A rule-based baseline detector.
6. An AI/ML-based detection engine.
7. An alert manager.
8. A Streamlit dashboard.
9. Evidence export for reports.
10. Docker Compose for local deployment.
11. README and usage documentation.

### 4.2 Out of Scope

The system must not include:

- Real-world unauthorized scanning.
- Malware execution.
- Exploit automation against public systems.
- Credential theft.
- Data exfiltration.
- Any real personal data.
- Production-level SOC deployment.
- Real-time enterprise SIEM integration as a required feature.

### 4.3 Safe Lab Boundary

All testing must happen inside:

- localhost,
- Docker network,
- simulated logs,
- synthetic dataset,
- public cybersecurity dataset if used.

No external IP or real domain should be scanned, attacked, brute-forced, or tested.

---

## 5. Recommended Tech Stack

### 5.1 Backend and ML

- Python 3.11+
- FastAPI for detection API
- Scikit-learn for ML models
- Pandas and NumPy for preprocessing
- Joblib for model saving/loading
- Pydantic for schemas

### 5.2 Dashboard

- Streamlit
- Plotly or Matplotlib
- Pandas for displaying tables

### 5.3 Lab App

- Flask or FastAPI
- SQLite for simple app data
- Nginx optional for access logs

### 5.4 DevOps

- Docker
- Docker Compose
- Makefile or shell scripts
- GitHub-ready repo structure

### 5.5 Optional Security Tools

Use only in safe local lab mode:

- OWASP ZAP against localhost app
- Nmap against Docker service/container only
- Wireshark or Zeek for packet/log evidence
- Postman for API testing

---

## 6. High-Level Architecture

### 6.1 Component Diagram

```text
+-----------------------+
|  Lab Web Application  |
|  login/search/profile |
+----------+------------+
           |
           v
+-----------------------+
|  App / Access Logs    |
|  JSONL or CSV logs    |
+----------+------------+
           |
           v
+-----------------------+
|  Log Collector        |
|  reads logs/events    |
+----------+------------+
           |
           v
+-----------------------+
|  Preprocessing        |
|  feature extraction   |
+----------+------------+
           |
           +-------------------------+
           |                         |
           v                         v
+----------------------+   +----------------------+
| Rule-Based Detector  |   | ML Detection Engine  |
+----------+-----------+   +----------+-----------+
           |                          |
           +------------+-------------+
                        |
                        v
+--------------------------------------+
| Alert Manager                         |
| severity, reason, confidence, evidence|
+------------------+-------------------+
                   |
                   v
+--------------------------------------+
| Streamlit Dashboard                   |
| alerts, charts, metrics, export       |
+--------------------------------------+
```

### 6.2 Docker Services

Use this Docker Compose service structure:

```text
services:
  lab-web:
    purpose: demo web application that produces logs

  detection-api:
    purpose: FastAPI service for preprocessing and prediction

  dashboard:
    purpose: Streamlit UI

  simulator:
    purpose: generate normal and suspicious lab events

  optional-nginx:
    purpose: access log source, reverse proxy
```

The first stable version can run without nginx. Nginx can be added as a polished enhancement.

---

## 7. Repository Structure

The coding agent should create or refactor the project into this structure:

```text
ai-driven-cyber-defense-lab/
|
+-- README.md
+-- PRD.md
+-- docker-compose.yml
+-- Dockerfile
+-- requirements.txt
+-- Makefile
+-- .gitignore
+-- .env.example
|
+-- data/
|   +-- raw/
|   +-- processed/
|   +-- logs/
|   |   +-- events.jsonl
|   |   +-- alerts.jsonl
|   |   +-- alerts.csv
|   +-- evidence/
|       +-- screenshots/
|       +-- metrics/
|       +-- exports/
|
+-- models/
|   +-- threat_model.joblib
|   +-- scaler.joblib
|   +-- label_encoder.joblib
|   +-- metrics.json
|   +-- confusion_matrix.png
|
+-- src/
|   +-- __init__.py
|   +-- config.py
|   +-- schemas.py
|   +-- preprocessing.py
|   +-- feature_engineering.py
|   +-- train_model.py
|   +-- evaluate_model.py
|   +-- detect.py
|   +-- rules.py
|   +-- alert_manager.py
|   +-- evidence_exporter.py
|
+-- api/
|   +-- main.py
|   +-- routes/
|       +-- health.py
|       +-- detect.py
|       +-- alerts.py
|
+-- dashboard/
|   +-- app.py
|   +-- pages/
|       +-- 1_Overview.py
|       +-- 2_Live_Alerts.py
|       +-- 3_Model_Metrics.py
|       +-- 4_Evidence_Export.py
|
+-- lab/
|   +-- web_app/
|   |   +-- app.py
|   |   +-- templates/
|   |   +-- static/
|   |   +-- lab_app.db
|   |
|   +-- simulator/
|       +-- simulate_events.py
|       +-- scenarios.py
|       +-- safe_payloads.py
|
+-- tests/
|   +-- test_preprocessing.py
|   +-- test_rules.py
|   +-- test_detection.py
|
+-- docs/
    +-- architecture.md
    +-- demo_script.md
    +-- ethics_and_legal_scope.md
    +-- test_cases.md
```

---

## 8. Functional Requirements

### FR-01: Local Lab Web Application

Build a simple web app that has the following pages/endpoints:

| Endpoint | Purpose |
|---|---|
| `/` | Home page |
| `/login` | Login form |
| `/search` | Search page |
| `/profile` | User profile |
| `/admin` | Admin-like page for testing access events |
| `/health` | Health check |

The app must generate structured logs for every important event.

#### Required log events

- Successful login
- Failed login
- Search request
- Suspicious search query marker
- Access to admin page
- Rate spike simulation
- API request event
- Error event

#### Log format

Use JSONL format. Each line must be one event:

```json
{
  "timestamp": "2026-05-26T10:00:00Z",
  "source_ip": "172.20.0.5",
  "user_id": "user_01",
  "event_type": "login_failed",
  "endpoint": "/login",
  "http_method": "POST",
  "status_code": 401,
  "request_count_1m": 12,
  "failed_login_count_5m": 8,
  "unique_ports_1m": 1,
  "payload_risk_score": 0.2,
  "user_agent": "lab-client",
  "label": "brute_force"
}
```

### FR-02: Event Simulator

Create a safe simulator that generates lab events without attacking real systems.

The simulator must support these scenarios:

| Scenario | Description |
|---|---|
| `normal` | Normal browsing and login behavior |
| `port_scan` | Simulated port scan-like log pattern |
| `brute_force` | Many failed login events |
| `web_attack` | Suspicious request markers for SQLi/XSS-like attempts in lab |
| `traffic_spike` | Sudden increase in requests |
| `mixed` | Combined normal and suspicious traffic |

Important: the simulator must not perform real attacks. It should generate logs or send harmless requests to the local lab app only.

Command examples:

```bash
python lab/simulator/simulate_events.py --scenario normal --count 100
python lab/simulator/simulate_events.py --scenario brute_force --count 50
python lab/simulator/simulate_events.py --scenario mixed --count 300
```

### FR-03: Preprocessing Pipeline

Implement preprocessing that:

- Reads JSONL/CSV logs.
- Handles missing values.
- Converts categorical fields to numerical features.
- Creates time-window features.
- Normalizes/scales numeric features when needed.
- Produces model-ready data.

Required feature examples:

| Feature | Meaning |
|---|---|
| `request_count_1m` | Number of requests in one minute |
| `failed_login_count_5m` | Number of failed logins in five minutes |
| `unique_endpoints_5m` | Number of unique endpoints accessed |
| `unique_ports_1m` | Number of unique ports touched |
| `status_4xx_count_5m` | Number of 4xx responses |
| `status_5xx_count_5m` | Number of 5xx responses |
| `payload_risk_score` | Risk score from suspicious string markers |
| `avg_request_interval` | Average delay between requests |
| `endpoint_risk_score` | Risk of endpoint being accessed |
| `method_encoded` | Encoded HTTP method |

### FR-04: Rule-Based Baseline Detector

Implement a baseline detector using transparent rules.

Required rules:

| Rule ID | Detection Logic |
|---|---|
| `R001` | Failed login count exceeds threshold |
| `R002` | Unique ports exceed threshold |
| `R003` | Request count per minute exceeds threshold |
| `R004` | Suspicious payload marker exists |
| `R005` | Too many 4xx/5xx errors in short time |
| `R006` | Repeated admin access failure |

Each rule output must include:

```json
{
  "is_threat": true,
  "threat_type": "brute_force",
  "severity": "high",
  "reason": "failed_login_count_5m exceeded threshold",
  "detector": "rule_based"
}
```

### FR-05: ML Detection Engine

Build an ML model that classifies events into:

- `normal`
- `port_scan`
- `brute_force`
- `web_attack`
- `traffic_spike`

Minimum model requirement:

- Random Forest classifier.
- Train/test split.
- Evaluation metrics.
- Saved model with Joblib.
- Prediction confidence.

Optional advanced models:

- Isolation Forest for anomaly detection.
- XGBoost if dependency is acceptable.
- Autoencoder only if time allows.

Required output:

```json
{
  "predicted_label": "brute_force",
  "confidence": 0.93,
  "is_threat": true,
  "top_features": [
    "failed_login_count_5m",
    "request_count_1m",
    "status_4xx_count_5m"
  ],
  "detector": "ml_random_forest"
}
```

### FR-06: Alert Manager

The Alert Manager combines rule-based and ML results.

Alert format:

```json
{
  "alert_id": "ALERT-20260526-0001",
  "timestamp": "2026-05-26T10:05:00Z",
  "threat_type": "brute_force",
  "severity": "high",
  "source_ip": "172.20.0.5",
  "endpoint": "/login",
  "rule_result": {
    "is_threat": true,
    "reason": "failed_login_count_5m exceeded threshold"
  },
  "ml_result": {
    "predicted_label": "brute_force",
    "confidence": 0.93
  },
  "recommended_action": "Enable rate limiting and temporary account lockout.",
  "evidence": {
    "log_file": "data/logs/events.jsonl",
    "event_index": 152
  }
}
```

Severity mapping:

| Severity | Condition |
|---|---|
| Critical | ML confidence high and rule-based detection also flags threat |
| High | ML confidence high or strong rule match |
| Medium | ML confidence medium or weak rule match |
| Low | Suspicious but uncertain |
| Informational | Normal or benign event |

### FR-07: Dashboard

Build a Streamlit dashboard with the following pages.

#### Page 1: Overview

Must show:

- Total events processed
- Total alerts
- Alerts by severity
- Alerts by threat type
- Latest alert
- Detection pipeline diagram
- System status

#### Page 2: Live Alerts

Must show:

- Alert table
- Filter by threat type
- Filter by severity
- Filter by detector
- Search by source IP or endpoint
- Alert details panel
- Recommended action

#### Page 3: Model Metrics

Must show:

- Accuracy
- Precision
- Recall
- F1-score
- Confusion matrix image
- Classification report
- Rule-based vs ML comparison
- Feature importance chart if available

#### Page 4: Evidence Export

Must show:

- Export alerts to CSV
- Export metrics to JSON
- Export test case summary
- Download-ready evidence bundle
- Demo checklist

### FR-08: Evidence Exporter

Generate files useful for the final report:

```text
data/evidence/exports/
|
+-- alerts.csv
+-- alerts.jsonl
+-- metrics.json
+-- classification_report.txt
+-- test_case_results.md
+-- demo_summary.md
```

`demo_summary.md` must include:

- Number of events
- Number of alerts
- Threat types detected
- Best model
- Key screenshots to capture manually
- Ethical scope note

### FR-09: Test Case Documentation

Create `docs/test_cases.md` containing a test table:

| TC ID | Scenario | Input | Expected Result | Evidence |
|---|---|---|---|---|
| TC01 | Normal traffic | Simulated normal events | No critical alert | events.jsonl |
| TC02 | Port scan | Simulated scan pattern | Port scan alert | alerts.csv |
| TC03 | Brute force | Failed login burst | Brute force alert | dashboard screenshot |
| TC04 | Web attack | Suspicious request marker | Web attack alert | request log |
| TC05 | Traffic spike | Request spike | Traffic spike alert | chart |
| TC06 | False positive case | High but normal traffic | Low/medium or no alert | analysis |
| TC07 | False negative case | Weak suspicious pattern | May be missed, documented | analysis |

### FR-10: Ethics and Legal Scope Documentation

Create `docs/ethics_and_legal_scope.md`.

It must clearly state:

- The demo only runs in a local lab.
- No real external target is attacked.
- No personal data is collected.
- All data is synthetic or from public datasets.
- The project does not distribute malware.
- The project does not provide instructions for attacking real systems.
- AI is used for defensive monitoring and education only.
- Model limitations are disclosed honestly.

---

## 9. Non-Functional Requirements

### 9.1 Usability

- One-command or near-one-command setup.
- Clear dashboard.
- Clear README.
- Simple demo script.
- No complicated cloud dependency.

### 9.2 Reliability

- The demo should work offline after dependency installation.
- The app should not crash if logs are missing.
- The dashboard should display helpful messages when no alerts exist.

### 9.3 Security and Safety

- No real attacks.
- No hardcoded real credentials.
- No external scanning.
- No malware.
- No sensitive data.
- All risky-looking events are simulated markers in local logs.

### 9.4 Performance

- Must handle at least 5,000 synthetic events locally.
- Dashboard should load within a few seconds.
- Model training on synthetic data should complete within 1–3 minutes on a normal laptop.

### 9.5 Maintainability

- Modular code.
- Clear function names.
- Type hints where practical.
- Basic tests for preprocessing, rules, and detection.
- Configurable thresholds.

---

## 10. CLI Commands

The final system should support these commands.

### 10.1 Setup

```bash
make setup
```

Equivalent to:

```bash
python -m venv .venv
pip install -r requirements.txt
```

### 10.2 Train Model

```bash
make train
```

Equivalent to:

```bash
python src/train_model.py
python src/evaluate_model.py
```

### 10.3 Generate Logs

```bash
make simulate-normal
make simulate-bruteforce
make simulate-portscan
make simulate-webattack
make simulate-spike
make simulate-mixed
```

### 10.4 Run Detection

```bash
make detect
```

Equivalent to:

```bash
python src/detect.py --input data/logs/events.jsonl --output data/logs/alerts.jsonl
```

### 10.5 Run Dashboard

```bash
make dashboard
```

Equivalent to:

```bash
streamlit run dashboard/app.py
```

### 10.6 Run Full Demo

```bash
make demo
```

Expected flow:

```text
1. Generate mixed logs.
2. Train/load model.
3. Run detection.
4. Export evidence.
5. Start dashboard.
```

### 10.7 Docker

```bash
docker compose up --build
```

---

## 11. API Requirements

If FastAPI is implemented, expose these endpoints:

| Endpoint | Method | Purpose |
|---|---|---|
| `/health` | GET | Health check |
| `/detect/event` | POST | Detect one event |
| `/detect/batch` | POST | Detect batch events |
| `/alerts` | GET | List alerts |
| `/metrics` | GET | Return model metrics |
| `/export/evidence` | POST | Generate evidence export |

Example request:

```json
{
  "timestamp": "2026-05-26T10:00:00Z",
  "source_ip": "172.20.0.5",
  "event_type": "login_failed",
  "endpoint": "/login",
  "status_code": 401,
  "request_count_1m": 12,
  "failed_login_count_5m": 8,
  "unique_ports_1m": 1,
  "payload_risk_score": 0.0
}
```

Example response:

```json
{
  "is_threat": true,
  "threat_type": "brute_force",
  "severity": "high",
  "confidence": 0.93,
  "recommended_action": "Enable rate limiting and temporary account lockout."
}
```

---

## 12. Data Requirements

### 12.1 Required Event Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `timestamp` | string | yes | ISO datetime |
| `source_ip` | string | yes | Local/synthetic IP |
| `user_id` | string | no | Synthetic user ID |
| `event_type` | string | yes | Event category |
| `endpoint` | string | yes | URL endpoint or service |
| `http_method` | string | no | GET/POST/etc. |
| `status_code` | int | yes | HTTP status |
| `request_count_1m` | int | yes | Requests in one minute |
| `failed_login_count_5m` | int | yes | Failed logins in five minutes |
| `unique_ports_1m` | int | yes | Unique ports in one minute |
| `status_4xx_count_5m` | int | yes | 4xx errors |
| `status_5xx_count_5m` | int | yes | 5xx errors |
| `payload_risk_score` | float | yes | Suspicious marker score |
| `label` | string | no | Ground truth for training |

### 12.2 Labels

Use the following labels:

```text
normal
port_scan
brute_force
web_attack
traffic_spike
```

### 12.3 Synthetic Data Generation

The training script may generate synthetic data if no real/public dataset exists.

Each class should have enough examples:

| Label | Minimum Rows |
|---|---|
| normal | 1000 |
| port_scan | 500 |
| brute_force | 500 |
| web_attack | 500 |
| traffic_spike | 500 |

Total minimum synthetic dataset size: **3,000 rows**.

---

## 13. ML Requirements

### 13.1 Model

Minimum:

- Random Forest classifier.

Recommended parameters:

```python
RandomForestClassifier(
    n_estimators=200,
    max_depth=None,
    random_state=42,
    class_weight="balanced"
)
```

### 13.2 Evaluation

Generate:

- Accuracy
- Precision
- Recall
- F1-score
- Classification report
- Confusion matrix
- Feature importance chart

### 13.3 Target Quality

Because this is a controlled synthetic/lab demo, expected target:

| Metric | Target |
|---|---|
| Accuracy | >= 0.85 |
| Macro F1-score | >= 0.80 |
| Recall for threats | >= 0.80 |

If metrics are lower, document limitations and explain why.

### 13.4 Model Explainability

Add simple explainability:

- Feature importance for Random Forest.
- Show top 3–5 important features.
- Include top features in dashboard.

---

## 14. Dashboard UX Requirements

### 14.1 Visual Style

The dashboard should look professional and presentation-ready:

- Clear title.
- Clean cards for KPIs.
- Tables with filters.
- Charts for alerts and metrics.
- Color-coded severity.
- Short explanation text for each page.

### 14.2 Dashboard Sections

#### Overview Cards

- Events processed
- Alerts generated
- High/Critical alerts
- ML model F1-score
- Last detection time

#### Charts

- Alerts by threat type
- Alerts by severity
- Events over time
- Rule-based vs ML detection count
- Feature importance

#### Tables

- Latest events
- Latest alerts
- Test case results

---

## 15. Recommended Actions Mapping

The system should generate defensive recommendations.

| Threat Type | Recommended Action |
|---|---|
| `port_scan` | Restrict exposed services, review firewall rules, monitor repeated scanning sources. |
| `brute_force` | Enable rate limiting, account lockout, MFA, and stronger authentication logging. |
| `web_attack` | Validate inputs, use parameterized queries, output encoding, and WAF rules. |
| `traffic_spike` | Apply rate limiting, autoscaling, queueing, and DDoS protection strategy. |
| `normal` | No action required. Continue monitoring. |

---

## 16. Demo Script

Create `docs/demo_script.md`.

The demo script should be 5–7 minutes.

### Demo Flow

```text
Step 1: Introduce the project.
Step 2: Show architecture diagram.
Step 3: Start the lab.
Step 4: Open dashboard.
Step 5: Generate normal traffic.
Step 6: Show normal logs.
Step 7: Generate brute-force scenario.
Step 8: Run detection.
Step 9: Show alert and recommendation.
Step 10: Generate mixed scenario.
Step 11: Show alerts by threat type.
Step 12: Show model metrics and confusion matrix.
Step 13: Show evidence export.
Step 14: Explain ethics and legal scope.
```

### Demo Commands

```bash
docker compose up --build
make simulate-normal
make detect
make simulate-bruteforce
make detect
make simulate-mixed
make detect
make export-evidence
```

---

## 17. README Requirements

The README must include:

1. Project title.
2. Project overview.
3. Architecture diagram.
4. Features.
5. Tech stack.
6. Folder structure.
7. Setup guide.
8. Run guide.
9. Demo commands.
10. Test scenarios.
11. Model metrics.
12. Evidence export.
13. Ethical and legal scope.
14. Limitations.
15. Future work.

---

## 18. Testing Requirements

### 18.1 Unit Tests

Add tests for:

- Preprocessing missing values.
- Feature extraction.
- Rule-based detection.
- ML prediction output schema.
- Alert severity mapping.

### 18.2 Manual Tests

Document manual tests in `docs/test_cases.md`.

### 18.3 Acceptance Test

The following command sequence must work:

```bash
make setup
make train
make simulate-mixed
make detect
make export-evidence
make dashboard
```

Or Docker equivalent:

```bash
docker compose up --build
```

---

## 19. Acceptance Criteria

### AC-01: Complete Local Setup

Given a fresh machine with Python and Docker, the user can run the project using README instructions.

### AC-02: Synthetic Logs Generated

The simulator can generate at least 5 event types:

- normal
- port_scan
- brute_force
- web_attack
- traffic_spike

### AC-03: Model Training Works

The training script produces:

- saved model
- metrics JSON
- classification report
- confusion matrix

### AC-04: Detection Works

The detection script reads events and produces alerts.

### AC-05: Rule-Based Baseline Works

Rules produce clear reasons for alerts.

### AC-06: ML Detection Works

ML model predicts threat type and confidence.

### AC-07: Dashboard Works

Streamlit dashboard shows:

- events
- alerts
- charts
- metrics
- evidence export

### AC-08: Evidence Export Works

Evidence files are created under:

```text
data/evidence/exports/
```

### AC-09: Ethical Scope Exists

`docs/ethics_and_legal_scope.md` exists and clearly states safe lab-only boundaries.

### AC-10: Presentation-Ready

The project includes:

- README
- architecture docs
- demo script
- test cases
- evidence exports

---

## 20. Implementation Priority

### Phase 1: Core Working Demo

Must implement first:

1. Synthetic log generator.
2. Preprocessing.
3. Rule-based detector.
4. Random Forest model.
5. Detection script.
6. Alerts output.
7. Basic dashboard.

### Phase 2: Polished Lab

Add:

1. Lab web app.
2. Docker Compose.
3. More realistic event generation.
4. Evidence exporter.
5. Better dashboard charts.
6. README and docs.

### Phase 3: High-Quality Presentation

Add:

1. Feature importance.
2. Confusion matrix image.
3. Test case result export.
4. Demo script.
5. Ethics/legal scope doc.
6. Screenshots and report-ready artifacts.

### Phase 4: Optional Advanced Features

Only if time remains:

1. Isolation Forest anomaly detection.
2. FastAPI detection API.
3. Zeek/Wireshark sample logs.
4. OWASP ZAP localhost scan evidence.
5. Real-time file watcher for logs.
6. Dark-mode dashboard theme.

---

## 21. Constraints for Coding Agent

The coding agent must follow these rules:

1. Do not write code that attacks external systems.
2. Do not include real exploit payloads intended for real systems.
3. Keep all simulations local and harmless.
4. Prefer synthetic markers over dangerous payloads.
5. Use simple, stable dependencies.
6. Ensure project runs on macOS/Linux/WSL.
7. Avoid Conda.
8. Use `pathlib.Path` for file paths.
9. Keep README commands simple.
10. Write modular and readable code.

---

## 22. Final Deliverables

The final project must include:

| Deliverable | Required |
|---|---|
| Source code | Yes |
| Docker Compose | Yes |
| README.md | Yes |
| PRD.md | Yes |
| Dashboard | Yes |
| ML model | Yes |
| Rule-based detector | Yes |
| Synthetic log generator | Yes |
| Evidence export | Yes |
| Test cases doc | Yes |
| Demo script | Yes |
| Ethics/legal doc | Yes |
| Metrics and confusion matrix | Yes |
| Report-ready screenshots | Recommended |
| Video demo | Recommended |

---

## 23. Future Work

Document these as future improvements:

- Real-time streaming detection.
- Integration with Wazuh, ELK, or Splunk.
- Support for CICIDS2017 or UNSW-NB15 ingestion.
- Explainable AI with SHAP.
- Model drift monitoring.
- Automated incident response playbooks.
- Integration with firewall/IDS rules.
- Threat intelligence enrichment.
- Role-based dashboard access control.

---

## 24. Final Notes for Coding Agent

The expected final result is not just a script. It should be a complete, polished, presentation-ready cybersecurity lab.

The most important demo story is:

```text
We built a safe local cyber defense lab.
The lab generates security logs.
A baseline detector catches simple known patterns.
An AI model detects and classifies suspicious behavior.
The dashboard shows alerts, confidence, severity, and recommendations.
The system exports evidence for academic reporting.
Everything is ethical, legal, local, and reproducible.
```

Build the system in small working increments. After each phase, ensure the project can still run end-to-end.
