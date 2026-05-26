# PRD — AI-Driven Cyber Defense Lab Demo

**Project:** The Rise of AI-Driven Cyber Defense: Revolutionizing Threat Detection in 2025  
**Implementation Name:** AI-Driven Cyber Defense Lab with LLM Incident Advisor  
**Target:** Coding agent, nhóm sinh viên, báo cáo và demo cuối kỳ  
**Main Goal:** Xây dựng một demo website/lab hoàn chỉnh cho hệ thống phòng thủ mạng ứng dụng AI, có detection model, rule-based baseline, alert manager, LLM recommendation và dashboard trực quan.

---

## 1. Product Overview

Đồ án xây dựng một hệ thống demo dạng **mini AI-powered SOC**. Hệ thống nhận dữ liệu từ IDS dataset hoặc log giả lập trong lab, tiền xử lý dữ liệu, phát hiện threat bằng rule-based detector và ML model, sinh cảnh báo, sau đó dùng LLM đọc cảnh báo để đề xuất các bước tiếp theo cho người dùng.

Pipeline tổng thể:

```text
IDS Dataset / Synthetic Lab Logs
→ Data Loading
→ Preprocessing + Feature Engineering
→ Rule-Based Detection
→ ML-Based Threat Detection
→ Alert Manager
→ LLM Incident Advisor
→ Security Dashboard
→ Evidence Export
```

Điểm quan trọng: **Detection model chịu trách nhiệm phát hiện threat**, còn **LLM chịu trách nhiệm giải thích incident và đề xuất next steps**. LLM không thay thế model và không tự động thực thi hành động phản ứng.

---

## 2. Product Goals

Hệ thống cần đạt các mục tiêu sau:

1. Có thể chạy local bằng Python hoặc Docker.
2. Có thể sinh log giả lập an toàn trong môi trường lab.
3. Có thể dùng IDS Dataset 2025 hoặc dataset IDS tương tự để train/evaluate model.
4. Có rule-based detector để làm baseline.
5. Có ML detection model để phân loại threat.
6. Có alert manager để tạo cảnh báo có severity, confidence và recommended action.
7. Có LLM Incident Advisor để đọc alert và sinh incident summary, investigation steps, mitigation actions.
8. Có dashboard hiển thị log, alert, metrics, rule vs AI, LLM recommendation và evidence export.
9. Có file evidence để đưa vào báo cáo cuối kỳ.
10. Có tài liệu đạo đức/pháp lý, đảm bảo demo chỉ chạy trong lab.

---

## 3. Product Scope

### 3.1. In Scope

- Website dashboard bằng Streamlit.
- Synthetic log simulator.
- Dataset loader cho CSV/JSONL.
- Preprocessing và feature engineering.
- Rule-based detector.
- ML detection model.
- Alert manager.
- LLM Incident Advisor.
- Evidence exporter.
- Docker/Docker Compose.
- README, docs, demo script, test cases.

### 3.2. Out of Scope

- Không làm production SOC/SIEM hoàn chỉnh.
- Không scan IP public.
- Không brute-force hệ thống thật.
- Không khai thác lỗ hổng thật ngoài lab.
- Không dùng dữ liệu cá nhân thật.
- Không triển khai malware.
- Không cho LLM tự động thực thi response action.

### 3.3. Safe Lab Boundary

Tất cả kiểm thử chỉ được thực hiện trong:

```text
localhost
Docker network
synthetic logs
public dataset
self-built lab application
```

---

## 4. Target Users

| User | Need |
|---|---|
| Sinh viên | Chạy demo, lấy minh chứng, trình bày pipeline |
| Giảng viên | Xem sản phẩm chạy thật, có phân tích và evidence |
| Người chấm | Đánh giá kỹ thuật, bảo mật, đạo đức và pháp lý |
| Coding agent | Dựa vào PRD để triển khai code |
| Người xem demo | Hiểu threat, alert và next steps |

---

## 5. Demo Story

Demo cần kể được câu chuyện sau:

```text
1. Hệ thống sinh hoặc load security logs.
2. Rule-based detector phát hiện các pattern rõ ràng.
3. ML model phân loại threat.
4. Alert manager tạo cảnh báo có severity và confidence.
5. LLM Advisor đọc alert và đề xuất bước xử lý tiếp theo.
6. Dashboard hiển thị mọi thứ rõ ràng.
7. Evidence được export để đưa vào báo cáo.
```

Demo flow 5–7 phút:

```text
1. Mở dashboard Overview.
2. Giới thiệu pipeline.
3. Sinh mixed logs trong lab.
4. Chạy detection engine.
5. Mở Threat Alerts để xem cảnh báo.
6. Chọn một alert brute_force hoặc web_attack.
7. Mở LLM Advisor để xem incident summary và next steps.
8. Mở Model Metrics để xem Precision/Recall/F1/confusion matrix.
9. Mở Rule vs AI để so sánh hai detector.
10. Mở Evidence Export để xuất minh chứng.
11. Kết luận về ethical scope.
```

---

## 6. High-Level Architecture

```text
+-----------------------------+
| IDS Dataset / Lab Simulator |
+--------------+--------------+
               |
               v
+-----------------------------+
| Data Loader                 |
| CSV / JSONL Reader          |
+--------------+--------------+
               |
               v
+-----------------------------+
| Preprocessing               |
| Cleaning, Encoding, Scaling |
+--------------+--------------+
               |
               v
+-----------------------------+
| Feature Engineering         |
| Security Features           |
+--------------+--------------+
               |
               +--------------------------+
               |                          |
               v                          v
+-----------------------------+  +-----------------------------+
| Rule-Based Detector         |  | ML Detection Model          |
| Transparent Rules           |  | Random Forest / XGBoost     |
+--------------+--------------+  +--------------+--------------+
               |                            |
               +-------------+--------------+
                             |
                             v
+--------------------------------------------------------------+
| Alert Manager                                                |
| threat_type, severity, confidence, reason, recommended action|
+-----------------------------+--------------------------------+
                              |
                              v
+--------------------------------------------------------------+
| LLM Incident Advisor                                         |
| summary, explanation, next steps, mitigation, evidence       |
+-----------------------------+--------------------------------+
                              |
                              v
+--------------------------------------------------------------+
| Streamlit Dashboard                                          |
| overview, logs, alerts, metrics, rule vs AI, LLM, export     |
+-----------------------------+--------------------------------+
                              |
                              v
+--------------------------------------------------------------+
| Evidence Export                                              |
| alerts.csv, metrics.json, recommendation_summary.md          |
+--------------------------------------------------------------+
```

---

## 7. Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.11+ |
| Data processing | Pandas, NumPy |
| ML | Scikit-learn |
| Model storage | Joblib |
| Dashboard | Streamlit |
| Visualization | Plotly, Matplotlib |
| Format | CSV, JSONL, JSON, Markdown |
| Deployment | Docker, Docker Compose |
| Optional API | FastAPI |
| Optional LLM | Local LLM/Ollama-compatible endpoint hoặc API provider |

Default LLM mode phải là `fallback` để demo chạy được ngay cả khi không có API key.

---

## 8. Repository Structure

```text
ai-driven-cyber-defense-demo/
│
├── README.md
├── PRD.md
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── Makefile
├── .gitignore
├── .env.example
│
├── data/
│   ├── raw/
│   ├── processed/
│   ├── logs/
│   │   ├── events.jsonl
│   │   ├── live_logs.csv
│   │   ├── detected_logs.csv
│   │   ├── alerts.csv
│   │   ├── alerts.jsonl
│   │   └── llm_recommendations.jsonl
│   └── evidence/
│       ├── screenshots/
│       └── exports/
│           ├── alerts.csv
│           ├── metrics.json
│           ├── classification_report.txt
│           ├── demo_summary.md
│           ├── recommendation_summary.md
│           └── llm_recommendations.jsonl
│
├── models/
│   ├── threat_model.joblib
│   ├── label_encoder.joblib
│   ├── scaler.joblib
│   ├── metrics.json
│   ├── classification_report.txt
│   ├── confusion_matrix.png
│   └── feature_importance.png
│
├── src/
│   ├── __init__.py
│   ├── config.py
│   ├── schemas.py
│   ├── data_loader.py
│   ├── preprocessing.py
│   ├── feature_engineering.py
│   ├── train_model.py
│   ├── evaluate_model.py
│   ├── rules.py
│   ├── detect.py
│   ├── alert_manager.py
│   ├── recommendation.py
│   ├── llm_advisor.py
│   ├── prompt_templates.py
│   ├── recommendation_fallback.py
│   └── evidence_exporter.py
│
├── lab/
│   ├── web_app/
│   │   ├── app.py
│   │   ├── templates/
│   │   └── static/
│   └── simulator/
│       ├── simulate_events.py
│       ├── scenarios.py
│       └── safe_payloads.py
│
├── dashboard/
│   ├── app.py
│   └── pages/
│       ├── 1_Overview.py
│       ├── 2_Live_Logs.py
│       ├── 3_Threat_Alerts.py
│       ├── 4_Model_Metrics.py
│       ├── 5_Rule_vs_AI.py
│       ├── 6_LLM_Advisor.py
│       └── 7_Evidence_Export.py
│
├── tests/
│   ├── test_preprocessing.py
│   ├── test_rules.py
│   ├── test_detection.py
│   ├── test_alert_manager.py
│   └── test_llm_fallback.py
│
└── docs/
    ├── architecture.md
    ├── setup_guide.md
    ├── demo_script.md
    ├── test_cases.md
    ├── ethics_and_legal_scope.md
    ├── dataset_notes.md
    └── llm_advisor_design.md
```

---

## 9. Data Requirements

Hệ thống hỗ trợ hai nguồn dữ liệu:

| Source | Purpose |
|---|---|
| IDS Dataset 2025 hoặc dataset IDS tương tự | Train/evaluate ML model |
| Synthetic lab logs | Demo live trên dashboard |

Các nhãn chuẩn hóa:

```text
normal
port_scan
brute_force
web_attack
traffic_spike
```

Log schema cho demo:

| Field | Type | Required | Description |
|---|---|---|---|
| timestamp | string | yes | ISO datetime |
| source_ip | string | yes | IP giả lập/local |
| user_id | string | no | synthetic user |
| event_type | string | yes | event category |
| endpoint | string | yes | app endpoint |
| http_method | string | no | GET/POST |
| status_code | int | yes | HTTP status |
| request_count_1m | int | yes | requests in 1 minute |
| failed_login_count_5m | int | yes | failed logins in 5 minutes |
| unique_ports_1m | int | yes | unique ports in 1 minute |
| status_4xx_count_5m | int | yes | 4xx count |
| status_5xx_count_5m | int | yes | 5xx count |
| payload_risk_score | float | yes | suspicious marker score |
| avg_request_interval | float | no | average request interval |
| endpoint_risk_score | float | no | endpoint risk score |
| label | string | no | ground truth label |

Example JSONL event:

```json
{
  "timestamp": "2026-05-26T10:00:00",
  "source_ip": "10.0.0.5",
  "user_id": "user_01",
  "event_type": "login_failed",
  "endpoint": "/login",
  "http_method": "POST",
  "status_code": 401,
  "request_count_1m": 15,
  "failed_login_count_5m": 10,
  "unique_ports_1m": 1,
  "status_4xx_count_5m": 10,
  "status_5xx_count_5m": 0,
  "payload_risk_score": 0.1,
  "label": "brute_force"
}
```

Preprocessing phải xử lý được missing values, infinity values, duplicated rows, inconsistent column names, categorical fields, label imbalance và unknown labels.

---

## 10. Threat Types

| Threat | Description | Key Features |
|---|---|---|
| normal | Traffic bình thường | low error, normal volume |
| port_scan | Dò quét cổng/dịch vụ | high unique ports |
| brute_force | Đăng nhập sai nhiều lần | high failed login count |
| web_attack | Request web bất thường | high payload risk score |
| traffic_spike | Tăng traffic đột biến | high request count |

Recommended action mapping:

| Threat | Recommended Action |
|---|---|
| port_scan | Review exposed services, restrict unnecessary ports, monitor repeated scanning sources. |
| brute_force | Enable rate limiting, account lockout, MFA, and stronger authentication logging. |
| web_attack | Validate inputs, use parameterized queries, output encoding, and WAF-style rules. |
| traffic_spike | Apply rate limiting, autoscaling, queueing, and DDoS protection strategy. |
| normal | No immediate action required. Continue monitoring. |

---

## 11. Functional Requirements

### FR-01: Dataset Loader

Module `src/data_loader.py` phải đọc CSV/JSONL, hỗ trợ nhiều CSV trong `data/raw`, chuẩn hóa tên cột, phát hiện label column nếu có và xuất dataframe chuẩn cho preprocessing.

Output:

```text
src/data_loader.py
data/processed/loaded_dataset.csv
```

Acceptance criteria:

- Load được CSV dataset.
- Load được JSONL lab logs.
- Không crash nếu thiếu optional columns.
- Có dataframe chuẩn cho preprocessing.

---

### FR-02: Preprocessing Module

Module `src/preprocessing.py` phải xử lý infinity values, missing values, categorical encoding, label encoding, scaling nếu cần, train/test split và lưu processed data.

Output:

```text
src/preprocessing.py
data/processed/train.csv
data/processed/test.csv
models/label_encoder.joblib
models/scaler.joblib
```

Acceptance criteria:

- Raw data chuyển thành model-ready data.
- Missing/infinity values được xử lý.
- Label encoder được lưu.
- Pipeline reproducible.

---

### FR-03: Feature Engineering

Module `src/feature_engineering.py` tạo các feature bảo mật:

```text
request_count_1m
failed_login_count_5m
unique_ports_1m
status_4xx_count_5m
status_5xx_count_5m
payload_risk_score
endpoint_risk_score
avg_request_interval
```

Acceptance criteria:

- Feature columns nhất quán giữa train và inference.
- Missing features được fill bằng default value.
- Feature list được document rõ.

---

### FR-04: Synthetic Lab Log Simulator

Simulator sinh log an toàn, không tấn công hệ thống thật.

Supported scenarios:

```text
normal
port_scan
brute_force
web_attack
traffic_spike
mixed
```

Commands:

```bash
python lab/simulator/simulate_events.py --scenario normal --count 100
python lab/simulator/simulate_events.py --scenario brute_force --count 100
python lab/simulator/simulate_events.py --scenario mixed --count 500
```

Output:

```text
data/logs/events.jsonl
data/logs/live_logs.csv
```

Acceptance criteria:

- Sinh được tất cả scenarios.
- Log đúng schema.
- Có label để demo/evaluate.
- Không gọi target bên ngoài.

---

### FR-05: Rule-Based Detector

Module `src/rules.py` tạo baseline detection bằng luật.

Rules:

| Rule ID | Detection Logic | Threat |
|---|---|---|
| R001 | failed_login_count_5m vượt threshold | brute_force |
| R002 | unique_ports_1m vượt threshold | port_scan |
| R003 | request_count_1m vượt threshold | traffic_spike |
| R004 | payload_risk_score vượt threshold | web_attack |
| R005 | quá nhiều 4xx/5xx errors | suspicious |
| R006 | repeated admin access failure | suspicious |

Rule output:

```json
{
  "is_threat": true,
  "threat_type": "brute_force",
  "severity": "high",
  "reason": "failed_login_count_5m exceeded threshold",
  "detector": "rule_based"
}
```

Acceptance criteria:

- Mỗi rule có reason rõ ràng.
- Threshold configurable.
- Kết quả rule có thể so sánh với ML.

---

### FR-06: ML Detection Model

Model tối thiểu: **Random Forest Classifier**.

Optional:

```text
Logistic Regression
XGBoost
Isolation Forest
```

Metrics cần sinh:

```text
Accuracy
Precision
Recall
F1-score
Classification report
Confusion matrix
Feature importance
```

Output:

```text
src/train_model.py
src/evaluate_model.py
models/threat_model.joblib
models/metrics.json
models/classification_report.txt
models/confusion_matrix.png
models/feature_importance.png
```

Acceptance criteria:

- Train được model.
- Load được model cho inference.
- Metrics được lưu.
- Confusion matrix được sinh.
- Feature importance được sinh nếu model hỗ trợ.

---

### FR-07: Detection Engine

Module `src/detect.py` chạy end-to-end detection.

Flow:

```text
Input logs
→ Preprocess
→ Rule detector
→ ML detector
→ Alert manager
→ alerts.csv / alerts.jsonl
```

Command:

```bash
python src/detect.py --input data/logs/events.jsonl --output data/logs/alerts.csv
```

Output:

```text
data/logs/detected_logs.csv
data/logs/alerts.csv
data/logs/alerts.jsonl
```

Acceptance criteria:

- Đọc được input logs.
- Chạy được rule detector.
- Chạy được ML detector.
- Kết hợp được kết quả thành alert records.

---

### FR-08: Alert Manager

Module `src/alert_manager.py` kết hợp rule và ML thành alert object.

Alert format:

```json
{
  "alert_id": "ALERT-0001",
  "timestamp": "2026-05-26T10:05:00",
  "source_ip": "10.0.0.5",
  "endpoint": "/login",
  "threat_type": "brute_force",
  "severity": "high",
  "rule_prediction": "brute_force",
  "rule_reason": "failed_login_count_5m exceeded threshold",
  "ml_prediction": "brute_force",
  "ml_confidence": 0.93,
  "recommended_action": "Enable rate limiting and account lockout.",
  "evidence_ref": "data/logs/events.jsonl:152"
}
```

Severity mapping:

| Severity | Condition |
|---|---|
| Critical | Rule và ML cùng phát hiện, confidence rất cao |
| High | ML confidence cao hoặc rule match mạnh |
| Medium | Có dấu hiệu nhưng chưa chắc chắn |
| Low | Tín hiệu yếu |
| Informational | Normal hoặc không nguy hiểm |

Acceptance criteria:

- Mỗi alert có `alert_id`.
- Mỗi alert có `severity`.
- Mỗi alert có `recommended_action`.
- Rule và ML results đều được giữ lại.

---

### FR-09: LLM Incident Advisor

Module `src/llm_advisor.py` đọc alert và sinh recommendation có cấu trúc.

Design rule:

```text
ML model = detects and classifies threat
LLM Advisor = explains alert and recommends next steps
```

LLM input là alert context có cấu trúc, không phải raw log quá dài.

Example input:

```json
{
  "alert_id": "ALERT-0001",
  "timestamp": "2026-05-26T10:05:00",
  "threat_type": "brute_force",
  "severity": "high",
  "source_ip": "10.0.0.5",
  "endpoint": "/login",
  "rule_prediction": "brute_force",
  "rule_reason": "failed_login_count_5m exceeded threshold",
  "ml_prediction": "brute_force",
  "ml_confidence": 0.93,
  "important_features": {
    "failed_login_count_5m": 28,
    "request_count_1m": 75,
    "status_4xx_count_5m": 25,
    "payload_risk_score": 0.1
  },
  "recent_events_summary": {
    "total_events_from_ip": 80,
    "failed_logins": 28,
    "affected_user_count": 3,
    "time_window": "5 minutes"
  }
}
```

LLM output phải là valid JSON:

```json
{
  "incident_summary": "The system detected a high-risk brute-force login pattern from source IP 10.0.0.5 targeting the /login endpoint.",
  "threat_explanation": "Brute-force login attempts occur when an attacker repeatedly tries different credentials to gain unauthorized access.",
  "severity_reasoning": "The alert is marked high because both the rule-based detector and ML model identified the same threat, with ML confidence of 0.93.",
  "immediate_next_steps": [
    "Review authentication logs for the affected time window.",
    "Check whether any account had a successful login after repeated failures.",
    "Apply rate limiting or temporary blocking in the local lab configuration."
  ],
  "investigation_steps": [
    "Inspect failed login patterns by username.",
    "Check whether multiple source IPs targeted the same account.",
    "Compare this event with previous login behavior."
  ],
  "mitigation_actions": [
    "Enable account lockout after repeated failed login attempts.",
    "Add rate limiting on the login endpoint.",
    "Enable MFA for sensitive accounts.",
    "Improve authentication logging."
  ],
  "false_positive_checklist": [
    "Verify whether this was a legitimate user who forgot their password.",
    "Check whether the traffic came from an internal test script.",
    "Confirm whether the affected accounts are test accounts."
  ],
  "evidence_to_collect": [
    "Authentication logs during the 5-minute window.",
    "Alert record from alerts.csv.",
    "Dashboard screenshot.",
    "Model confidence and rule reason."
  ],
  "long_term_improvements": [
    "Deploy stronger login monitoring.",
    "Retrain the detection model with more diverse authentication patterns.",
    "Add anomaly detection for distributed brute-force attempts."
  ]
}
```

Prompt template trong `src/prompt_templates.py`:

```text
You are a defensive cybersecurity incident response assistant.

Your task is to analyze a security alert generated by a lab-based AI-driven cyber defense system.

Important rules:
- Only provide defensive recommendations.
- Do not provide offensive exploitation steps.
- Do not suggest attacking, scanning, or compromising real systems.
- Assume all activity happens in a safe local lab.
- Be concise, practical, and suitable for a student security report.
- Explain the alert in a way that a human analyst can understand.
- Return your answer as valid JSON only.

Alert context:
{alert_context}

Generate:
1. incident_summary
2. threat_explanation
3. severity_reasoning
4. immediate_next_steps
5. investigation_steps
6. mitigation_actions
7. false_positive_checklist
8. evidence_to_collect
9. long_term_improvements
```

LLM modes:

| Mode | Description |
|---|---|
| fallback | Rule/template-based recommendation, không cần API key |
| local | Local LLM endpoint, optional |
| api | External LLM API, optional |

Default mode bắt buộc là `fallback`.

Fallback example:

```python
FALLBACK_RECOMMENDATIONS = {
    "brute_force": {
        "incident_summary": "A brute-force-like login pattern was detected.",
        "immediate_next_steps": [
            "Review failed login logs.",
            "Check whether any login succeeded after repeated failures.",
            "Apply rate limiting in the local lab configuration."
        ],
        "mitigation_actions": [
            "Enable MFA.",
            "Improve authentication logging.",
            "Add account lockout policy."
        ]
    }
}
```

LLM safety guardrails:

- Không sinh offensive exploitation steps.
- Không sinh script brute-force.
- Không sinh lệnh scan IP public.
- Không sinh malware instruction.
- Không sinh privilege escalation steps.
- Không sinh detection evasion guidance.
- Chỉ sinh defensive guidance: log investigation, evidence collection, rate limiting, input validation, MFA, monitoring, reporting.

Dashboard phải hiển thị note:

```text
LLM recommendations are advisory only. Human review is required before applying any response action.
```

Output:

```text
src/llm_advisor.py
src/prompt_templates.py
src/recommendation_fallback.py
data/logs/llm_recommendations.jsonl
```

---

## 12. Website Dashboard Requirements

Dashboard dùng Streamlit và gồm các trang sau:

| Page | Purpose |
|---|---|
| Overview | Tổng quan hệ thống |
| Live Logs | Hiển thị log đầu vào |
| Threat Alerts | Hiển thị alert |
| Model Metrics | Hiển thị metrics |
| Rule vs AI | So sánh rule-based và ML-based |
| LLM Advisor | Hiển thị incident summary và next steps |
| Evidence Export | Xuất minh chứng |

### Page 1: Overview

Hiển thị:

- Project title.
- System description.
- Total logs processed.
- Total alerts.
- Alerts by severity.
- Alerts by threat type.
- Last detection time.
- Pipeline diagram.
- Ethical scope note.

Acceptance criteria:

- Load được dù chưa có dữ liệu.
- Nếu thiếu data thì hướng dẫn command cần chạy.
- Có KPI cards và ít nhất một chart.

### Page 2: Live Logs

Hiển thị log table và filter:

```text
timestamp
source_ip
event_type
endpoint
status_code
request_count_1m
failed_login_count_5m
unique_ports_1m
payload_risk_score
label
```

Tính năng:

- Filter event_type.
- Filter label.
- Search source_ip.
- Search endpoint.
- Chart log count theo thời gian.

### Page 3: Threat Alerts

Hiển thị:

```text
alert_id
timestamp
threat_type
severity
source_ip
endpoint
rule_prediction
rule_reason
ml_prediction
ml_confidence
recommended_action
```

Tính năng:

- Filter severity.
- Filter threat_type.
- Filter source_ip.
- Alert detail panel.
- Recommended action.

### Page 4: Model Metrics

Hiển thị:

- Accuracy.
- Precision.
- Recall.
- F1-score.
- Classification report.
- Confusion matrix.
- Feature importance.
- Label distribution.

### Page 5: Rule vs AI

Hiển thị:

- Rule prediction count.
- ML prediction count.
- Agreement count.
- Disagreement count.
- Examples where rule and ML disagree.
- Short analysis text.

### Page 6: LLM Advisor

Hiển thị:

- Alert selector.
- Incident summary.
- Threat explanation.
- Severity reasoning.
- Immediate next steps.
- Investigation steps.
- Mitigation actions.
- False positive checklist.
- Evidence to collect.
- Long-term improvements.
- Advisory-only note.
- Export recommendation button.

### Page 7: Evidence Export

Export files:

```text
data/evidence/exports/
├── alerts.csv
├── metrics.json
├── classification_report.txt
├── confusion_matrix.png
├── feature_importance.png
├── llm_recommendations.jsonl
├── recommendation_summary.md
├── test_case_results.md
└── demo_summary.md
```

---

## 13. Evidence Exporter

Module `src/evidence_exporter.py` tạo report-ready artifacts.

Output:

```text
data/evidence/exports/alerts.csv
data/evidence/exports/metrics.json
data/evidence/exports/classification_report.txt
data/evidence/exports/recommendation_summary.md
data/evidence/exports/demo_summary.md
data/evidence/exports/test_case_results.md
```

`demo_summary.md` template:

```text
# Demo Summary

## Dataset / Logs
Total logs processed:
Total alerts generated:
Threat types detected:

## Model
Model used:
Accuracy:
Precision:
Recall:
F1-score:

## Rule vs AI
Agreement count:
Disagreement count:

## LLM Advisor
LLM mode:
Recommendations generated:
Example alert analyzed:

## Ethical Scope
This demo runs only in a safe local lab environment using synthetic or public data.
```

---

## 14. CLI Requirements

Commands cần hỗ trợ:

```bash
pip install -r requirements.txt
python src/train_model.py
python src/evaluate_model.py
python lab/simulator/simulate_events.py --scenario mixed --count 500
python src/detect.py
python src/llm_advisor.py
python src/evidence_exporter.py
streamlit run dashboard/app.py
```

Makefile:

```makefile
setup:
	pip install -r requirements.txt

simulate:
	python lab/simulator/simulate_events.py --scenario mixed --count 500

train:
	python src/train_model.py
	python src/evaluate_model.py

detect:
	python src/detect.py

advise:
	python src/llm_advisor.py

export:
	python src/evidence_exporter.py

dashboard:
	streamlit run dashboard/app.py

demo:
	python lab/simulator/simulate_events.py --scenario mixed --count 500
	python src/detect.py
	python src/llm_advisor.py
	python src/evidence_exporter.py
	streamlit run dashboard/app.py
```

---

## 15. Docker Requirements

Project cần chạy được bằng:

```bash
docker compose up --build
```

Minimal `docker-compose.yml`:

```yaml
services:
  dashboard:
    build: .
    ports:
      - "8501:8501"
    volumes:
      - .:/app
    command: streamlit run dashboard/app.py --server.address=0.0.0.0
```

Optional services:

| Service | Purpose |
|---|---|
| dashboard | Streamlit UI |
| detection | Detection scripts/API |
| simulator | Log generation |
| lab-web | Optional local web app |
| nginx | Optional access log source |

---

## 16. Config Requirements

Create:

```text
src/config.py
.env.example
```

Required config values:

```text
DATA_DIR=data
RAW_DATA_DIR=data/raw
PROCESSED_DATA_DIR=data/processed
LOG_DIR=data/logs
MODEL_DIR=models
EVIDENCE_DIR=data/evidence/exports

LLM_MODE=fallback
LLM_PROVIDER=none
LLM_API_KEY=
LLM_MODEL=
LLM_ENDPOINT=

RULE_FAILED_LOGIN_THRESHOLD=10
RULE_UNIQUE_PORTS_THRESHOLD=20
RULE_REQUEST_SPIKE_THRESHOLD=150
RULE_PAYLOAD_RISK_THRESHOLD=0.7
```

Acceptance criteria:

- Project chạy được không cần `.env`.
- Default LLM mode là fallback.
- Threshold có thể chỉnh qua config.

---

## 17. Non-Functional Requirements

### Usability

- Setup đơn giản.
- Dashboard dễ hiểu.
- Missing files phải có hướng dẫn chạy command.
- Demo giải thích được trong 5–7 phút.

### Reliability

- Dashboard không crash khi thiếu file.
- Detection validate input schema.
- LLM Advisor có fallback mode.
- Evidence exporter tự tạo folder nếu thiếu.

### Safety

- Không external attack.
- Không real personal data.
- Không malware.
- Không harmful payload generation.
- Không automatic response trên hệ thống thật.
- LLM output defensive-only.

### Performance

- Xử lý ít nhất 5,000 synthetic events local.
- Model training chạy được trên laptop phổ thông.
- Dashboard load trong vài giây với demo-scale data.

### Maintainability

- Code modular.
- Config centralized.
- Threshold configurable.
- File paths dùng `pathlib.Path`.
- Có tests cho core modules.

---

## 18. Implementation Tasks

### Phase 1: MVP End-to-End Demo

#### Task 1: Initialize Project

Deliverables:

```text
README.md
requirements.txt
src/config.py
dashboard/app.py
```

Work:

```text
- Create folders.
- Add README.md.
- Add requirements.txt.
- Add .gitignore.
- Add config.py.
```

#### Task 2: Build Synthetic Log Simulator

Deliverables:

```text
lab/simulator/simulate_events.py
data/logs/events.jsonl
data/logs/live_logs.csv
```

Work:

```text
- Implement normal, brute_force, port_scan, web_attack, traffic_spike, mixed.
- Output CSV and JSONL.
- Ensure schema consistency.
```

#### Task 3: Build Preprocessing Pipeline

Deliverables:

```text
src/data_loader.py
src/preprocessing.py
src/feature_engineering.py
data/processed/
```

Work:

```text
- Load CSV/JSONL.
- Normalize columns.
- Handle NaN and infinity.
- Encode labels.
- Save processed files.
```

#### Task 4: Build Rule-Based Detector

Deliverables:

```text
src/rules.py
data/logs/rule_alerts.csv
```

Work:

```text
- Implement R001-R006.
- Return threat_type, severity, reason.
- Make thresholds configurable.
```

#### Task 5: Train ML Model

Deliverables:

```text
src/train_model.py
src/evaluate_model.py
models/threat_model.joblib
models/metrics.json
models/confusion_matrix.png
```

Work:

```text
- Train Random Forest.
- Evaluate metrics.
- Save model.
- Save metrics.
- Save confusion matrix.
```

#### Task 6: Build Detection Engine

Deliverables:

```text
src/detect.py
data/logs/detected_logs.csv
```

Work:

```text
- Read logs.
- Run rule detector.
- Run ML model.
- Produce detected_logs.csv.
```

#### Task 7: Build Alert Manager

Deliverables:

```text
src/alert_manager.py
data/logs/alerts.csv
data/logs/alerts.jsonl
```

Work:

```text
- Generate alert_id.
- Determine severity.
- Attach rule reason.
- Attach ML confidence.
- Attach recommended action.
```

#### Task 8: Build Basic Dashboard

Deliverables:

```text
dashboard/app.py
dashboard/pages/
```

Work:

```text
- Build Streamlit layout.
- Add Overview page.
- Add Live Logs page.
- Add Threat Alerts page.
- Add Model Metrics page.
```

---

### Phase 2: LLM Advisor and Evidence

#### Task 9: Build LLM Fallback Recommendation

Deliverable:

```text
src/recommendation_fallback.py
```

Work:

```text
- Create fallback recommendation dictionary.
- Map each threat to next steps.
- Return structured JSON.
```

#### Task 10: Build LLM Incident Advisor

Deliverables:

```text
src/llm_advisor.py
src/prompt_templates.py
data/logs/llm_recommendations.jsonl
```

Work:

```text
- Read alerts.csv.
- Build alert_context.
- Use fallback/local/API mode.
- Parse JSON output.
- Save llm_recommendations.jsonl.
```

#### Task 11: Add LLM Advisor Page

Deliverable:

```text
dashboard/pages/6_LLM_Advisor.py
```

Work:

```text
- Add alert selector.
- Show incident summary.
- Show immediate next steps.
- Show investigation steps.
- Show mitigation actions.
- Show evidence checklist.
```

#### Task 12: Build Evidence Exporter

Deliverables:

```text
src/evidence_exporter.py
data/evidence/exports/
```

Work:

```text
- Export alerts.
- Export metrics.
- Export classification report.
- Export LLM recommendation summary.
- Export demo summary.
```

---

### Phase 3: Polish and Documentation

#### Task 13: Dockerize Project

Deliverables:

```text
Dockerfile
docker-compose.yml
```

Work:

```text
- Create Dockerfile.
- Create docker-compose.yml.
- Test dashboard startup.
- Mount data volume.
```

#### Task 14: Write Documentation

Deliverables:

```text
docs/architecture.md
docs/setup_guide.md
docs/demo_script.md
docs/test_cases.md
docs/ethics_and_legal_scope.md
docs/dataset_notes.md
docs/llm_advisor_design.md
```

#### Task 15: Add Tests

Deliverables:

```text
tests/test_preprocessing.py
tests/test_rules.py
tests/test_detection.py
tests/test_alert_manager.py
tests/test_llm_fallback.py
```

---

## 19. Test Cases

Create `docs/test_cases.md`.

| TC ID | Scenario | Input | Expected Result | Evidence |
|---|---|---|---|---|
| TC01 | Normal traffic | normal logs | no high/critical alert | live_logs.csv |
| TC02 | Port scan | simulated scan pattern | port_scan alert | alerts.csv |
| TC03 | Brute force | failed login burst | brute_force alert | dashboard screenshot |
| TC04 | Web attack | suspicious request marker | web_attack alert | alerts.csv |
| TC05 | Traffic spike | high request count | traffic_spike alert | chart |
| TC06 | Rule vs AI disagreement | mixed ambiguous logs | disagreement examples | Rule vs AI page |
| TC07 | LLM Advisor | selected alert | next steps generated | llm_recommendations.jsonl |
| TC08 | Fallback LLM mode | no API key | fallback recommendation shown | dashboard |
| TC09 | Evidence export | export button | files created | evidence folder |

---

## 20. Ethics and Legal Scope

Create `docs/ethics_and_legal_scope.md` with this content:

```text
This project is implemented only for academic and defensive cybersecurity education.
All testing is performed in a local lab environment using synthetic logs or public datasets.
The system does not attack, scan, exploit, or compromise any real external system.
No personal data is collected or processed.
The LLM module is advisory only and does not execute response actions automatically.
Human review is required before applying any recommendation.
```

Must include:

- Lab-only boundary.
- No real personal data.
- No external attack.
- No malware.
- No automatic remediation.
- LLM is advisory only.
- Limitations of AI/ML and LLM recommendations.

---

## 21. README Requirements

README must include:

```text
1. Project title
2. Overview
3. Architecture
4. Features
5. Folder structure
6. Setup guide
7. Run commands
8. Demo script
9. Dataset usage
10. Model training
11. Dashboard pages
12. LLM Advisor
13. Evidence export
14. Ethics and legal scope
15. Limitations
16. Future work
```

---

## 22. Acceptance Criteria

| ID | Criteria |
|---|---|
| AC-01 | End-to-end pipeline works: simulate → detect → alert → LLM → dashboard → export |
| AC-02 | Dashboard has Overview, Live Logs, Threat Alerts, Metrics, Rule vs AI, LLM Advisor, Evidence Export |
| AC-03 | Detects port_scan, brute_force, web_attack, traffic_spike |
| AC-04 | Generates metrics.json, classification_report.txt, confusion_matrix.png |
| AC-05 | Generates llm_recommendations.jsonl and recommendation_summary.md |
| AC-06 | Runs without LLM API key using fallback mode |
| AC-07 | Evidence export creates report-ready files |
| AC-08 | No real external target is attacked or scanned |
| AC-09 | Docker Compose works |
| AC-10 | Project is presentation-ready |

---

## 23. Timeline

| Week | Work | Output |
|---|---|---|
| Week 1 | Scope, repo, dataset loading, simulator | README, simulator, sample logs |
| Week 2 | Preprocessing, rule detector, ML model | model, metrics, confusion matrix |
| Week 3 | Detection engine, alert manager, dashboard | alerts, dashboard pages |
| Week 4 | LLM Advisor, evidence export, Docker, docs | final demo, docs, report artifacts |

---

## 24. Team Task Assignment

### Role 1: Data and Model

```text
- Dataset loading
- EDA
- Preprocessing
- Model training
- Model evaluation
- Metrics and confusion matrix
```

Deliverables:

```text
src/data_loader.py
src/preprocessing.py
src/train_model.py
src/evaluate_model.py
models/
```

### Role 2: Detection and Alert

```text
- Rule-based detector
- Detection engine
- Alert manager
- Recommendation mapping
```

Deliverables:

```text
src/rules.py
src/detect.py
src/alert_manager.py
src/recommendation.py
data/logs/alerts.csv
```

### Role 3: Website Dashboard

```text
- Streamlit dashboard
- Overview page
- Live Logs page
- Threat Alerts page
- Model Metrics page
- Rule vs AI page
- Evidence Export page
```

Deliverables:

```text
dashboard/app.py
dashboard/pages/
```

### Role 4: LLM, Docs and Demo

```text
- LLM Advisor
- Fallback recommendations
- Evidence exporter
- Docker setup
- README and docs
- Demo script
```

Deliverables:

```text
src/llm_advisor.py
src/recommendation_fallback.py
src/evidence_exporter.py
Dockerfile
docker-compose.yml
docs/
```

---

## 25. Demo Script

Create `docs/demo_script.md`.

```text
1. Introduce the problem:
   Security logs are large and hard to inspect manually.

2. Show architecture:
   Logs → Detection Model → Alert → LLM Advisor → Dashboard.

3. Generate lab logs:
   Run simulator with mixed scenario.

4. Run detection:
   Show alerts.csv is generated.

5. Open dashboard Overview:
   Show total logs, alerts, threat types.

6. Open Live Logs:
   Show input events.

7. Open Threat Alerts:
   Select brute_force or web_attack alert.

8. Open LLM Advisor:
   Show incident summary, next steps, mitigation actions.

9. Open Model Metrics:
   Explain Precision, Recall, F1-score, confusion matrix.

10. Open Rule vs AI:
    Show agreement/disagreement.

11. Open Evidence Export:
    Export report-ready evidence.

12. Close with ethics:
    Lab-only, no real attack, no personal data, LLM advisory only.
```

---

## 26. Future Work

- Real-time log watcher.
- Integration with Wazuh/ELK/Splunk.
- Support CICIDS/UNSW ingestion profiles.
- SHAP explainability.
- Model drift monitoring.
- Local LLM deployment.
- Role-based dashboard access.
- Incident response playbook templates.
- SIEM-style correlation rules.
- More advanced anomaly detection.

---

## 27. Final Instruction for Coding Agent

Build this project as a complete, polished, presentation-ready lab demo.

The MVP must work end-to-end first:

```text
simulate logs
→ detect
→ alerts.csv
→ llm_recommendations.jsonl
→ dashboard
→ evidence export
```

Do not over-optimize early. Prioritize a working demo, clear dashboard, safe lab boundary, meaningful recommendations and report-ready evidence.

The final system should tell this story:

```text
We built a safe local cyber defense lab.
The lab generates or loads security logs.
A rule-based detector catches known suspicious patterns.
An ML model classifies threat types.
An alert manager creates structured alerts.
An LLM Advisor explains incidents and recommends next steps.
A dashboard visualizes everything.
Evidence is exported for the final report.
Everything is ethical, legal, local and reproducible.
```

