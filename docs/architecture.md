# Architecture

## Purpose

This project demonstrates a safe local AI-SOC pipeline. It collects lab events, extracts detection features, compares rule-based and ML-based detection, generates alerts, and exports evidence for academic reporting.

## Components

```text
+-----------------------+
| Flask Lab Web App     |
| login/search/admin    |
+----------+------------+
           |
           v
+-----------------------+
| JSONL Event Logs      |
| data/logs/events.jsonl|
+----------+------------+
           |
           v
+-----------------------+
| Preprocessing         |
| feature extraction    |
+----------+------------+
           |
           +-------------------------+
           |                         |
           v                         v
+----------------------+   +----------------------+
| Rule-Based Detector  |   | Random Forest Model  |
+----------+-----------+   +----------+-----------+
           |                          |
           +------------+-------------+
                        |
                        v
+--------------------------------------+
| Alert Manager                         |
| severity, evidence, recommendation    |
+------------------+-------------------+
                   |
                   v
+--------------------------------------+
| Dashboard + API + Evidence Export     |
+--------------------------------------+
```

## Data Flow

1. The Flask app or simulator writes JSONL events.
2. Preprocessing normalizes missing fields and creates model-ready features.
3. Rules detect known patterns such as brute force, port scan, traffic spike, simulated web attack markers, error bursts, and admin access failures.
4. The Random Forest model predicts one of five labels: `normal`, `port_scan`, `brute_force`, `web_attack`, `traffic_spike`.
5. The alert manager combines rule and ML results, maps severity, attaches evidence, and recommends defensive actions.
6. Dashboard and API read the generated artifacts.

## Safety Boundary

The project never targets external systems. Suspicious-looking events are synthetic log markers, not exploit execution. The only allowed execution targets are localhost, Docker services, and generated datasets.
