from __future__ import annotations

from copy import deepcopy


BASE_RECOMMENDATION = {
    "incident_summary": "The lab detected a suspicious security pattern that requires analyst review.",
    "threat_explanation": "The alert combines transparent rule results and machine learning classification over safe synthetic logs.",
    "severity_reasoning": "Severity is based on rule strength, model confidence, and agreement between detectors.",
    "immediate_next_steps": [
        "Review the related log records for the alert time window.",
        "Validate whether the source IP and endpoint are expected in the local lab.",
        "Preserve the alert row, model confidence, and dashboard screenshot as evidence.",
    ],
    "investigation_steps": [
        "Compare the current event volume with nearby normal traffic.",
        "Check whether the same source IP appears in multiple alerts.",
        "Review rule reason and important feature values before deciding on response.",
    ],
    "mitigation_actions": [
        "Keep testing within localhost or Docker networks only.",
        "Tune detection thresholds after reviewing false positives.",
        "Document the analyst decision in the demo report.",
    ],
    "false_positive_checklist": [
        "Confirm the event came from a synthetic lab scenario.",
        "Check whether a benign load test or scripted demo created the pattern.",
        "Compare rule and ML disagreement before escalating severity.",
    ],
    "evidence_to_collect": [
        "Alert record from alerts.csv.",
        "Input log reference from events.jsonl.",
        "Model metrics and rule reason.",
        "Dashboard screenshot.",
    ],
    "long_term_improvements": [
        "Train with a larger public IDS dataset.",
        "Add analyst feedback labels for future model tuning.",
        "Add SIEM-style correlation rules for multi-step incidents.",
    ],
}


THREAT_OVERRIDES = {
    "brute_force": {
        "incident_summary": "A brute-force-like login pattern was detected against the login endpoint.",
        "threat_explanation": "Brute-force activity is repeated authentication failure that may indicate credential guessing.",
        "immediate_next_steps": [
            "Review failed login logs for the affected account and source IP.",
            "Check whether any successful login happened after repeated failures.",
            "Apply lab-only rate limiting or temporary blocking for the source IP.",
        ],
        "mitigation_actions": [
            "Enable MFA for sensitive accounts.",
            "Add account lockout after repeated failed attempts.",
            "Increase authentication logging and alerting.",
        ],
    },
    "port_scan": {
        "incident_summary": "A port-scan-like service probing pattern was detected from a local lab source.",
        "threat_explanation": "Port scanning attempts to discover exposed services before deeper attack planning.",
        "immediate_next_steps": [
            "Review which local services or endpoints were probed.",
            "Check whether the activity came from an expected lab simulator run.",
            "Preserve the source IP, unique port count, and timestamps as evidence.",
        ],
        "mitigation_actions": [
            "Restrict unnecessary exposed services.",
            "Add firewall rules in the lab environment.",
            "Monitor repeated probes from the same source.",
        ],
    },
    "web_attack": {
        "incident_summary": "A suspicious web request pattern was detected using safe simulated payload markers.",
        "threat_explanation": "The request pattern resembles common web attack attempts, but uses harmless lab markers only.",
        "immediate_next_steps": [
            "Review endpoint, payload risk score, and HTTP status codes.",
            "Check input validation around the affected route.",
            "Confirm the marker came from the safe simulator, not a real payload.",
        ],
        "mitigation_actions": [
            "Validate and sanitize input.",
            "Use parameterized queries and output encoding.",
            "Add WAF-style rules for high-risk markers.",
        ],
    },
    "traffic_spike": {
        "incident_summary": "A high-volume traffic spike was detected in the local lab logs.",
        "threat_explanation": "Traffic spikes can degrade availability and may represent automated abuse or stress testing.",
        "immediate_next_steps": [
            "Review request volume around the alert window.",
            "Check whether the source IP is a known local load-test generator.",
            "Inspect 429 and 5xx rates for service stress indicators.",
        ],
        "mitigation_actions": [
            "Add rate limiting.",
            "Use queueing or autoscaling strategy in production designs.",
            "Improve observability for request volume anomalies.",
        ],
    },
}


def fallback_recommendation(alert: dict) -> dict:
    threat_type = str(alert.get("threat_type", "suspicious")).lower()
    recommendation = deepcopy(BASE_RECOMMENDATION)
    for key, value in THREAT_OVERRIDES.get(threat_type, {}).items():
        recommendation[key] = value

    recommendation["severity_reasoning"] = (
        f"Severity is '{alert.get('severity', 'unknown')}' because rule prediction "
        f"'{alert.get('rule_prediction', 'normal')}' and ML prediction "
        f"'{alert.get('ml_prediction', 'normal')}' produced confidence "
        f"{alert.get('ml_confidence', 'n/a')}."
    )
    return recommendation
