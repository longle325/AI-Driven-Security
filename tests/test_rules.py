from src.alert_manager import combine_results, recommended_action_for
from src.rules import detect_rule_threats


def test_rules_detect_brute_force_and_explain_reason():
    event = {
        "timestamp": "2026-05-26T10:00:00Z",
        "source_ip": "172.20.0.5",
        "event_type": "login_failed",
        "endpoint": "/login",
        "status_code": 401,
        "failed_login_count_5m": 8,
        "request_count_1m": 12,
        "unique_ports_1m": 1,
        "status_4xx_count_5m": 8,
        "status_5xx_count_5m": 0,
        "payload_risk_score": 0.0,
    }

    result = detect_rule_threats(event)

    assert result["is_threat"] is True
    assert result["threat_type"] == "brute_force"
    assert result["severity"] in {"high", "critical"}
    assert any(match["rule_id"] == "R001" for match in result["matched_rules"])


def test_alert_combines_rule_and_ml_as_critical_when_both_are_confident():
    event = {
        "timestamp": "2026-05-26T10:05:00Z",
        "source_ip": "172.20.0.5",
        "endpoint": "/login",
    }
    rule_result = {
        "is_threat": True,
        "threat_type": "brute_force",
        "severity": "high",
        "reason": "failed_login_count_5m exceeded threshold",
        "matched_rules": [{"rule_id": "R001"}],
        "detector": "rule_based",
    }
    ml_result = {
        "is_threat": True,
        "predicted_label": "brute_force",
        "confidence": 0.95,
        "top_features": ["failed_login_count_5m"],
        "detector": "ml_random_forest",
    }

    alert = combine_results(event, rule_result, ml_result, event_index=7)

    assert alert["severity"] == "critical"
    assert alert["threat_type"] == "brute_force"
    assert alert["recommended_action"] == recommended_action_for("brute_force")
    assert alert["evidence"]["event_index"] == 7
