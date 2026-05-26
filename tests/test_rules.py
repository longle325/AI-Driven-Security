from src.rules import evaluate_event


def test_brute_force_rule_returns_reason():
    result = evaluate_event(
        {
            "failed_login_count_5m": 18,
            "unique_ports_1m": 1,
            "request_count_1m": 40,
            "payload_risk_score": 0.1,
            "status_4xx_count_5m": 18,
            "status_5xx_count_5m": 0,
            "endpoint": "/login",
            "status_code": 401,
        }
    )

    assert result.is_threat is True
    assert result.threat_type == "brute_force"
    assert result.rule_id == "R001"
    assert "failed_login" in result.reason


def test_web_attack_rule_returns_high_signal():
    result = evaluate_event(
        {
            "failed_login_count_5m": 0,
            "unique_ports_1m": 1,
            "request_count_1m": 20,
            "payload_risk_score": 0.94,
            "status_4xx_count_5m": 8,
            "status_5xx_count_5m": 0,
            "endpoint": "/search",
            "status_code": 400,
        }
    )

    assert result.is_threat is True
    assert result.threat_type == "web_attack"
    assert result.severity == "critical"
