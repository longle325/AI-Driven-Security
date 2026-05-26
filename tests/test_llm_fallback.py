from src.llm_advisor import advise_alert


def test_advisor_fallback_is_structured():
    result = advise_alert(
        {
            "alert_id": "ALERT-0001",
            "threat_type": "brute_force",
            "severity": "high",
            "rule_prediction": "brute_force",
            "ml_prediction": "brute_force",
            "ml_confidence": 0.93,
        },
        force_fallback=True,
    )

    recommendation = result["recommendation"]
    assert result["mode"] == "fallback"
    assert "incident_summary" in recommendation
    assert recommendation["immediate_next_steps"]
    assert recommendation["mitigation_actions"]
