from lab.simulator.scenarios import generate_events
from src.schemas import LOG_COLUMNS, THREAT_TYPES


def test_simulator_generates_valid_schema():
    events = generate_events("mixed", 80, seed=7)

    assert len(events) == 80
    assert set(LOG_COLUMNS).issubset(events[0].keys())
    assert {event["label"] for event in events}.issubset(set(THREAT_TYPES))
    assert all(str(event["source_ip"]).startswith("10.") for event in events)
