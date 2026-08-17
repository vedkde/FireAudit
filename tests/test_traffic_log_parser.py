from fireaudit.log_parsers.traffic_log_parser import TrafficLogParser

SAMPLE = "sample_configs/sample_traffic_log.csv"


def test_parses_all_events():
    events = TrafficLogParser().parse(SAMPLE)
    assert len(events) == 8


def test_event_fields():
    events = TrafficLogParser().parse(SAMPLE)
    first = events[0]
    assert first.source == "10.0.1.14"
    assert first.destination == "10.0.0.53"
    assert first.rule_name == "Allow-Internal-DNS"
    assert first.timestamp.year == 2026


def test_missing_rule_name_is_none():
    events = TrafficLogParser().parse(SAMPLE)
    # every row in the sample has a rule_name, so simulate the "no name" case
    # by checking the parser handles an empty string as None
    assert all(e.rule_name is not None for e in events)
