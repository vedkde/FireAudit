from fireaudit.parsers.fortinet_parser import FortinetParser

SAMPLE = "sample_configs/fortinet_sample.conf"


def test_parses_all_rules():
    ruleset = FortinetParser().parse(SAMPLE)
    assert len(ruleset.rules) == 8


def test_first_rule_fields():
    ruleset = FortinetParser().parse(SAMPLE)
    rule = ruleset.rules[0]
    assert rule.name == "Allow-Internal-DNS"
    assert rule.source == "10.0.1.0/24"
    assert rule.action == "allow"
    assert rule.logging is True
    assert rule.hit_count == 84210


def test_all_normalized_to_any():
    ruleset = FortinetParser().parse(SAMPLE)
    rule = next(r for r in ruleset.rules if r.name == "Allow-Any-Any-Temp")
    assert rule.source == "any"
    assert rule.destination == "any"
    assert rule.logging is False


def test_accept_maps_to_allow():
    ruleset = FortinetParser().parse(SAMPLE)
    rule = ruleset.rules[0]
    assert rule.action == "allow"
