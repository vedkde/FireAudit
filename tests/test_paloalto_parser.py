from fireaudit.parsers.paloalto_parser import PaloAltoParser

SAMPLE = "sample_configs/paloalto_sample.xml"


def test_parses_all_rules():
    ruleset = PaloAltoParser().parse(SAMPLE)
    assert len(ruleset.rules) == 8


def test_first_rule_fields():
    ruleset = PaloAltoParser().parse(SAMPLE)
    rule = ruleset.rules[0]
    assert rule.name == "Allow-Internal-DNS"
    assert rule.source == "10.0.1.0/24"
    assert rule.destination == "10.0.0.53/32"
    assert rule.action == "allow"
    assert rule.logging is True
    assert rule.hit_count == 84210


def test_any_any_rule_detected():
    ruleset = PaloAltoParser().parse(SAMPLE)
    rule = next(r for r in ruleset.rules if r.name == "Allow-Any-Any-Temp")
    assert rule.is_any_any()
    assert rule.logging is False


def test_vendor_name():
    ruleset = PaloAltoParser().parse(SAMPLE)
    assert ruleset.vendor == "paloalto"
