from fireaudit.analysis.duplicates import find_duplicates
from fireaudit.models import Rule


def make_rule(name, position, source="10.0.0.0/24", destination="any", service="tcp/443", action="allow"):
    return Rule(
        name=name, position=position, source=source, destination=destination,
        service=service, action=action, logging=True,
    )


def test_identical_rules_flagged_as_duplicate():
    rules = [make_rule("first", 1), make_rule("second", 2)]
    findings = find_duplicates(rules)
    assert len(findings) == 1
    assert findings[0].rule.name == "second"
    assert findings[0].related_rule.name == "first"


def test_different_service_not_duplicate():
    rules = [make_rule("first", 1, service="tcp/443"), make_rule("second", 2, service="tcp/80")]
    findings = find_duplicates(rules)
    assert len(findings) == 0


def test_three_identical_rules_flags_last_two():
    rules = [make_rule("a", 1), make_rule("b", 2), make_rule("c", 3)]
    findings = find_duplicates(rules)
    assert len(findings) == 2
    assert all(f.related_rule.name == "a" for f in findings)
