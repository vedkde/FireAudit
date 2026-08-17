from fireaudit.analysis.permissiveness import find_permissive_rules
from fireaudit.models import Rule


def make_rule(name, source, destination, service, action="allow", logging=True):
    return Rule(
        name=name, position=1, source=source, destination=destination,
        service=service, action=action, logging=logging,
    )


def test_any_any_any_flagged_critical():
    rules = [make_rule("r1", "any", "any", "any")]
    findings = find_permissive_rules(rules)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].issue_type == "any_any_any_allow"


def test_any_any_specific_service_flagged_high():
    rules = [make_rule("r1", "any", "any", "tcp/443")]
    findings = find_permissive_rules(rules)
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_deny_rules_not_flagged():
    rules = [make_rule("r1", "any", "any", "any", action="deny")]
    findings = find_permissive_rules(rules)
    assert len(findings) == 0


def test_specific_rule_not_flagged():
    rules = [make_rule("r1", "10.0.0.0/24", "10.0.1.0/24", "tcp/443")]
    findings = find_permissive_rules(rules)
    assert len(findings) == 0
