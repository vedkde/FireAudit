from fireaudit.analysis.shadowing import find_shadowing
from fireaudit.models import Rule


def make_rule(name, position, source, destination, service, action, logging=True):
    return Rule(
        name=name, position=position, source=source, destination=destination,
        service=service, action=action, logging=logging,
    )


def test_narrower_rule_shadowed_by_broader_rule_with_different_action():
    rules = [
        make_rule("broad-allow", 1, "10.0.0.0/24", "10.0.0.53/32", "DNS", "allow"),
        make_rule("narrow-deny", 2, "10.0.0.5/32", "10.0.0.53/32", "DNS", "deny"),
    ]
    findings = find_shadowing(rules)
    assert len(findings) == 1
    assert findings[0].issue_type == "shadowed_rule"
    assert findings[0].rule.name == "narrow-deny"
    assert findings[0].related_rule.name == "broad-allow"


def test_same_action_flagged_as_redundant_not_shadowed():
    rules = [
        make_rule("broad-allow", 1, "10.0.0.0/24", "10.0.0.53/32", "DNS", "allow"),
        make_rule("narrow-allow", 2, "10.0.0.5/32", "10.0.0.53/32", "DNS", "allow"),
    ]
    findings = find_shadowing(rules)
    assert len(findings) == 1
    assert findings[0].issue_type == "redundant_rule"


def test_no_shadowing_when_subnets_dont_overlap():
    rules = [
        make_rule("rule-a", 1, "10.0.1.0/24", "any", "any", "allow"),
        make_rule("rule-b", 2, "10.0.2.0/24", "any", "any", "deny"),
    ]
    findings = find_shadowing(rules)
    assert len(findings) == 0


def test_any_source_shadows_everything_below():
    rules = [
        make_rule("any-allow", 1, "any", "any", "any", "allow"),
        make_rule("specific-deny", 2, "10.0.5.0/24", "10.0.6.0/24", "tcp/22", "deny"),
    ]
    findings = find_shadowing(rules)
    assert len(findings) == 1
    assert findings[0].rule.name == "specific-deny"
