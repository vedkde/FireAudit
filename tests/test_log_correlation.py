from datetime import datetime

from fireaudit.analysis.log_correlation import correlate_logs
from fireaudit.models import LogEvent, Rule


def make_rule(name, position=1, source="10.0.0.0/24", destination="any", service="tcp/443", action="allow"):
    return Rule(
        name=name, position=position, source=source, destination=destination,
        service=service, action=action, logging=True,
    )


def make_event(rule_name=None, source="10.0.0.5", destination="8.8.8.8", service="tcp/443",
                action="allow", timestamp=None):
    return LogEvent(
        timestamp=timestamp or datetime(2026, 8, 1, 12, 0, 0),
        source=source, destination=destination, service=service,
        action=action, rule_name=rule_name,
    )


def test_matches_by_rule_name():
    rule = make_rule("web-allow")
    events = [make_event(rule_name="web-allow")]
    correlate_logs([rule], events)
    assert rule.log_confirmed is True
    assert rule.last_seen == datetime(2026, 8, 1, 12, 0, 0)


def test_rule_with_no_matching_events_stays_unconfirmed():
    rule = make_rule("unused-rule", source="10.0.5.0/24")
    events = [make_event(rule_name="some-other-rule", source="10.0.9.9")]
    correlate_logs([rule], events)
    assert rule.log_confirmed is False
    assert rule.last_seen is None


def test_unnamed_rule_in_log_still_falls_back_to_criteria_match():
    # if the log names a rule that no longer exists in the ruleset (renamed,
    # deleted), correlation should still fall back to matching by criteria
    # rather than silently missing real usage
    rule = make_rule("current-rule-name", source="10.0.0.0/24")
    events = [make_event(rule_name="old-deleted-rule-name", source="10.0.0.5")]
    correlate_logs([rule], events)
    assert rule.log_confirmed is True


def test_last_seen_uses_most_recent_event():
    rule = make_rule("web-allow")
    events = [
        make_event(rule_name="web-allow", timestamp=datetime(2026, 7, 1)),
        make_event(rule_name="web-allow", timestamp=datetime(2026, 8, 10)),
    ]
    correlate_logs([rule], events)
    assert rule.last_seen == datetime(2026, 8, 10)


def test_fuzzy_match_by_criteria_when_no_rule_name():
    rule = make_rule("web-allow", source="10.0.0.0/24", destination="any", service="tcp/443", action="allow")
    events = [make_event(rule_name=None, source="10.0.0.5", destination="8.8.8.8", service="tcp/443", action="allow")]
    correlate_logs([rule], events)
    assert rule.log_confirmed is True
