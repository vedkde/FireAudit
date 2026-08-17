"""
Correlates traffic log events back to firewall rules to determine actual
observed usage, rather than relying on the config export's hit-count alone.

Matching strategy: prefer matching by rule_name when the log includes it,
since that is unambiguous. Fall back to matching by source/destination/
service/action criteria when rule_name is not present in the log, which is
fuzzier since more than one rule can share overlapping criteria.
"""

import ipaddress

from fireaudit.models import LogEvent, Rule


def _network_contains(rule_value: str, event_value: str) -> bool:
    rule_value = rule_value.strip().lower()
    if rule_value == "any":
        return True

    # log events carry a single host address, rule fields may be a CIDR
    try:
        rule_net = ipaddress.ip_network(rule_value, strict=False)
        event_addr = ipaddress.ip_address(event_value.strip())
        return event_addr in rule_net
    except ValueError:
        # not IP data (named object, service string, etc), fall back to exact match
        return rule_value == event_value.strip().lower()


def _service_matches(rule_value: str, event_value: str) -> bool:
    rule_value = rule_value.strip().lower()
    if rule_value == "any":
        return True
    return rule_value == event_value.strip().lower()


def _criteria_match(rule: Rule, event: LogEvent) -> bool:
    return (
        _network_contains(rule.source, event.source)
        and _network_contains(rule.destination, event.destination)
        and _service_matches(rule.service, event.service)
        and rule.action.strip().lower() == event.action.strip().lower()
    )


def correlate_logs(rules: list[Rule], events: list[LogEvent]) -> None:
    """Mutates the given rules in place, setting last_seen and log_confirmed
    based on the provided log events."""

    rules_by_name = {r.name: r for r in rules}

    for event in events:
        matched_rule = None

        if event.rule_name and event.rule_name in rules_by_name:
            matched_rule = rules_by_name[event.rule_name]
        else:
            # falls back to criteria matching both when the log has no
            # rule_name at all, and when it names a rule that no longer
            # exists in the current ruleset (renamed or deleted since the
            # log was captured). This avoids missing real usage just
            # because a rule name went stale.
            #
            # matches against the first rule (in position order) whose
            # criteria cover this event, mirroring how a real firewall
            # evaluates rules top to bottom
            for rule in sorted(rules, key=lambda r: r.position):
                if _criteria_match(rule, event):
                    matched_rule = rule
                    break

        if matched_rule is None:
            continue

        matched_rule.log_confirmed = True
        if matched_rule.last_seen is None or event.timestamp > matched_rule.last_seen:
            matched_rule.last_seen = event.timestamp
