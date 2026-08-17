"""
Flags rules that appear unused.

If a traffic log was provided and correlated (rule.log_confirmed is True),
this uses the real last_seen timestamp, which is a much stronger signal
than hit-count alone: hit-count is just a running counter since an unknown
reset point, while last_seen tells you exactly how long the rule has been
silent.

If no log data is available, this falls back to hit-count only, and every
finding says so explicitly, since a hit-count of 0 could just mean the
counter was recently reset rather than the rule being genuinely unused.
"""

from datetime import datetime

from fireaudit.models import Finding, Rule

LOW_HIT_THRESHOLD = 5
STALE_DAYS_THRESHOLD = 90


def find_unused_rules(rules: list[Rule], logs_provided: bool = False) -> list[Finding]:
    findings = []

    for rule in rules:
        if logs_provided and rule.log_confirmed:
            findings.extend(_check_with_log_data(rule))
        elif logs_provided and not rule.log_confirmed:
            findings.append(Finding(
                rule=rule,
                issue_type="unused_rule_log_confirmed",
                severity="high",
                message=(
                    f"Rule '{rule.name}' had no matching traffic in the provided log data at all. "
                    "This is a strong signal the rule is genuinely unused."
                ),
                suggested_fix="Confirm with the rule owner, then remove this rule.",
            ))
        elif rule.hit_count is not None:
            findings.extend(_check_with_hit_count_only(rule))

    return findings


def _check_with_log_data(rule: Rule) -> list[Finding]:
    if rule.last_seen is None:
        return []

    days_since_last_seen = (datetime.now() - rule.last_seen).days

    if days_since_last_seen >= STALE_DAYS_THRESHOLD:
        return [Finding(
            rule=rule,
            issue_type="stale_rule_log_confirmed",
            severity="medium",
            message=(
                f"Rule '{rule.name}' was last seen matching traffic "
                f"{days_since_last_seen} days ago (log-confirmed)."
            ),
            suggested_fix="Verify this rule still serves an active purpose, otherwise remove it.",
        )]
    return []


def _check_with_hit_count_only(rule: Rule) -> list[Finding]:
    if rule.hit_count == 0:
        return [Finding(
            rule=rule,
            issue_type="unused_rule_hit_count_only",
            severity="medium",
            message=(
                f"Rule '{rule.name}' has a hit count of 0 in the config export. "
                "No log data was provided, so this is based on hit-count only, "
                "which resets periodically and does not confirm the rule is truly unused."
            ),
            suggested_fix=(
                "Confirm this rule is still needed. Providing a traffic log alongside "
                "the config export would give a more reliable answer."
            ),
        )]
    if rule.hit_count < LOW_HIT_THRESHOLD:
        return [Finding(
            rule=rule,
            issue_type="low_usage_rule_hit_count_only",
            severity="low",
            message=(
                f"Rule '{rule.name}' has an unusually low hit count ({rule.hit_count}), "
                "based on hit-count only, no log data available."
            ),
            suggested_fix="Verify this rule is still required, it may be a leftover from a past change.",
        )]
    return []
