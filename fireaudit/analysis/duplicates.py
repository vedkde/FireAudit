"""
Flags rules that are functional duplicates of an earlier rule: same
source, destination, service, and action. These add clutter and make
the rulebase harder to audit without adding any security value.
"""

from fireaudit.models import Finding, Rule


def _match_key(rule: Rule) -> tuple:
    return (
        rule.source.strip().lower(),
        rule.destination.strip().lower(),
        rule.service.strip().lower(),
        rule.action.strip().lower(),
    )


def find_duplicates(rules: list[Rule]) -> list[Finding]:
    findings = []
    seen: dict[tuple, Rule] = {}

    for rule in rules:
        key = _match_key(rule)
        if key in seen:
            original = seen[key]
            findings.append(Finding(
                rule=rule,
                issue_type="duplicate_rule",
                severity="low",
                message=(
                    f"Rule '{rule.name}' (position {rule.position}) has identical match criteria "
                    f"and action as rule '{original.name}' (position {original.position})."
                ),
                suggested_fix=f"Remove '{rule.name}', it duplicates '{original.name}'.",
                related_rule=original,
            ))
        else:
            seen[key] = rule

    return findings
