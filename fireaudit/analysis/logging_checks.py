"""
Flags allow rules that do not have logging enabled. This is a common
compliance/audit finding since it means matched traffic leaves no trail.
"""

from fireaudit.models import Finding, Rule


def find_logging_gaps(rules: list[Rule]) -> list[Finding]:
    findings = []

    for rule in rules:
        if rule.is_allow() and not rule.logging:
            severity = "high" if rule.is_any_any() else "medium"
            findings.append(Finding(
                rule=rule,
                issue_type="no_logging",
                severity=severity,
                message=f"Rule '{rule.name}' allows traffic but does not have logging enabled.",
                suggested_fix="Enable logging on this rule so matched traffic can be audited and investigated.",
            ))

    return findings
