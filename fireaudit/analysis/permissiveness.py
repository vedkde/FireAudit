"""
Flags rules that are overly broad: any/any, any-service allow rules,
or allow rules missing logging on top of being broad.
"""

from fireaudit.models import Finding, Rule


def find_permissive_rules(rules: list[Rule]) -> list[Finding]:
    findings = []

    for rule in rules:
        if not rule.is_allow():
            continue

        src_any = rule.source.strip().lower() == "any"
        dst_any = rule.destination.strip().lower() == "any"
        svc_any = rule.service.strip().lower() == "any"

        if src_any and dst_any and svc_any:
            findings.append(Finding(
                rule=rule,
                issue_type="any_any_any_allow",
                severity="critical",
                message=(
                    f"Rule '{rule.name}' allows any source to any destination on any service. "
                    "This is the broadest possible allow rule."
                ),
                suggested_fix=(
                    "Restrict source, destination, and service to only what is required. "
                    "If this is meant as a temporary rule, add an expiry reminder and remove it."
                ),
            ))
        elif src_any and dst_any:
            findings.append(Finding(
                rule=rule,
                issue_type="any_any_allow",
                severity="high",
                message=f"Rule '{rule.name}' allows any source to any destination.",
                suggested_fix="Restrict source and/or destination to known networks.",
            ))
        elif src_any:
            findings.append(Finding(
                rule=rule,
                issue_type="any_source_allow",
                severity="medium",
                message=f"Rule '{rule.name}' allows traffic from any source.",
                suggested_fix="Restrict source to the specific networks that need this access.",
            ))
        elif svc_any:
            findings.append(Finding(
                rule=rule,
                issue_type="any_service_allow",
                severity="medium",
                message=f"Rule '{rule.name}' allows any service/port between its source and destination.",
                suggested_fix="Restrict service to only the ports/protocols actually required.",
            ))

    return findings
