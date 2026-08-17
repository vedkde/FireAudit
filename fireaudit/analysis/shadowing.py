"""
Detects rule shadowing: a rule that can never fire because an earlier rule
in the list already matches all of its traffic.

This is real containment logic, not string comparison. A rule is shadowed
by an earlier rule if:
  - the earlier rule's source network contains (or equals) this rule's source
  - the earlier rule's destination network contains (or equals) this rule's destination
  - the earlier rule's service covers this rule's service
  - the earlier rule's action differs, OR the earlier rule fully overlaps
    and its action is the same (making this rule redundant rather than
    dangerous, still worth flagging)
"""

import ipaddress

from fireaudit.models import Finding, Rule


def _to_network(value: str):
    """Return an ip_network for a single CIDR/host string, or None if not parseable
    (e.g. 'any', a named service object, multiple comma-separated members)."""
    value = value.strip()
    if value.lower() == "any" or "," in value:
        return None
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def _network_contains_or_equal(broader: str, narrower: str) -> bool:
    if broader.strip().lower() == "any":
        return True
    broader_net = _to_network(broader)
    narrower_net = _to_network(narrower)
    if broader_net is None or narrower_net is None:
        # can't prove containment for named objects, treat as no match
        return broader.strip().lower() == narrower.strip().lower()
    return narrower_net.subnet_of(broader_net) or narrower_net == broader_net


def _service_covers(broader: str, narrower: str) -> bool:
    broader = broader.strip().lower()
    narrower = narrower.strip().lower()
    if broader == "any":
        return True
    return broader == narrower


def find_shadowing(rules: list[Rule]) -> list[Finding]:
    findings = []

    for i, rule in enumerate(rules):
        for earlier in rules[:i]:
            src_covered = _network_contains_or_equal(earlier.source, rule.source)
            dst_covered = _network_contains_or_equal(earlier.destination, rule.destination)
            svc_covered = _service_covers(earlier.service, rule.service)

            if src_covered and dst_covered and svc_covered:
                if earlier.action.lower() != rule.action.lower():
                    findings.append(Finding(
                        rule=rule,
                        issue_type="shadowed_rule",
                        severity="high",
                        message=(
                            f"Rule '{rule.name}' (position {rule.position}) can never match traffic "
                            f"because earlier rule '{earlier.name}' (position {earlier.position}) already "
                            f"catches all of its traffic with a different action ({earlier.action})."
                        ),
                        suggested_fix=(
                            f"Move '{rule.name}' above '{earlier.name}', or narrow the source/destination "
                            f"of '{earlier.name}' so it no longer covers this traffic."
                        ),
                        related_rule=earlier,
                    ))
                else:
                    findings.append(Finding(
                        rule=rule,
                        issue_type="redundant_rule",
                        severity="low",
                        message=(
                            f"Rule '{rule.name}' (position {rule.position}) is redundant: earlier rule "
                            f"'{earlier.name}' (position {earlier.position}) already matches the same "
                            f"traffic with the same action."
                        ),
                        suggested_fix=f"Remove '{rule.name}', it has no effect given '{earlier.name}'.",
                        related_rule=earlier,
                    ))
                break  # only report the first (nearest) shadowing rule

    return findings
