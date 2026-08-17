"""
Parser for Palo Alto XML rulebase exports (security policy section).

Expects the standard PAN-OS config XML structure under
devices/entry/vsys/entry/rulebase/security/rules/entry.
"""

import xml.etree.ElementTree as ET

from fireaudit.models import Rule, RuleSet
from fireaudit.parsers.base_parser import BaseParser


def _member_text(entry: ET.Element, tag: str) -> str:
    node = entry.find(tag)
    if node is None:
        return "any"
    members = [m.text for m in node.findall("member") if m.text]
    if not members:
        return "any"
    return ",".join(members)


class PaloAltoParser(BaseParser):
    vendor_name = "paloalto"

    def parse(self, filepath: str) -> RuleSet:
        tree = ET.parse(filepath)
        root = tree.getroot()

        rule_entries = root.findall(".//rulebase/security/rules/entry")

        rules = []
        for position, entry in enumerate(rule_entries, start=1):
            name = entry.get("name", f"rule-{position}")
            source = _member_text(entry, "source")
            destination = _member_text(entry, "destination")
            service = _member_text(entry, "service")

            action_node = entry.find("action")
            action = action_node.text if action_node is not None and action_node.text else "deny"

            log_node = entry.find("log-end")
            logging_enabled = (log_node is not None and log_node.text == "yes")

            hit_node = entry.find("hit-count")
            hit_count = int(hit_node.text) if hit_node is not None and hit_node.text else None

            rules.append(Rule(
                name=name,
                position=position,
                source=source,
                destination=destination,
                service=service,
                action=action,
                logging=logging_enabled,
                hit_count=hit_count,
                raw_line=ET.tostring(entry, encoding="unicode").strip(),
            ))

        return RuleSet(vendor=self.vendor_name, source_file=filepath, rules=rules)
