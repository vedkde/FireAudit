"""
Parser for Fortinet FortiOS firewall policy config blocks.

Fortinet config is a flat, line-based "set key value" format grouped by
"edit <id> ... next" blocks inside "config firewall policy ... end".
This parser walks it as plain text rather than trying to use a generic
config-file library, since the syntax is fairly specific to FortiOS.
"""

import re

from fireaudit.models import Rule, RuleSet
from fireaudit.parsers.base_parser import BaseParser

SET_LINE = re.compile(r'^\s*set\s+(\S+)\s+"?([^"]*)"?\s*$')

# Fortinet uses "all" the same way Palo Alto uses "any"
FORTINET_ANY_VALUES = {"all", "any"}


class FortinetParser(BaseParser):
    vendor_name = "fortinet"

    def parse(self, filepath: str) -> RuleSet:
        with open(filepath, "r") as f:
            text = f.read()

        blocks = re.findall(r"edit\s+\d+\s*(.*?)\s*next", text, re.DOTALL)

        rules = []
        for position, block in enumerate(blocks, start=1):
            fields = {}
            for line in block.splitlines():
                match = SET_LINE.match(line)
                if match:
                    key, value = match.groups()
                    fields[key] = value.strip()

            name = fields.get("name", f"rule-{position}")
            source = fields.get("srcaddr", "all")
            destination = fields.get("dstaddr", "all")
            service = fields.get("service", "ALL")
            action = fields.get("action", "deny")
            logtraffic = fields.get("logtraffic", "disable")
            hit_count_raw = fields.get("hit-count")

            rules.append(Rule(
                name=name,
                position=position,
                source=_normalize_any(source),
                destination=_normalize_any(destination),
                service=_normalize_any(service),
                action="allow" if action == "accept" else action,
                logging=(logtraffic in ("all", "utm")),
                hit_count=int(hit_count_raw) if hit_count_raw is not None else None,
                raw_line=block.strip(),
            ))

        return RuleSet(vendor=self.vendor_name, source_file=filepath, rules=rules)


def _normalize_any(value: str) -> str:
    return "any" if value.lower() in FORTINET_ANY_VALUES else value
