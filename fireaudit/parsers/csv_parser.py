"""
Parser for the generic CSV rule format, used as a vendor-agnostic fallback.

Expected columns: name, source, destination, service, action, logging, hit_count
"""

import csv

from fireaudit.models import Rule, RuleSet
from fireaudit.parsers.base_parser import BaseParser


class CsvParser(BaseParser):
    vendor_name = "generic_csv"

    def parse(self, filepath: str) -> RuleSet:
        rules = []
        with open(filepath, "r", newline="") as f:
            reader = csv.DictReader(f)
            for position, row in enumerate(reader, start=1):
                hit_count_raw = row.get("hit_count", "").strip()
                logging_raw = row.get("logging", "false").strip().lower()

                rules.append(Rule(
                    name=row.get("name", f"rule-{position}"),
                    position=position,
                    source=row.get("source", "any").strip(),
                    destination=row.get("destination", "any").strip(),
                    service=row.get("service", "any").strip(),
                    action=row.get("action", "deny").strip(),
                    logging=(logging_raw in ("true", "yes", "1")),
                    hit_count=int(hit_count_raw) if hit_count_raw.isdigit() else None,
                    raw_line=",".join(row.values()),
                ))

        return RuleSet(vendor=self.vendor_name, source_file=filepath, rules=rules)
