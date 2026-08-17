"""
Parser for a generic traffic log format, used as the vendor-agnostic
starting point since real vendor log formats vary a lot.

Expected columns: timestamp, source, destination, service, action, rule_name
rule_name is optional. timestamp must be ISO format (YYYY-MM-DDTHH:MM:SS)
or YYYY-MM-DD HH:MM:SS.
"""

import csv
from datetime import datetime

from fireaudit.log_parsers.base_log_parser import BaseLogParser
from fireaudit.models import LogEvent

TIMESTAMP_FORMATS = ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"]


def _parse_timestamp(raw: str) -> datetime:
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(raw.strip(), fmt)
        except ValueError:
            continue
    raise ValueError(f"Unrecognized timestamp format: {raw}")


class TrafficLogParser(BaseLogParser):
    format_name = "generic_traffic_log"

    def parse(self, filepath: str) -> list[LogEvent]:
        events = []
        with open(filepath, "r", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rule_name = row.get("rule_name", "").strip() or None
                events.append(LogEvent(
                    timestamp=_parse_timestamp(row["timestamp"]),
                    source=row.get("source", "any").strip(),
                    destination=row.get("destination", "any").strip(),
                    service=row.get("service", "any").strip(),
                    action=row.get("action", "").strip(),
                    rule_name=rule_name,
                ))
        return events
