"""
Sniffs an input file and returns the right parser instance.

Detection order: file extension first, then content sniffing as a fallback
for cases where the extension is missing or wrong.
"""

from fireaudit.parsers.base_parser import BaseParser
from fireaudit.parsers.csv_parser import CsvParser
from fireaudit.parsers.fortinet_parser import FortinetParser
from fireaudit.parsers.paloalto_parser import PaloAltoParser


def detect_parser(filepath: str) -> BaseParser:
    lower_path = filepath.lower()

    if lower_path.endswith(".xml"):
        return PaloAltoParser()
    if lower_path.endswith(".csv"):
        return CsvParser()
    if lower_path.endswith(".conf") or lower_path.endswith(".cfg"):
        return FortinetParser()

    # fall back to content sniffing
    with open(filepath, "r", errors="ignore") as f:
        head = f.read(2000)

    if head.strip().startswith("<?xml") or "<rulebase>" in head:
        return PaloAltoParser()
    if "config firewall policy" in head:
        return FortinetParser()
    if "," in head.splitlines()[0] if head.splitlines() else False:
        return CsvParser()

    raise ValueError(
        f"Could not detect firewall config format for {filepath}. "
        "Supported: Palo Alto XML (.xml), Fortinet config (.conf), generic CSV (.csv)"
    )
