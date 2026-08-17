"""
Core data models used across the whole tool.

Every parser (Palo Alto, Fortinet, CSV) converts its input into the same
Rule/RuleSet shape defined here. All analysis code only ever touches these
models, never the vendor-specific formats directly.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Rule:
    name: str
    position: int
    source: str
    destination: str
    service: str
    action: str
    logging: bool
    hit_count: Optional[int] = None
    raw_line: str = ""

    # populated by log correlation, if a traffic log was provided
    last_seen: Optional[datetime] = None
    log_confirmed: bool = False

    def is_any_any(self) -> bool:
        return self.source.strip().lower() == "any" and self.destination.strip().lower() == "any"

    def is_allow(self) -> bool:
        return self.action.strip().lower() in ("allow", "accept", "permit")


@dataclass
class LogEvent:
    timestamp: datetime
    source: str
    destination: str
    service: str
    action: str
    rule_name: Optional[str] = None  # present if the log records which rule handled the traffic


@dataclass
class RuleSet:
    vendor: str
    source_file: str
    rules: list[Rule] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.rules)


@dataclass
class Finding:
    rule: Rule
    issue_type: str
    severity: str  # critical, high, medium, low
    message: str
    suggested_fix: str
    related_rule: Optional[Rule] = None

    def to_dict(self) -> dict:
        return {
            "rule_name": self.rule.name,
            "rule_position": self.rule.position,
            "issue_type": self.issue_type,
            "severity": self.severity,
            "message": self.message,
            "suggested_fix": self.suggested_fix,
            "related_rule_name": self.related_rule.name if self.related_rule else None,
        }
