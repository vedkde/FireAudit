"""
Runs every analyzer against a RuleSet and assembles the results into a
single report data structure that both the CLI and the HTML report can use.

If log_events is provided, logs are correlated against the rules first so
the unused-rule check can use real last-seen data instead of hit-count alone.
"""

from datetime import datetime
from typing import Optional

from fireaudit.analysis.duplicates import find_duplicates
from fireaudit.analysis.log_correlation import correlate_logs
from fireaudit.analysis.logging_checks import find_logging_gaps
from fireaudit.analysis.permissiveness import find_permissive_rules
from fireaudit.analysis.shadowing import find_shadowing
from fireaudit.analysis.unused_rules import find_unused_rules
from fireaudit.models import LogEvent, RuleSet
from fireaudit.scoring import score_findings

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def build_report(ruleset: RuleSet, log_events: Optional[list[LogEvent]] = None) -> dict:
    logs_provided = log_events is not None and len(log_events) > 0

    if logs_provided:
        correlate_logs(ruleset.rules, log_events)

    findings = []
    findings += find_shadowing(ruleset.rules)
    findings += find_permissive_rules(ruleset.rules)
    findings += find_unused_rules(ruleset.rules, logs_provided=logs_provided)
    findings += find_logging_gaps(ruleset.rules)
    findings += find_duplicates(ruleset.rules)

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    scoring = score_findings(findings)

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "source_file": ruleset.source_file,
        "vendor": ruleset.vendor,
        "total_rules": len(ruleset.rules),
        "logs_provided": logs_provided,
        "findings": findings,
        "scoring": scoring,
    }
