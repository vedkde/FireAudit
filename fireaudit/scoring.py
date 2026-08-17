"""
Turns a list of Findings into an overall risk score plus per-rule scores.

The score is a simple weighted sum, capped at 100. This is intentionally
simple and transparent rather than a black box, since an auditor needs to
be able to explain why a score is what it is.
"""

from fireaudit.models import Finding

SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 12,
    "medium": 5,
    "low": 2,
}

RISK_BANDS = [
    (0, 10, "Low"),
    (10, 30, "Moderate"),
    (30, 60, "High"),
    (60, 1000, "Critical"),
]


def score_findings(findings: list[Finding]) -> dict:
    total_score = 0
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for finding in findings:
        total_score += SEVERITY_WEIGHTS.get(finding.severity, 0)
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

    band = _risk_band(total_score)

    return {
        "total_score": total_score,
        "risk_band": band,
        "severity_counts": severity_counts,
        "total_findings": len(findings),
    }


def _risk_band(score: int) -> str:
    for low, high, label in RISK_BANDS:
        if low <= score < high:
            return label
    return "Critical"
