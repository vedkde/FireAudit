from fireaudit.models import Finding, Rule
from fireaudit.scoring import score_findings


def make_finding(severity):
    rule = Rule(name="r", position=1, source="any", destination="any", service="any", action="allow", logging=True)
    return Finding(rule=rule, issue_type="test_issue", severity=severity, message="msg", suggested_fix="fix")


def test_empty_findings_gives_zero_score():
    result = score_findings([])
    assert result["total_score"] == 0
    assert result["risk_band"] == "Low"


def test_critical_finding_raises_score_significantly():
    result = score_findings([make_finding("critical")])
    assert result["total_score"] == 25
    assert result["risk_band"] == "Moderate"


def test_severity_counts_tracked_correctly():
    findings = [make_finding("critical"), make_finding("high"), make_finding("high"), make_finding("low")]
    result = score_findings(findings)
    assert result["severity_counts"]["critical"] == 1
    assert result["severity_counts"]["high"] == 2
    assert result["severity_counts"]["low"] == 1
    assert result["total_findings"] == 4


def test_high_score_reaches_critical_band():
    findings = [make_finding("critical") for _ in range(3)]
    result = score_findings(findings)
    assert result["risk_band"] == "Critical"
