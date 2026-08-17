"""
Scriptable command-line interface. No prompts, suitable for automation
or CI pipelines.

Usage:
    python main.py audit --input sample_configs/paloalto_sample.xml --output report.html
    python main.py audit --input sample_configs/paloalto_sample.xml --logs sample_configs/sample_traffic_log.csv --output report.html
"""

import sys

import click

from fireaudit.log_parsers.traffic_log_parser import TrafficLogParser
from fireaudit.parsers.detect_format import detect_parser
from fireaudit.report.html_report import render_html_report
from fireaudit.report.report_builder import build_report


@click.group()
def cli():
    pass


@cli.command()
@click.option("--input", "input_path", required=True, help="Path to the firewall config export")
@click.option("--logs", "logs_path", default=None, help="Optional path to a traffic log CSV for real usage data")
@click.option("--output", "output_path", default="report.html", help="Path to write the HTML report")
def audit(input_path, logs_path, output_path):
    """Run a full audit against a firewall config file and write an HTML report."""
    try:
        parser = detect_parser(input_path)
        ruleset = parser.parse(input_path)
    except Exception as exc:
        click.echo(f"Failed to parse {input_path}: {exc}", err=True)
        sys.exit(1)

    log_events = None
    if logs_path:
        try:
            log_events = TrafficLogParser().parse(logs_path)
        except Exception as exc:
            click.echo(f"Failed to parse log file {logs_path}: {exc}", err=True)
            sys.exit(1)

    report_data = build_report(ruleset, log_events=log_events)
    render_html_report(report_data, output_path)

    scoring = report_data["scoring"]
    click.echo(f"Parsed {report_data['total_rules']} rules from {input_path} ({ruleset.vendor})")
    if log_events is not None:
        click.echo(f"Correlated {len(log_events)} log events from {logs_path}")
    click.echo(f"Findings: {scoring['total_findings']} | Risk score: {scoring['total_score']} ({scoring['risk_band']})")
    click.echo(f"Report written to {output_path}")


if __name__ == "__main__":
    cli()
