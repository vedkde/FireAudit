"""
Interactive terminal walkthrough of the audit tool, built on rich.

This is meant for demos and manual use: pick a file, watch the analysis
run, see a summary table right in the terminal, then optionally generate
and open the full HTML report.
"""

import glob
import os
import time
import webbrowser
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from fireaudit.log_parsers.traffic_log_parser import TrafficLogParser
from fireaudit.parsers.detect_format import detect_parser
from fireaudit.report.html_report import render_html_report
from fireaudit.report.report_builder import build_report

console = Console()

SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "orange3",
    "medium": "yellow",
    "low": "green",
}


def _pick_input_file() -> str:
    console.print(Panel.fit("FireAudit", subtitle="interactive mode"))

    sample_files = sorted(glob.glob("sample_configs/*"))
    if sample_files:
        console.print("\nSample configs available:")
        for i, path in enumerate(sample_files, start=1):
            console.print(f"  [{i}] {path}")
        console.print("  [0] Enter a custom file path")

        choice = Prompt.ask("\nPick a file", default="1")
        if choice.strip() == "0":
            return Prompt.ask("Enter the path to your firewall config file")
        try:
            index = int(choice) - 1
            return sample_files[index]
        except (ValueError, IndexError):
            console.print("[red]Invalid choice, falling back to manual path entry.[/red]")

    return Prompt.ask("Enter the path to your firewall config file")


def _pick_log_file() -> Optional[str]:
    if not Confirm.ask("\nDo you have a traffic log to cross-reference for real usage data?", default=False):
        return None

    sample_logs = sorted(glob.glob("sample_configs/*log*"))
    if sample_logs:
        console.print("\nSample logs available:")
        for i, path in enumerate(sample_logs, start=1):
            console.print(f"  [{i}] {path}")
        console.print("  [0] Enter a custom file path")

        choice = Prompt.ask("\nPick a file", default="1")
        if choice.strip() == "0":
            return Prompt.ask("Enter the path to your traffic log file")
        try:
            index = int(choice) - 1
            return sample_logs[index]
        except (ValueError, IndexError):
            console.print("[red]Invalid choice, falling back to manual path entry.[/red]")

    return Prompt.ask("Enter the path to your traffic log file")


def _print_summary_table(report_data: dict) -> None:
    scoring = report_data["scoring"]

    console.print()
    console.print(f"[bold]Rules parsed:[/bold] {report_data['total_rules']}  "
                   f"[bold]Vendor:[/bold] {report_data['vendor']}")
    console.print(f"[bold]Risk score:[/bold] {scoring['total_score']}  "
                   f"[bold]Risk band:[/bold] {scoring['risk_band']}")

    table = Table(title="Findings", show_lines=False)
    table.add_column("Severity")
    table.add_column("Rule")
    table.add_column("Issue")
    table.add_column("Message", overflow="fold")

    for finding in report_data["findings"]:
        style = SEVERITY_STYLE.get(finding.severity, "white")
        table.add_row(
            f"[{style}]{finding.severity.upper()}[/{style}]",
            finding.rule.name,
            finding.issue_type,
            finding.message,
        )

    console.print(table)


def run_interactive() -> None:
    input_path = _pick_input_file()

    if not os.path.exists(input_path):
        console.print(f"[red]File not found: {input_path}[/red]")
        return

    try:
        parser = detect_parser(input_path)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        return

    console.print(f"\nDetected format: [bold]{parser.vendor_name}[/bold]")

    with console.status("[bold green]Parsing rule base..."):
        time.sleep(0.4)
        ruleset = parser.parse(input_path)

    log_path = _pick_log_file()
    log_events = None
    if log_path:
        if not os.path.exists(log_path):
            console.print(f"[red]Log file not found: {log_path}, continuing without it.[/red]")
        else:
            with console.status("[bold green]Parsing traffic log..."):
                time.sleep(0.3)
                log_events = TrafficLogParser().parse(log_path)
            console.print(f"Loaded {len(log_events)} log events")

    with console.status("[bold green]Running analysis (shadowing, permissiveness, unused, logging, duplicates)..."):
        time.sleep(0.6)
        report_data = build_report(ruleset, log_events=log_events)

    _print_summary_table(report_data)

    if Confirm.ask("\nGenerate full HTML report?", default=True):
        output_path = Prompt.ask("Output file path", default="report.html")
        render_html_report(report_data, output_path)
        console.print(f"[green]Report written to {output_path}[/green]")

        if Confirm.ask("Open it in your browser now?", default=True):
            webbrowser.open(f"file://{os.path.abspath(output_path)}")


if __name__ == "__main__":
    run_interactive()
