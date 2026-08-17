# FireAudit

A tool that reads a firewall's exported rulebase and flags the mistakes that
normally get caught by manually scanning through hundreds of rules: rules
that can never fire, rules that are far too permissive, rules nobody uses,
rules with logging turned off, and duplicate rules.

It supports Palo Alto XML exports, Fortinet configs, and generic CSV. It
optionally cross-references a traffic log for real usage data instead of
relying on the config's hit-count alone.

## Why this exists

Firewall rulebases grow over years, through many admins, with few rules
ever removed. Two problems are especially easy to miss by reading rules
top to bottom: a rule that is silently shadowed by an earlier, broader
rule and never actually applies, and a rule that looks used because its
hit-count is nonzero, when that count may just be old traffic from before
the last counter reset. This tool checks for both, along with a handful
of other common issues, and explains each finding in plain language with
a suggested fix.

## What it checks

- **Shadowed rules**: a rule that can never match traffic because an
  earlier rule already covers the same source, destination, and service
- **Overly permissive rules**: source, destination, or service set to
  "any" on an allow rule
- **Unused rules**: zero hit-count in the config export, or (if a traffic
  log is provided) zero matching traffic across the whole log period
- **Missing logging**: allow rules with logging disabled
- **Duplicate rules**: two rules with identical match criteria and action

## How it works

Every input format (Palo Alto XML, Fortinet config, CSV) is parsed into
the same internal `Rule` model, so every check runs the same way
regardless of which vendor the config came from. Shadowing and log
correlation both use real subnet containment logic through Python's
`ipaddress` module rather than string comparison, so `10.0.1.5/32` is
correctly understood to sit inside `10.0.1.0/24`.

If a traffic log is supplied, its entries are matched back to rules by
rule name where available, and by matching source, destination, service,
and action otherwise. This gives a real last-seen date for each rule
instead of a hit-count that resets on an unknown schedule. Every finding
in the report says plainly whether it is confirmed by log data or based
on hit-count alone.

Findings are scored by severity and rolled up into an overall risk score
and risk band, then rendered into a single HTML report.

## Installation

```bash
pip install -r requirements.txt
```

Requires Python 3.9 or later.

## Usage

Interactive mode, no arguments needed:

```bash
python main.py
```

This walks you through picking a config file, optionally a traffic log,
then prints a findings summary to the terminal and offers to generate
and open the full HTML report.

Scriptable mode, for automation:

```bash
python main.py audit --input sample_configs/paloalto_sample.xml --output report.html
```

With a traffic log for stronger usage data:

```bash
python main.py audit --input sample_configs/paloalto_sample.xml --logs sample_configs/sample_traffic_log.csv --output report.html
```

## Project layout

```
fireaudit/
    models.py         Rule, RuleSet, Finding, LogEvent data classes
    parsers/            one parser per config format, all output a RuleSet
    log_parsers/         traffic log parser, outputs a list of LogEvent
    analysis/             one file per check, each returns a list of Finding
    scoring.py           turns Findings into a risk score and risk band
    report/               builds report data and renders it to HTML
    cli.py                 scriptable command line interface
    interactive.py         guided terminal walkthrough
```

Adding a new firewall vendor means writing one new parser that returns
the standard `Rule` model. Nothing else in the codebase needs to change.

## Sample data

`sample_configs/` contains matching Palo Alto, Fortinet, and CSV
rulebases with the same set of deliberate issues built into each, plus a
matching traffic log, so you can compare results across formats and see
the difference log correlation makes.

## Tests

```bash
pytest
```

## Limitations

This is static analysis of a config export, not a live scan of the
firewall. Hit-count and traffic-log data only ever go as far back as
what was actually exported or captured. A rule that fires rarely (a
quarterly job, a disaster recovery path) can still be misflagged as
unused if the log window does not happen to cover that traffic.
