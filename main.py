"""
Entry point.

No arguments: launches the interactive terminal walkthrough.
Any arguments: routes to the scriptable click-based CLI.

Examples:
    python main.py
    python main.py audit --input sample_configs/paloalto_sample.xml --output report.html
"""

import sys

if __name__ == "__main__":
    if len(sys.argv) == 1:
        from fireaudit.interactive import run_interactive
        run_interactive()
    else:
        from fireaudit.cli import cli
        cli()
