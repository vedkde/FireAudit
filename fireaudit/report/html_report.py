"""
Renders the report data dict into a standalone HTML file using Jinja2.
"""

import os

from jinja2 import Environment, FileSystemLoader

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")


def render_html_report(report_data: dict, output_path: str) -> str:
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template("report_template.html")

    html = template.render(**report_data)

    with open(output_path, "w") as f:
        f.write(html)

    return output_path
