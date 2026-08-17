from setuptools import find_packages, setup

setup(
    name="fireaudit",
    version="0.1.0",
    description="Parses firewall rule exports and audits them for shadowing, permissiveness, and other risks",
    packages=find_packages(exclude=["tests"]),
    install_requires=[
        "click>=8.1",
        "rich>=13.7",
        "jinja2>=3.1",
    ],
    entry_points={
        "console_scripts": [
            "fireaudit=fireaudit.cli:cli",
        ],
    },
    python_requires=">=3.9",
)
