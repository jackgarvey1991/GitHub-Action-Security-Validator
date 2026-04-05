"""
GASV - GitHub Actions Security Validator
CLI entry point
"""
import sys
import json
from pathlib import Path
import click
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich import box

from gasv.scanner import Scanner

console = Console()

SEVERITY_COLOURS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "white",
}


@click.group()
@click.version_option(version="0.1.0", prog_name="gasv")
def cli():
    """GASV - GitHub Actions Security Validator

    Statically analyses GitHub Actions workflow YAML files to detect
    security vulnerabilities and produce remediation recommendations.
    """


@cli.command()
@click.argument("paths", nargs=-1, required=True, type=click.Path(exists=True))
@click.option(
    "--format",
    "output_format",
    default="table",
    type=click.Choice(["table", "json", "sarif"]),
    help="Output format (default: table)",
)
@click.option(
    "--severity",
    default="LOW",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]),
    help="Minimum severity to report (default: LOW)",
)
@click.option("--exit-zero", is_flag=True, help="Always exit 0 even if findings exist")
def scan(paths, output_format, severity, exit_zero):
    """Scan one or more workflow YAML files or directories for security issues."""
    severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    min_level = severity_order.index(severity)

    workflow_files = []
    for path_str in paths:
        path = Path(path_str)
        if path.is_dir():
            workflow_files.extend(path.rglob("*.yml"))
            workflow_files.extend(path.rglob("*.yaml"))
        else:
            workflow_files.append(path)

    if not workflow_files:
        console.print("[yellow]No workflow files found.[/yellow]")
        sys.exit(0)

    scanner = Scanner()
    all_findings = []

    for wf_path in workflow_files:
        findings = scanner.scan_file(wf_path)
        filtered = [
            f for f in findings
            if severity_order.index(f["severity"]) >= min_level
        ]
        all_findings.extend(filtered)

    if output_format == "json":
        click.echo(json.dumps(all_findings, indent=2))
    elif output_format == "sarif":
        click.echo(json.dumps(_to_sarif(all_findings), indent=2))
    else:
        _print_table(all_findings, workflow_files)

    has_high_plus = any(
        severity_order.index(f["severity"]) >= severity_order.index("HIGH")
        for f in all_findings
    )
    if has_high_plus and not exit_zero:
        sys.exit(1)


def _print_table(findings, scanned_files):
    """Render findings as a Rich table."""
    console.print(
        f"\n[bold]GASV[/bold] — scanned [cyan]{len(scanned_files)}[/cyan] file(s)\n"
    )

    if not findings:
        console.print("[bold green]✓ No issues found.[/bold green]\n")
        return

    table = Table(
        title=f"{len(findings)} finding(s)",
        box=box.ROUNDED,
        show_lines=True,
        expand=True,
    )
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Rule", width=28)
    table.add_column("File", width=30)
    table.add_column("Location", width=12)
    table.add_column("Description")

    for f in sorted(findings, key=lambda x: ["INFO","LOW","MEDIUM","HIGH","CRITICAL"].index(x["severity"]), reverse=True):
        sev = f["severity"]
        colour = SEVERITY_COLOURS.get(sev, "white")
        table.add_row(
            Text(sev, style=colour),
            f["rule_id"],
            f["file"],
            f.get("location", "—"),
            f["message"],
        )

    console.print(table)
    console.print()

    # Remediation summary
    seen_rules = set()
    console.print("[bold]Remediation Guidance[/bold]")
    for f in findings:
        rid = f["rule_id"]
        if rid not in seen_rules:
            seen_rules.add(rid)
            console.print(f"  [cyan]{rid}[/cyan]: {f.get('remediation', 'See rule documentation.')}")
    console.print()


def _to_sarif(findings):
    """Convert findings to SARIF 2.1.0 format."""
    rules = {}
    results = []
    for f in findings:
        rid = f["rule_id"]
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": rid.replace("-", " ").title(),
                "shortDescription": {"text": f.get("message", "")},
                "help": {"text": f.get("remediation", "")},
            }
        results.append({
            "ruleId": rid,
            "level": f["severity"].lower() if f["severity"] != "CRITICAL" else "error",
            "message": {"text": f["message"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"]},
                    "region": {"startLine": f.get("line", 1)},
                }
            }],
        })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "GASV",
                    "version": "0.1.0",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }


def main():
    cli()


if __name__ == "__main__":
    main()
