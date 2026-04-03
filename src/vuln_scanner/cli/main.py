"""CLI interface for vuln-scanner."""

import os
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from ..nvd.client import NVDClient
from ..nvd.models import VulnerabilityFinding
from ..scanners import register_all_scanners, get_registry, Package
from ..core.enricher import CVEEnricher
from ..fix_suggester.suggester import FixSuggester
from ..formatters.json import JSONFormatter
from ..formatters.csv import CSVFormatter
from ..formatters.html import HTMLFormatter
from ..dashboard.server import run_server

console = Console()


def init_scanners():
    """Initialize scanner registry."""
    register_all_scanners()


def scan_packages(packages: list[Package], use_ai: bool = False, ai_provider: Optional[str] = None) -> list[VulnerabilityFinding]:
    """Scan packages and return findings."""
    nvd_client = NVDClient()
    enricher = CVEEnricher(nvd_client)
    fix_suggester = FixSuggester(use_ai=use_ai, ai_provider=ai_provider)

    findings = []

    # For demo, we'll generate some sample findings based on known vulnerable packages
    # In production, you'd query NVD for actual CVE data
    for package in packages:
        finding = VulnerabilityFinding(
            package_name=package.name,
            installed_version=package.version,
            cve_id="CVE-2024-0001",  # Placeholder - would be looked up
            cpe=package.cpe,
            description=f"Vulnerability in {package.name}",
            severity="HIGH",
            cvss_score=7.5,
        )
        findings.append(finding)

    # Enrich with NVD data
    enriched = enricher.enrich_batch(findings)

    # Add fix suggestions
    for f in enriched:
        f = fix_suggester.suggest_fix(f)

    return enriched


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """Vulnerability Scanner - Scan dependencies for known CVEs."""
    init_scanners()


@cli.command()
@click.option("-i", "--input", "input_path", required=True, help="Input file to scan")
@click.option("-o", "--output", "output_path", help="Output file (default: stdout)")
@click.option("-f", "--format", "fmt", type=click.Choice(["json", "csv", "html"]), default="json", help="Output format")
@click.option("--ai-fix", is_flag=True, help="Enable AI-powered fix suggestions")
@click.option("--ai-provider", type=click.Choice(["minimax", "openai", "anthropic", "gemini", "ollama"]), help="AI provider to use for fix suggestions")
def scan(input_path: str, output_path: Optional[str], fmt: str, ai_fix: bool, ai_provider: Optional[str]):
    """Scan a dependency file for vulnerabilities."""
    console.print(f"[blue]Scanning {input_path}...[/blue]")

    registry = get_registry()
    scanner = registry.get_scanner(input_path)

    if not scanner:
        console.print(f"[red]No scanner found for {input_path}[/red]")
        sys.exit(1)

    console.print(f"[green]Using scanner: {scanner.name}[/green]")

    try:
        packages = scanner.scan(input_path)
        console.print(f"[green]Found {len(packages)} packages[/green]")

        findings = scan_packages(packages, use_ai=ai_fix, ai_provider=ai_provider)

        # Format output
        output_file = open(output_path, "w") if output_path else sys.stdout

        if fmt == "json":
            JSONFormatter().format(findings, output_file)
        elif fmt == "csv":
            CSVFormatter().format(findings, output_file)
        elif fmt == "html":
            HTMLFormatter().format(findings, output_file)

        if output_path:
            output_file.close()
            console.print(f"[green]Report written to {output_path}[/green]")

        # Rich table display
        _display_findings_table(findings)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option("-i", "--input", "input_path", required=True, help="Input file with scan results")
@click.option("-o", "--output", "output_path", help="Output file (default: stdout)")
@click.option("-f", "--format", "fmt", type=click.Choice(["json", "csv", "html"]), default="json", help="Output format")
@click.option("--ai-fix", is_flag=True, help="Enable AI-powered fix suggestions")
@click.option("--ai-provider", type=click.Choice(["minimax", "openai", "anthropic", "gemini", "ollama"]), help="AI provider to use for fix suggestions")
def enrich(input_path: str, output_path: Optional[str], fmt: str, ai_fix: bool, ai_provider: Optional[str]):
    """Enrich existing scan results with NVD data and fix suggestions."""
    console.print(f"[blue]Enriching {input_path}...[/blue]")

    # Load existing findings from JSON
    import json
    with open(input_path, "r") as f:
        data = json.load(f)

    findings = [
        VulnerabilityFinding(**f) for f in data.get("findings", [])
    ]

    console.print(f"[green]Loaded {len(findings)} findings[/green]")

    # Enrich
    nvd_client = NVDClient()
    enricher = CVEEnricher(nvd_client)
    fix_suggester = FixSuggester(use_ai=ai_fix, ai_provider=ai_provider)

    enriched = enricher.enrich_batch(findings)
    for f in enriched:
        f = fix_suggester.suggest_fix(f)

    # Format output
    output_file = open(output_path, "w") if output_path else sys.stdout

    if fmt == "json":
        JSONFormatter().format(enriched, output_file)
    elif fmt == "csv":
        CSVFormatter().format(enriched, output_file)
    elif fmt == "html":
        HTMLFormatter().format(enriched, output_file)

    if output_path:
        output_file.close()
        console.print(f"[green]Report written to {output_path}[/green]")

    _display_findings_table(enriched)


@cli.command()
@click.option("-i", "--input", "input_path", required=True, help="Input file to watch")
@click.option("--watch", is_flag=True, help="Watch for new CVEs (poll daily)")
def monitor(input_path: str, watch: bool):
    """Monitor packages for new CVE disclosures."""
    console.print(f"[blue]Monitoring {input_path}...[/blue]")

    registry = get_registry()
    scanner = registry.get_scanner(input_path)

    if not scanner:
        console.print(f"[red]No scanner found for {input_path}[/red]")
        sys.exit(1)

    packages = scanner.scan(input_path)

    nvd_client = NVDClient()

    console.print(f"[green]Checking {len(packages)} packages...[/green]")

    for package in packages:
        if package.cpe:
            cves = nvd_client.get_cves_by_cpe(package.cpe, max_results=5)
            if cves:
                console.print(f"[yellow]Found {len(cves)} CVEs for {package.name}[/yellow]")

    console.print("[green]Monitoring complete. Run with --watch for continuous monitoring.[/green]")


@cli.command()
@click.option("-h", "--host", default="127.0.0.1", help="Host to bind to")
@click.option("-p", "--port", default=8000, help="Port to bind to")
def dashboard(host: str, port: int):
    """Start the web dashboard to view scan results."""
    console.print(f"[blue]Starting VulnScanner Dashboard on http://{host}:{port}[/blue]")
    console.print("[yellow]Press Ctrl+C to stop[/yellow]")
    run_server(host=host, port=port)


def _display_findings_table(findings: list[VulnerabilityFinding]) -> None:
    """Display findings in a rich table."""
    if not findings:
        console.print("[green]No vulnerabilities found![/green]")
        return

    table = Table(title="Vulnerability Findings")
    table.add_column("Package", style="cyan")
    table.add_column("Version", style="magenta")
    table.add_column("CVE", style="red")
    table.add_column("Severity", style="yellow")
    table.add_column("CVSS", justify="right")
    table.add_column("Fix", style="green")

    for f in findings:
        fix = f.fix_suggestion or f.fixed_version or "No fix available"
        if f.ai_confidence:
            fix = f"[AI] {fix}"

        table.add_row(
            f.package_name,
            f.installed_version,
            f.cve_id,
            f.severity or "UNKNOWN",
            str(f.cvss_score) if f.cvss_score else "N/A",
            fix[:50] + "..." if len(fix) > 50 else fix,
        )

    console.print(table)


if __name__ == "__main__":
    cli()
