# ==============================================================================
# Product:       lh-sbom-auditor (lh-sbom)
# Module:        src.lh_sbom_auditor.exporters.table
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Rich terminal table exporter for audit findings and SBOM reports."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from lh_sbom_auditor.models import AuditReport, DependencyGraph, Severity

_SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "cyan",
}


def render_audit_table(report: AuditReport, console: Console | None = None) -> None:
    """Print an interactive, formatted Rich table of audit findings to the terminal."""
    con = console or Console()

    # Header Panel
    con.print(
        Panel.fit(
            "[bold cyan]Logihertz Systems - Supply Chain Security Auditor[/bold cyan]\n"
            f"[dim]Target: {report.target_path} | Ecosystem: {report.ecosystem.value.upper()} | "
            f"Packages Scanned: {report.graph.total_count}[/dim]",
            border_style="cyan",
        )
    )

    # Summary Panel
    crit_style = "bold red" if report.critical_count > 0 else "dim"
    high_style = "red" if report.high_count > 0 else "dim"
    med_style = "yellow" if report.medium_count > 0 else "dim"
    low_style = "blue" if report.low_count > 0 else "dim"

    summary_text = (
        f"Findings Summary: "
        f"[{crit_style}]Critical: {report.critical_count}[/{crit_style}] | "
        f"[{high_style}]High: {report.high_count}[/{high_style}] | "
        f"[{med_style}]Medium: {report.medium_count}[/{med_style}] | "
        f"[{low_style}]Low: {report.low_count}[/{low_style}]"
    )
    con.print(Panel(summary_text, border_style="blue"))

    if report.total_findings == 0:
        con.print(
            Panel(
                "[bold green]✓ PASSED: No security policy violations found![/bold green]",
                border_style="green",
            )
        )
        return

    table = Table(
        title="Detected Supply Chain Risks & Policy Violations",
        header_style="bold magenta",
        show_lines=True,
    )
    table.add_column("Severity", justify="center", style="bold", width=12)
    table.add_column("Rule ID", justify="center", style="dim", width=14)
    table.add_column("Package", style="bold white", width=22)
    table.add_column("Issue Title & Description", style="white", min_width=35)
    table.add_column("Recommendation", style="green", min_width=30)

    for finding in report.findings:
        sev_style = _SEVERITY_STYLES.get(finding.severity, "white")
        sev_text = Text(finding.severity.value, style=sev_style)

        pkg_str = f"{finding.package_name}\n[dim]({finding.package_version})[/dim]"

        desc_str = f"[bold]{finding.title}[/bold]\n{finding.description}"
        table.add_row(
            sev_text,
            finding.rule_id,
            pkg_str,
            desc_str,
            finding.recommendation,
        )

    con.print(table)

    if report.passed:
        con.print(
            "[bold yellow]Status: PASSED WITH WARNINGS (No Critical or High issues)[/bold yellow]\n"
        )
    else:
        con.print(
            "[bold red]Status: FAILED (Critical or High policy violations detected)[/bold red]\n"
        )


def render_graph_table(graph: DependencyGraph, console: Console | None = None) -> None:
    """Print a summary table of the dependency graph components."""
    con = console or Console()

    table = Table(
        title=f"Dependency Graph Inventory: {graph.root_name} (v{graph.root_version})",
        header_style="bold cyan",
        show_lines=False,
    )
    table.add_column("Package Name", style="bold white")
    table.add_column("Version", style="cyan")
    table.add_column("Type", justify="center")
    table.add_column("Pinned", justify="center")
    table.add_column("License", style="italic")
    table.add_column("Hashes", justify="center", style="dim")

    for pkg in sorted(graph.all_packages, key=lambda p: p.name.lower()):
        direct_str = "[bold green]Direct[/bold green]" if pkg.direct else "[dim]Transitive[/dim]"
        pinned_str = "[green]Yes[/green]" if pkg.is_pinned else "[bold red]No[/bold red]"
        lic_str = pkg.license or "[dim]Undeclared[/dim]"
        hash_count = str(len(pkg.checksums)) if pkg.checksums else "[dim]None[/dim]"

        table.add_row(
            pkg.name,
            pkg.version,
            direct_str,
            pinned_str,
            lic_str,
            hash_count,
        )

    con.print(table)
