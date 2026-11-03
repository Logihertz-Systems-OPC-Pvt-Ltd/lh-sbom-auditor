"""Command-line interface (CLI) for lh-sbom-auditor."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from lh_sbom_auditor import __version__
from lh_sbom_auditor.auditor.engine import AuditEngine
from lh_sbom_auditor.auditor.policy import AuditPolicy
from lh_sbom_auditor.exporters.json_exporter import export_audit_json, export_graph_json
from lh_sbom_auditor.exporters.sarif import export_audit_sarif, export_graph_sarif
from lh_sbom_auditor.exporters.table import render_audit_table
from lh_sbom_auditor.parsers.base import detect_and_parse
from lh_sbom_auditor.sbom.cyclonedx import CycloneDXGenerator

app = typer.Typer(
    name="lh-sbom",
    help="Logihertz Systems - Supply Chain Security CLI & CycloneDX SBOM Auditor.",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()
err_console = Console(stderr=True)


class GenerateFormat(StrEnum):
    """Output format for generate command."""

    CYCLONEDX = "cyclonedx"
    JSON = "json"
    SARIF = "sarif"


class AuditFormat(StrEnum):
    """Output format for audit command."""

    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"


def version_callback(value: bool) -> None:
    """Display CLI tool version."""
    if value:
        console.print(
            f"[bold cyan]lh-sbom-auditor[/bold cyan] version [bold green]{__version__}[/bold green]"
        )
        raise typer.Exit(code=0)


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-v",
            help="Show tool version and exit.",
            callback=version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """Logihertz Systems Software Supply Chain Security Auditor."""
    pass


@app.command(name="generate")
def generate(
    path: Annotated[
        Path,
        typer.Argument(
            help="Path to manifest/lockfile (uv.lock, requirements.txt, package-lock.json) or dir.",
            exists=True,
            readable=True,
        ),
    ],
    format: Annotated[
        GenerateFormat,
        typer.Option(
            "--format",
            "-f",
            help="Output format: cyclonedx (CycloneDX 1.5 JSON), json (graph), or sarif.",
            case_sensitive=False,
        ),
    ] = GenerateFormat.CYCLONEDX,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Output file destination (writes to stdout if omitted).",
        ),
    ] = None,
) -> None:
    """Generate a standard CycloneDX v1.5 JSON SBOM or dependency inventory."""
    try:
        graph = detect_and_parse(path)
    except Exception as exc:
        err_console.print(f"[bold red]Error parsing lockfile:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    # Format output according to requested format
    if format == GenerateFormat.CYCLONEDX:
        content = CycloneDXGenerator(graph).generate_json()
    elif format == GenerateFormat.JSON:
        content = export_graph_json(graph)
    elif format == GenerateFormat.SARIF:
        content = export_graph_sarif(graph)
    else:
        err_console.print(f"[bold red]Unsupported format:[/bold red] {format}")
        raise typer.Exit(code=1)

    if output is not None:
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(content, encoding="utf-8")
            err_console.print(
                f"[green]✓ Successfully generated {format.value} SBOM to:[/green] {output}"
            )
        except Exception as exc:
            err_console.print(f"[bold red]Failed to write output to file:[/bold red] {exc}")
            raise typer.Exit(code=1) from exc
    else:
        typer.echo(content)


@app.command(name="audit")
def audit(
    path: Annotated[
        Path,
        typer.Argument(
            help="Path to manifest/lockfile (uv.lock, requirements.txt, package-lock.json) or dir.",
            exists=True,
            readable=True,
        ),
    ],
    policy: Annotated[
        Path | None,
        typer.Option(
            "--policy",
            "-p",
            help="Path to custom policy file (YAML or JSON).",
            exists=True,
            readable=True,
        ),
    ] = None,
    format: Annotated[
        AuditFormat,
        typer.Option(
            "--format",
            "-f",
            help="Audit report format: table (Rich), json, or sarif (OASIS SARIF 2.1.0).",
            case_sensitive=False,
        ),
    ] = AuditFormat.TABLE,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Output destination file. If omitted, outputs directly to console/stdout.",
        ),
    ] = None,
) -> None:
    """Audit dependencies against supply chain risk rules (unpinned, license, typosquatting)."""
    try:
        graph = detect_and_parse(path)
    except Exception as exc:
        err_console.print(f"[bold red]Error parsing target manifest:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    # Load policy
    if policy is not None:
        try:
            audit_policy = AuditPolicy.from_file(policy)
        except Exception as exc:
            err_console.print(f"[bold red]Error loading policy file '{policy}':[/bold red] {exc}")
            raise typer.Exit(code=1) from exc
    else:
        audit_policy = AuditPolicy.default_policy()

    # Run audit
    engine = AuditEngine(policy=audit_policy)
    report = engine.audit(graph)

    # Export report
    if format == AuditFormat.TABLE:
        if output is not None:
            # Capture table formatting for file export
            file_console = Console(record=True, width=120)
            render_audit_table(report, console=file_console)
            content = file_console.export_text()
            try:
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(content, encoding="utf-8")
                err_console.print(f"[green]✓ Audit table report written to:[/green] {output}")
            except Exception as exc:
                err_console.print(f"[bold red]Failed to write report to file:[/bold red] {exc}")
                raise typer.Exit(code=1) from exc
        else:
            render_audit_table(report, console=console)

    elif format == AuditFormat.JSON:
        content = export_audit_json(report)
        if output is not None:
            try:
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(content, encoding="utf-8")
                err_console.print(f"[green]✓ Audit JSON report written to:[/green] {output}")
            except Exception as exc:
                err_console.print(f"[bold red]Failed to write report to file:[/bold red] {exc}")
                raise typer.Exit(code=1) from exc
        else:
            typer.echo(content)

    elif format == AuditFormat.SARIF:
        content = export_audit_sarif(report)
        if output is not None:
            try:
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(content, encoding="utf-8")
                err_console.print(
                    f"[green]✓ Audit SARIF v2.1.0 report written to:[/green] {output}"
                )
            except Exception as exc:
                err_console.print(f"[bold red]Failed to write report to file:[/bold red] {exc}")
                raise typer.Exit(code=1) from exc
        else:
            typer.echo(content)

    # Determine exit code based on policy compliance
    if not report.passed:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
