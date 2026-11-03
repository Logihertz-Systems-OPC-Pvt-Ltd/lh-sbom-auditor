"""Structured JSON exporter for graphs and audit reports."""

from __future__ import annotations

import json
from typing import Any

from lh_sbom_auditor import __version__
from lh_sbom_auditor.models import AuditReport, DependencyGraph


def export_audit_json(report: AuditReport, indent: int = 2) -> str:
    """Export an AuditReport as formatted JSON string."""
    data = {
        "$schema": "https://logihertz.com/schemas/lh-sbom-audit-report-v1.json",
        "scanner": {
            "name": "lh-sbom-auditor",
            "vendor": "Logihertz Systems OPC Pvt Ltd",
            "version": __version__,
        },
        **report.to_dict(),
    }
    return json.dumps(data, indent=indent, default=str)


def export_graph_json(graph: DependencyGraph, indent: int = 2) -> str:
    """Export normalized DependencyGraph as formatted JSON string."""
    data: dict[str, Any] = {
        "$schema": "https://logihertz.com/schemas/lh-dependency-graph-v1.json",
        "scanner": {
            "name": "lh-sbom-auditor",
            "vendor": "Logihertz Systems OPC Pvt Ltd",
            "version": __version__,
        },
        **graph.to_dict(),
    }
    return json.dumps(data, indent=indent, default=str)

