# ==============================================================================
# Product:       lh-sbom-auditor (lh-sbom)
# Module:        src.lh_sbom_auditor.exporters.sarif
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""OASIS SARIF v2.1.0 exporter for static analysis integration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lh_sbom_auditor import __version__
from lh_sbom_auditor.models import AuditReport, DependencyGraph, Severity

SARIF_SCHEMA_V210 = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

# Rule definitions catalogue for SARIF driver
_RULES_CATALOGUE = [
    {
        "id": "LH-RULE-001",
        "name": "UnpinnedDependencyVersion",
        "shortDescription": {"text": "Dependency version is unpinned or uses a floating range."},
        "fullDescription": {
            "text": (
                "Unpinned dependencies create non-deterministic build environments and leave "
                "the project susceptible to upstream supply chain attacks and breaking changes."
            )
        },
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://docs.logihertz.com/rules/LH-RULE-001",
    },
    {
        "id": "LH-RULE-002",
        "name": "LicensePolicyViolation",
        "shortDescription": {
            "text": "Dependency license violates organizational compliance policy."
        },
        "fullDescription": {
            "text": (
                "The package license is either forbidden (e.g. restrictive copyleft licenses like "
                "GPL/AGPL in commercial software) or not on the approved whitelist."
            )
        },
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://docs.logihertz.com/rules/LH-RULE-002",
    },
    {
        "id": "LH-RULE-003",
        "name": "UndeclaredOrUnknownLicense",
        "shortDescription": {"text": "Dependency has no declared license in its package manifest."},
        "fullDescription": {
            "text": (
                "Using software components without an explicitly declared open-source license "
                "creates legal ambiguity and intellectual property liabilities."
            )
        },
        "defaultConfiguration": {"level": "warning"},
        "helpUri": "https://docs.logihertz.com/rules/LH-RULE-003",
    },
    {
        "id": "LH-RULE-004",
        "name": "TyposquattingRiskVector",
        "shortDescription": {"text": "Package name closely mimics a popular library name."},
        "fullDescription": {
            "text": (
                "Typosquatting attacks deploy packages with names nearly identical to established "
                "open-source packages to trick developers into installing malicious code."
            )
        },
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://docs.logihertz.com/rules/LH-RULE-004",
    },
]


def _map_severity_to_sarif_level(severity: Severity) -> str:
    """Map internal severity to SARIF v2.1.0 level (error, warning, note)."""
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def export_audit_sarif(report: AuditReport, indent: int = 2) -> str:
    """Generate official OASIS SARIF v2.1.0 JSON report from AuditReport."""
    rules_index_map = {r["id"]: idx for idx, r in enumerate(_RULES_CATALOGUE)}

    uri = (
        Path(report.target_path).as_uri()
        if Path(report.target_path).is_absolute()
        else report.target_path
    )

    results: list[dict[str, Any]] = []
    for finding in report.findings:
        rule_idx = rules_index_map.get(finding.rule_id, 0)
        level = _map_severity_to_sarif_level(finding.severity)

        result_obj: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "ruleIndex": rule_idx,
            "level": level,
            "message": {"text": f"{finding.title}: {finding.description}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": 1, "startColumn": 1},
                    }
                }
            ],
            "properties": {
                "packageName": finding.package_name,
                "packageVersion": finding.package_version,
                "recommendation": finding.recommendation,
                "severity": finding.severity.value,
                "purl": finding.location,
            },
        }
        results.append(result_obj)

    sarif_doc: dict[str, Any] = {
        "$schema": SARIF_SCHEMA_V210,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "lh-sbom-auditor",
                        "organization": "Logihertz Systems OPC Pvt Ltd",
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-sbom-auditor",
                        "rules": _RULES_CATALOGUE,
                    }
                },
                "artifacts": [{"location": {"uri": uri}}],
                "results": results,
            }
        ],
    }

    return json.dumps(sarif_doc, indent=indent)


def export_graph_sarif(graph: DependencyGraph, indent: int = 2) -> str:
    """Generate structural SARIF inventory report for a DependencyGraph."""
    uri = (
        Path(graph.manifest_path).as_uri()
        if Path(graph.manifest_path).is_absolute()
        else graph.manifest_path
    )

    results: list[dict[str, Any]] = []
    for pkg in graph.all_packages:
        level = "warning" if not pkg.is_pinned else "note"
        status_str = "Pinned" if pkg.is_pinned else "Unpinned"
        msg = f"Component '{pkg.name}@{pkg.version}' ({status_str})"

        results.append(
            {
                "ruleId": "LH-RULE-001" if not pkg.is_pinned else "LH-INVENTORY",
                "level": level,
                "message": {"text": msg},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "properties": {
                    "packageName": pkg.name,
                    "packageVersion": pkg.version,
                    "purl": pkg.purl,
                    "direct": pkg.direct,
                },
            }
        )

    sarif_doc: dict[str, Any] = {
        "$schema": SARIF_SCHEMA_V210,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "lh-sbom-auditor",
                        "organization": "Logihertz Systems OPC Pvt Ltd",
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-sbom-auditor",
                        "rules": _RULES_CATALOGUE,
                    }
                },
                "artifacts": [{"location": {"uri": uri}}],
                "results": results,
            }
        ],
    }

    return json.dumps(sarif_doc, indent=indent)
