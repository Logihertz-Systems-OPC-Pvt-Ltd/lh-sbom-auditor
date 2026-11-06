# ==============================================================================
# Product:       lh-sbom-auditor (lh-sbom)
# Module:        src.lh_sbom_auditor.models
# Role:          Data Models & Rule Definitions
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Core domain models for lh-sbom-auditor."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from urllib.parse import quote


class Ecosystem(StrEnum):
    """Supported package management ecosystems."""

    PYPI = "pypi"
    NPM = "npm"


class Severity(StrEnum):
    # --- Severity Rank & Weighting Structure ---
    # Defines discrete security tiers for findings and threshold gating.
    # Higher ordinal rankings enforce stricter build break / fail-on gates.
    """Risk severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Numeric rank for sorting severity (higher is more critical)."""
        ranks = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return ranks.get(self, 0)


def normalize_algorithm(alg: str) -> str:
    """Normalize hash algorithm name to canonical CycloneDX format."""
    cleaned = alg.strip().upper().replace("_", "-")
    if cleaned == "SHA256":
        return "SHA-256"
    if cleaned == "SHA512":
        return "SHA-512"
    if cleaned == "SHA384":
        return "SHA-384"
    if cleaned == "SHA1":
        return "SHA-1"
    return cleaned


@dataclass(frozen=True)
class Checksum:
    """Cryptographic checksum for a package artifact."""

    algorithm: str
    value: str

    def __post_init__(self) -> None:
        """Ensure canonical algorithm name."""
        object.__setattr__(self, "algorithm", normalize_algorithm(self.algorithm))

    def to_dict(self) -> dict[str, str]:
        """Convert checksum to dictionary."""
        return {"algorithm": self.algorithm, "value": self.value}


@dataclass
class Package:
    """A resolved software package within a dependency manifest."""

    name: str
    version: str
    ecosystem: Ecosystem
    direct: bool = False
    is_dev: bool = False
    license: str | None = None
    checksums: list[Checksum] = field(default_factory=list)
    resolved_url: str | None = None
    dependencies: list[str] = field(default_factory=list)
    is_pinned: bool = True
    purl: str | None = None

    def __post_init__(self) -> None:
        """Calculate canonical Package URL (purl) if not explicitly set."""
        if self.purl is None:
            self.purl = self.build_purl()

    def build_purl(self) -> str:
        """Construct standard Package URL according to specification."""
        clean_name = self.name.strip()
        ver = quote(self.version.strip(), safe="") if self.version else "0.0.0"

        if self.ecosystem == Ecosystem.NPM:
            if clean_name.startswith("@") and "/" in clean_name:
                scope, subname = clean_name.split("/", 1)
                encoded_scope = quote(scope, safe="")
                encoded_name = quote(subname, safe="")
                return f"pkg:npm/{encoded_scope}/{encoded_name}@{ver}"
            encoded_name = quote(clean_name, safe="")
            return f"pkg:npm/{encoded_name}@{ver}"

        # Default: PyPI
        encoded_name = quote(clean_name.lower().replace("_", "-"), safe="")
        return f"pkg:pypi/{encoded_name}@{ver}"

    def to_dict(self) -> dict[str, Any]:
        """Convert package instance to serializable dictionary."""
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem.value,
            "purl": self.purl,
            "direct": self.direct,
            "is_dev": self.is_dev,
            "license": self.license,
            "is_pinned": self.is_pinned,
            "resolved_url": self.resolved_url,
            "checksums": [c.to_dict() for c in self.checksums],
            "dependencies": list(self.dependencies),
        }


@dataclass
class DependencyGraph:
    """Normalized dependency graph of software components."""

    root_name: str
    root_version: str
    ecosystem: Ecosystem
    manifest_path: str
    packages: dict[str, Package] = field(default_factory=dict)
    edges: dict[str, list[str]] = field(default_factory=dict)

    def add_package(self, package: Package) -> None:
        """Add or update a package in the dependency graph."""
        self.packages[package.name] = package

    def add_dependency(self, parent_name: str, child_name: str) -> None:
        """Add a dependency relationship edge between two packages."""
        if parent_name not in self.edges:
            self.edges[parent_name] = []
        if child_name not in self.edges[parent_name]:
            self.edges[parent_name].append(child_name)

    def get_package(self, name: str) -> Package | None:
        """Retrieve a package by its name."""
        return self.packages.get(name)

    @property
    def direct_packages(self) -> list[Package]:
        """Return list of all direct root dependencies."""
        return [p for p in self.packages.values() if p.direct]

    @property
    def all_packages(self) -> list[Package]:
        """Return list of all packages in the graph."""
        return list(self.packages.values())

    @property
    def total_count(self) -> int:
        """Return total number of unique dependencies."""
        return len(self.packages)

    def to_dict(self) -> dict[str, Any]:
        """Serialize dependency graph to a dictionary."""
        return {
            "root_name": self.root_name,
            "root_version": self.root_version,
            "ecosystem": self.ecosystem.value,
            "manifest_path": self.manifest_path,
            "total_packages": self.total_count,
            "packages": {k: v.to_dict() for k, v in self.packages.items()},
            "dependencies": dict(self.edges),
        }


@dataclass
class Finding:
    """Security or compliance finding detected by the auditor."""

    rule_id: str
    rule_name: str
    package_name: str
    package_version: str
    severity: Severity
    title: str
    description: str
    recommendation: str
    location: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize finding to dictionary format."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "package_name": self.package_name,
            "package_version": self.package_version,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "location": self.location,
        }


@dataclass
class AuditReport:
    """Overall audit report compiling findings across a dependency graph."""

    target_path: str
    ecosystem: Ecosystem
    graph: DependencyGraph
    findings: list[Finding] = field(default_factory=list)
    policy_applied: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def total_findings(self) -> int:
        """Total count of issues discovered."""
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        """Number of critical severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Number of high severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        """Number of medium severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        """Number of low severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        """Number of info severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def passed(self) -> bool:
        """Determine whether the audit passed policy (no Critical or High issues)."""
        return self.critical_count == 0 and self.high_count == 0

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary representation."""
        return {
            "target_path": self.target_path,
            "ecosystem": self.ecosystem.value,
            "timestamp": self.timestamp.isoformat(),
            "summary": {
                "total_packages": self.graph.total_count,
                "total_findings": self.total_findings,
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
                "passed": self.passed,
            },
            "policy": self.policy_applied,
            "findings": [f.to_dict() for f in self.findings],
        }
