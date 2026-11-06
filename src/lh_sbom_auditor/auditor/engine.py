# ==============================================================================
# Product:       lh-sbom-auditor (lh-sbom)
# Module:        src.lh_sbom_auditor.auditor.engine
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Engine orchestrating dependency graph audits against configured rules."""

from __future__ import annotations

from lh_sbom_auditor.auditor.policy import AuditPolicy
from lh_sbom_auditor.auditor.rules import (
    AbstractAuditRule,
    LicenseComplianceRule,
    TyposquattingRule,
    UnpinnedVersionRule,
)
from lh_sbom_auditor.models import AuditReport, DependencyGraph, Finding


class AuditEngine:
    """Evaluates packages in a DependencyGraph against security and compliance rules."""

    def __init__(
        self,
        policy: AuditPolicy | None = None,
        custom_rules: list[AbstractAuditRule] | None = None,
    ) -> None:
        self.policy = policy or AuditPolicy.default_policy()
        if custom_rules is not None:
            self.rules = custom_rules
        else:
            self.rules = [
                UnpinnedVersionRule(),
                LicenseComplianceRule(),
                TyposquattingRule(),
            ]

    def audit(self, graph: DependencyGraph) -> AuditReport:
        """Execute audit across all packages in the dependency graph."""
        findings: list[Finding] = []

        for package in graph.all_packages:
            for rule in self.rules:
                rule_findings = rule.evaluate(package, self.policy)
                findings.extend(rule_findings)

        # Sort findings by severity (critical first) then package name
        findings.sort(key=lambda f: (-f.severity.rank, f.package_name, f.rule_id))

        return AuditReport(
            target_path=graph.manifest_path,
            ecosystem=graph.ecosystem,
            graph=graph,
            findings=findings,
            policy_applied=self.policy.to_dict(),
        )
