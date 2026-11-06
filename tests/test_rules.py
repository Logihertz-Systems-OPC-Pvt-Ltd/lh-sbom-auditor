# ==============================================================================
# Product:       lh-sbom-auditor (lh-sbom)
# Module:        tests.test_rules
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for audit rules, risk evaluation, and typosquatting detection."""

from __future__ import annotations

from lh_sbom_auditor.auditor.engine import AuditEngine
from lh_sbom_auditor.auditor.policy import AuditPolicy
from lh_sbom_auditor.auditor.rules import (
    LicenseComplianceRule,
    TyposquattingRule,
    UnpinnedVersionRule,
    damerau_levenshtein_distance,
)
from lh_sbom_auditor.models import DependencyGraph, Ecosystem, Package, Severity


def test_damerau_levenshtein_distance() -> None:
    """Verify Damerau-Levenshtein distance calculation."""
    assert damerau_levenshtein_distance("requests", "requests") == 0
    # Transposition
    assert damerau_levenshtein_distance("reqeusts", "requests") == 1
    # Deletion
    assert damerau_levenshtein_distance("reqests", "requests") == 1
    # Insertion
    assert damerau_levenshtein_distance("requestss", "requests") == 1
    # Substitution
    assert damerau_levenshtein_distance("recuests", "requests") == 1


def test_unpinned_rule() -> None:
    """Test unpinned version detection."""
    rule = UnpinnedVersionRule()
    policy = AuditPolicy.default_policy()

    # Pinned package
    pkg_pinned = Package(
        name="requests", version="2.31.0", ecosystem=Ecosystem.PYPI, is_pinned=True
    )
    assert rule.evaluate(pkg_pinned, policy) == []

    # Unpinned package with >=
    pkg_unpinned1 = Package(
        name="urllib3", version=">=2.0.0", ecosystem=Ecosystem.PYPI, is_pinned=False
    )
    findings1 = rule.evaluate(pkg_unpinned1, policy)
    assert len(findings1) == 1
    assert findings1[0].rule_id == "LH-RULE-001"
    assert findings1[0].severity == Severity.HIGH

    # Unpinned package with "latest"
    pkg_unpinned2 = Package(
        name="random-lib", version="latest", ecosystem=Ecosystem.PYPI, is_pinned=False
    )
    findings2 = rule.evaluate(pkg_unpinned2, policy)
    assert len(findings2) == 1


def test_license_compliance_rule() -> None:
    """Test license compliance evaluation."""
    rule = LicenseComplianceRule()
    policy = AuditPolicy.default_policy()

    # Allowed license
    pkg_mit = Package(name="express", version="4.18.2", ecosystem=Ecosystem.NPM, license="MIT")
    assert rule.evaluate(pkg_mit, policy) == []

    # Explicitly denied license (GPL-3.0)
    pkg_gpl = Package(
        name="copyleft-tool", version="1.0.0", ecosystem=Ecosystem.PYPI, license="GPL-3.0"
    )
    findings_gpl = rule.evaluate(pkg_gpl, policy)
    assert len(findings_gpl) == 1
    assert findings_gpl[0].rule_id == "LH-RULE-002"
    assert findings_gpl[0].severity == Severity.CRITICAL

    # Unknown license with allow_unknown=False
    pkg_unknown = Package(
        name="mysterious-pkg", version="1.0.0", ecosystem=Ecosystem.PYPI, license=None
    )
    findings_unk = rule.evaluate(pkg_unknown, policy)
    assert len(findings_unk) == 1
    assert findings_unk[0].rule_id == "LH-RULE-003"
    assert findings_unk[0].severity == Severity.MEDIUM

    # Well-known fallback for requests (Apache-2.0 is allowed)
    pkg_requests = Package(
        name="requests", version="2.31.0", ecosystem=Ecosystem.PYPI, license=None
    )
    assert rule.evaluate(pkg_requests, policy) == []


def test_typosquatting_rule() -> None:
    """Test typosquatting detection across various attack vectors."""
    rule = TyposquattingRule()
    policy = AuditPolicy.default_policy()

    # Legitimate popular package MUST NOT be flagged
    real_requests = Package(
        name="requests", version="2.31.0", ecosystem=Ecosystem.PYPI, is_pinned=True
    )
    assert rule.evaluate(real_requests, policy) == []

    real_lodash = Package(name="lodash", version="4.17.21", ecosystem=Ecosystem.NPM, is_pinned=True)
    assert rule.evaluate(real_lodash, policy) == []

    # 1. Edit distance / transposition (reqeusts -> requests)
    typo_req = Package(name="reqeusts", version="1.0.0", ecosystem=Ecosystem.PYPI, is_pinned=True)
    findings1 = rule.evaluate(typo_req, policy)
    assert len(findings1) == 1
    assert findings1[0].rule_id == "LH-RULE-004"
    assert "requests" in findings1[0].description

    # 2. Transposition on npm (lodsh -> lodash)
    typo_lod = Package(name="lodsh", version="1.0.0", ecosystem=Ecosystem.NPM, is_pinned=True)
    findings2 = rule.evaluate(typo_lod, policy)
    assert len(findings2) == 1
    assert "lodash" in findings2[0].description

    # 3. Separator confusion (python_dateutil vs python-dateutil)
    policy.typosquatting.custom_targets.add("python-dateutil")
    typo_sep = Package(
        name="python_dateutil", version="1.0.0", ecosystem=Ecosystem.PYPI, is_pinned=True
    )
    findings3 = rule.evaluate(typo_sep, policy)
    assert len(findings3) == 1

    # 4. Affix squatting (requests-python)
    typo_affix = Package(
        name="requests-python", version="1.0.0", ecosystem=Ecosystem.PYPI, is_pinned=True
    )
    findings4 = rule.evaluate(typo_affix, policy)
    assert len(findings4) == 1


def test_audit_engine_integration() -> None:
    """Test running complete audit engine on a dependency graph."""
    graph = DependencyGraph(
        root_name="test-project",
        root_version="1.0.0",
        ecosystem=Ecosystem.PYPI,
        manifest_path="test.txt",
    )

    # Clean package
    graph.add_package(
        Package(name="requests", version="2.31.0", ecosystem=Ecosystem.PYPI, is_pinned=True)
    )

    # Unpinned package
    graph.add_package(
        Package(name="urllib3", version=">=2.0.0", ecosystem=Ecosystem.PYPI, is_pinned=False)
    )

    # Denied license package
    graph.add_package(
        Package(
            name="gpl-pkg",
            version="1.0.0",
            ecosystem=Ecosystem.PYPI,
            is_pinned=True,
            license="GPL-3.0",
        )
    )

    # Typosquatted package
    graph.add_package(
        Package(name="collorama", version="1.0.0", ecosystem=Ecosystem.PYPI, is_pinned=True)
    )

    engine = AuditEngine()
    report = engine.audit(graph)

    assert report.total_findings >= 3
    assert report.passed is False
    assert report.critical_count >= 1  # GPL-3.0 is critical
    assert report.high_count >= 2  # unpinned + typosquatting
