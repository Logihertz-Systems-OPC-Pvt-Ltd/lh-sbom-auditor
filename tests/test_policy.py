# ==============================================================================
# Product:       lh-sbom-auditor (lh-sbom)
# Module:        tests.test_policy
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for audit policy loading and YAML/JSON parsing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lh_sbom_auditor.auditor.policy import AuditPolicy, parse_yaml_or_json
from lh_sbom_auditor.models import Severity


def test_default_policy() -> None:
    """Test default policy configuration values."""
    policy = AuditPolicy.default_policy()
    assert policy.version == "1.0"
    assert policy.unpinned.enabled is True
    assert policy.unpinned.severity == Severity.HIGH

    assert policy.licenses.enabled is True
    assert "MIT" in policy.licenses.allowed
    assert "Apache-2.0" in policy.licenses.allowed
    assert "GPL-3.0" in policy.licenses.denied
    assert policy.licenses.allow_unknown is False
    assert policy.licenses.unknown_severity == Severity.MEDIUM
    assert policy.licenses.denied_severity == Severity.CRITICAL

    assert policy.typosquatting.enabled is True
    assert policy.typosquatting.severity == Severity.HIGH
    assert policy.typosquatting.threshold == 1


def test_load_yaml_policy(sample_policy_path: Path) -> None:
    """Test loading and parsing a YAML policy file."""
    policy = AuditPolicy.from_file(sample_policy_path)
    assert policy.version == "1.0"
    assert policy.unpinned.enabled is True
    assert "BSD-3-Clause" in policy.licenses.allowed
    assert "GPL-2.0" in policy.licenses.denied
    assert "custom-corp-lib" in policy.typosquatting.custom_targets


def test_load_json_policy(tmp_path: Path) -> None:
    """Test loading and parsing a JSON policy file."""
    json_path = tmp_path / "policy.json"
    data = {
        "version": "2.0",
        "rules": {
            "unpinned_versions": {"enabled": False, "severity": "low"},
            "licenses": {
                "enabled": True,
                "allowed": ["MIT"],
                "denied": ["AGPL-3.0"],
                "allow_unknown": True,
            },
            "typosquatting": {"enabled": True, "threshold": 2},
        },
    }
    json_path.write_text(json.dumps(data), encoding="utf-8")

    policy = AuditPolicy.from_file(json_path)
    assert policy.version == "2.0"
    assert policy.unpinned.enabled is False
    assert policy.unpinned.severity == Severity.LOW
    assert policy.licenses.allowed == {"MIT"}
    assert policy.licenses.allow_unknown is True
    assert policy.typosquatting.threshold == 2


def test_parse_yaml_or_json_edge_cases() -> None:
    """Test YAML parser on comments, quotes, inline lists, and primitives."""
    yaml_text = """
    # Header comment
    name: "test-policy"
    debug: false
    count: 42
    ratio: 3.14
    items:
      - one # inline comment
      - "two"
      - 'three'
    inline_arr: [a, b, c]
    """
    res = parse_yaml_or_json(yaml_text)
    assert res["name"] == "test-policy"
    assert res["debug"] is False
    assert res["count"] == 42
    assert res["ratio"] == 3.14
    assert res["items"] == ["one", "two", "three"]
    assert res["inline_arr"] == ["a", "b", "c"]


def test_missing_policy_file(tmp_path: Path) -> None:
    """Test exception when policy file does not exist."""
    with pytest.raises(FileNotFoundError):
        AuditPolicy.from_file(tmp_path / "non-existent-policy.yaml")
