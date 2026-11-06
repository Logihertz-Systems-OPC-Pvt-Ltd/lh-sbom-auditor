# ==============================================================================
# Product:       lh-sbom-auditor (lh-sbom)
# Module:        tests.test_cli
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for lh-sbom CLI commands and exporters."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from lh_sbom_auditor.cli import app

runner = CliRunner()


def test_cli_version() -> None:
    """Test lh-sbom --version flag."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "lh-sbom-auditor version 0.1.0" in result.output


def test_cli_generate_cyclonedx(sample_uv_lock_path: Path) -> None:
    """Test lh-sbom generate <path> --format cyclonedx."""
    result = runner.invoke(app, ["generate", str(sample_uv_lock_path), "--format", "cyclonedx"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.5"


def test_cli_generate_json(sample_uv_lock_path: Path) -> None:
    """Test lh-sbom generate <path> --format json."""
    result = runner.invoke(app, ["generate", str(sample_uv_lock_path), "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["scanner"]["name"] == "lh-sbom-auditor"
    assert "packages" in data


def test_cli_generate_sarif(sample_uv_lock_path: Path) -> None:
    """Test lh-sbom generate <path> --format sarif."""
    result = runner.invoke(app, ["generate", str(sample_uv_lock_path), "--format", "sarif"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) > 0


def test_cli_generate_output_file(sample_uv_lock_path: Path, tmp_path: Path) -> None:
    """Test lh-sbom generate --output <file>."""
    out_file = tmp_path / "sbom.json"
    result = runner.invoke(
        app,
        ["generate", str(sample_uv_lock_path), "--format", "cyclonedx", "--output", str(out_file)],
    )
    assert result.exit_code == 0
    assert out_file.is_file()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["bomFormat"] == "CycloneDX"


def test_cli_audit_table(sample_uv_lock_path: Path) -> None:
    """Test lh-sbom audit <path> --format table."""
    result = runner.invoke(app, ["audit", str(sample_uv_lock_path), "--format", "table"])
    # uv.lock is clean (all versions pinned, licenses compliant/known)
    assert result.exit_code == 0
    assert "Logihertz Systems" in result.output
    assert "PASSED" in result.output


def test_cli_audit_json(sample_uv_lock_path: Path) -> None:
    """Test lh-sbom audit <path> --format json."""
    result = runner.invoke(app, ["audit", str(sample_uv_lock_path), "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "summary" in data
    assert data["summary"]["passed"] is True


def test_cli_audit_sarif(sample_requirements_path: Path) -> None:
    """Test lh-sbom audit with violations outputting SARIF."""
    result = runner.invoke(app, ["audit", str(sample_requirements_path), "--format", "sarif"])
    # requirements.txt has unpinned dependencies & typosquatting -> exit code 1
    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["version"] == "2.1.0"
    results = data["runs"][0]["results"]
    assert len(results) > 0
    rule_ids = {r["ruleId"] for r in results}
    assert "LH-RULE-001" in rule_ids  # unpinned


def test_cli_audit_output_file(sample_requirements_path: Path, tmp_path: Path) -> None:
    """Test lh-sbom audit --output <file>."""
    out_file = tmp_path / "audit_report.json"
    result = runner.invoke(
        app,
        ["audit", str(sample_requirements_path), "--format", "json", "--output", str(out_file)],
    )
    assert result.exit_code == 1  # has violations
    assert out_file.is_file()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["summary"]["passed"] is False


def test_cli_audit_custom_policy(sample_requirements_path: Path, sample_policy_path: Path) -> None:
    """Test lh-sbom audit --policy <policy.yaml>."""
    result = runner.invoke(
        app,
        [
            "audit",
            str(sample_requirements_path),
            "--policy",
            str(sample_policy_path),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["policy"]["version"] == "1.0"


def test_cli_invalid_path(tmp_path: Path) -> None:
    """Test error handling for non-existent path."""
    result = runner.invoke(app, ["generate", str(tmp_path / "missing.lock")])
    assert result.exit_code != 0
