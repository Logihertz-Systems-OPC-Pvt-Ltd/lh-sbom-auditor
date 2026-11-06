# ==============================================================================
# Product:       lh-sbom-auditor (lh-sbom)
# Module:        tests.test_parsers
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for lockfile and manifest parsers."""

from __future__ import annotations

from pathlib import Path

import pytest

from lh_sbom_auditor.models import Ecosystem
from lh_sbom_auditor.parsers.base import detect_and_parse
from lh_sbom_auditor.parsers.package_lock import PackageLockParser
from lh_sbom_auditor.parsers.requirements import RequirementsParser
from lh_sbom_auditor.parsers.uv_lock import UvLockParser


def test_uv_lock_parser(sample_uv_lock_path: Path) -> None:
    """Test parsing uv.lock file."""
    parser = UvLockParser()
    assert parser.can_parse(sample_uv_lock_path)
    assert parser.ecosystem == Ecosystem.PYPI

    graph = parser.parse(sample_uv_lock_path)
    assert graph.root_name == "sample-app"
    assert graph.root_version == "0.1.0"
    assert graph.ecosystem == Ecosystem.PYPI
    assert graph.total_count == 6  # rich, typer, requests, urllib3, click, pygments

    # Verify direct dependencies of root
    direct_names = {p.name for p in graph.direct_packages}
    assert "rich" in direct_names
    assert "typer" in direct_names
    assert "requests" in direct_names

    # Check checksums for rich
    rich_pkg = graph.get_package("rich")
    assert rich_pkg is not None
    assert rich_pkg.version == "13.7.1"
    assert rich_pkg.is_pinned is True
    assert len(rich_pkg.checksums) == 2
    assert rich_pkg.checksums[0].algorithm == "SHA-256"


def test_requirements_parser(sample_requirements_path: Path) -> None:
    """Test parsing pip requirements.txt file."""
    parser = RequirementsParser()
    assert parser.can_parse(sample_requirements_path)
    assert parser.ecosystem == Ecosystem.PYPI

    graph = parser.parse(sample_requirements_path)
    assert graph.ecosystem == Ecosystem.PYPI
    assert graph.total_count == 7

    # requests is pinned with ==
    req = graph.get_package("requests")
    assert req is not None
    assert req.version == "2.31.0"
    assert req.is_pinned is True
    assert len(req.checksums) == 1
    assert req.checksums[0].algorithm == "SHA-256"

    # urllib3 has >= so is unpinned
    u3 = graph.get_package("urllib3")
    assert u3 is not None
    assert u3.is_pinned is False

    # unpinned-lib has no version so is unpinned
    unp = graph.get_package("unpinned-lib")
    assert unp is not None
    assert unp.is_pinned is False
    assert unp.version == "latest"


def test_package_lock_parser_v3(sample_package_lock_v3_path: Path) -> None:
    """Test parsing npm package-lock.json v3."""
    parser = PackageLockParser()
    assert parser.can_parse(sample_package_lock_v3_path)
    assert parser.ecosystem == Ecosystem.NPM

    graph = parser.parse(sample_package_lock_v3_path)
    assert graph.root_name == "sample-node-app"
    assert graph.root_version == "1.0.0"
    assert graph.ecosystem == Ecosystem.NPM

    # Check direct package express
    exp = graph.get_package("express")
    assert exp is not None
    assert exp.version == "4.18.2"
    assert exp.direct is True
    assert exp.is_dev is False
    assert exp.license == "MIT"
    assert len(exp.checksums) == 1
    assert exp.checksums[0].algorithm == "SHA-512"

    # Check dev dependency jest
    jest = graph.get_package("jest")
    assert jest is not None
    assert jest.direct is True
    assert jest.is_dev is True

    # Check scoped package @types/node
    types_node = graph.get_package("@types/node")
    assert types_node is not None
    assert types_node.name == "@types/node"
    assert types_node.purl == "pkg:npm/%40types/node@18.15.0"


def test_package_lock_parser_v1(sample_package_lock_v1_path: Path) -> None:
    """Test parsing npm package-lock.json v1."""
    parser = PackageLockParser()
    assert parser.can_parse(sample_package_lock_v1_path)

    graph = parser.parse(sample_package_lock_v1_path)
    assert graph.root_name == "sample-v1-app"
    assert "express" in graph.packages
    assert "accepts" in graph.packages


def test_detect_and_parse(tmp_path: Path, sample_uv_lock_path: Path) -> None:
    """Test auto-detection on directory and file targets."""
    # Target is file
    g1 = detect_and_parse(sample_uv_lock_path)
    assert g1.ecosystem == Ecosystem.PYPI

    # Target is directory containing uv.lock
    g2 = detect_and_parse(tmp_path)
    assert g2.ecosystem == Ecosystem.PYPI

    # Non-existent path
    with pytest.raises(FileNotFoundError):
        detect_and_parse(tmp_path / "non-existent")

    # Unsupported file
    dummy = tmp_path / "dummy.unknown"
    dummy.write_text("random text", encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported lockfile format"):
        detect_and_parse(dummy)
