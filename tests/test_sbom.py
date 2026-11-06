# ==============================================================================
# Product:       lh-sbom-auditor (lh-sbom)
# Module:        tests.test_sbom
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for CycloneDX 1.5 JSON SBOM generation."""

from __future__ import annotations

import json
from pathlib import Path

from lh_sbom_auditor.parsers.base import detect_and_parse
from lh_sbom_auditor.sbom.cyclonedx import CycloneDXGenerator


def test_cyclonedx_1_5_schema_structure(sample_uv_lock_path: Path) -> None:
    """Verify CycloneDX 1.5 JSON output conforms to required specification structure."""
    graph = detect_and_parse(sample_uv_lock_path)
    generator = CycloneDXGenerator(graph)
    data = generator.generate_dict()

    # Top-level required keys
    assert data["$schema"] == "http://cyclonedx.org/schema/bom-1.5.schema.json"
    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.5"
    assert data["serialNumber"].startswith("urn:uuid:")
    assert data["version"] == 1

    # Metadata
    metadata = data["metadata"]
    assert "timestamp" in metadata
    assert len(metadata["tools"]) > 0
    assert metadata["tools"][0]["vendor"] == "Logihertz Systems OPC Pvt Ltd"
    assert metadata["tools"][0]["name"] == "lh-sbom-auditor"

    root_comp = metadata["component"]
    assert root_comp["type"] == "application"
    assert root_comp["name"] == "sample-app"
    assert root_comp["version"] == "0.1.0"
    assert "bom-ref" in root_comp

    # Components list
    components = data["components"]
    assert len(components) == graph.total_count

    comp_names = {c["name"] for c in components}
    assert "rich" in comp_names
    assert "typer" in comp_names

    # Check rich component details
    rich_comp = next(c for c in components if c["name"] == "rich")
    assert rich_comp["type"] == "library"
    assert rich_comp["version"] == "13.7.1"
    assert rich_comp["purl"] == "pkg:pypi/rich@13.7.1"
    assert rich_comp["scope"] == "required"
    assert "hashes" in rich_comp
    assert len(rich_comp["hashes"]) == 2
    assert rich_comp["hashes"][0]["alg"] == "SHA-256"

    # Dependencies section
    dependencies = data["dependencies"]
    assert len(dependencies) >= 1
    root_dep = next(d for d in dependencies if d["ref"] == root_comp["bom-ref"])
    assert len(root_dep["dependsOn"]) == len(graph.direct_packages)


def test_cyclonedx_json_output(sample_package_lock_v3_path: Path) -> None:
    """Test JSON string serialization of CycloneDX SBOM."""
    graph = detect_and_parse(sample_package_lock_v3_path)
    json_str = CycloneDXGenerator(graph).generate_json()

    # Valid JSON string
    parsed = json.loads(json_str)
    assert parsed["bomFormat"] == "CycloneDX"
    assert parsed["specVersion"] == "1.5"

    # Check npm purl
    express_comp = next(c for c in parsed["components"] if c["name"] == "express")
    assert express_comp["purl"] == "pkg:npm/express@4.18.2"
    assert express_comp["licenses"][0]["license"]["id"] == "MIT"

    # Check scoped npm purl
    types_node_comp = next(c for c in parsed["components"] if c["name"] == "@types/node")
    assert types_node_comp["purl"] == "pkg:npm/%40types/node@18.15.0"
