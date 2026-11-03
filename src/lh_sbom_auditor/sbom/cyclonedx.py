"""CycloneDX v1.5 JSON SBOM generator."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from lh_sbom_auditor import __version__
from lh_sbom_auditor.models import DependencyGraph, Ecosystem

# Standard SPDX license identifiers commonly used
_KNOWN_SPDX = {
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "CC0-1.0",
    "Unlicense",
    "0BSD",
    "Zlib",
    "GPL-2.0",
    "GPL-2.0-only",
    "GPL-3.0",
    "GPL-3.0-only",
    "AGPL-3.0",
    "AGPL-3.0-only",
    "LGPL-2.1",
    "LGPL-3.0",
    "MPL-2.0",
    "EPL-2.0",
}


class CycloneDXGenerator:
    """Generates CycloneDX v1.5 JSON Software Bill of Materials (SBOM)."""

    def __init__(self, graph: DependencyGraph) -> None:
        self.graph = graph

    def generate_dict(self) -> dict[str, Any]:
        """Build dictionary structure complying with CycloneDX v1.5 JSON schema."""
        now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        serial = f"urn:uuid:{uuid.uuid4()}"

        root_purl = self._build_root_purl()
        root_bom_ref = root_purl

        components: list[dict[str, Any]] = []
        bom_ref_map: dict[str, str] = {}

        for pkg in self.graph.all_packages:
            bom_ref = pkg.purl or f"pkg:{pkg.ecosystem.value}/{pkg.name}@{pkg.version}"
            bom_ref_map[pkg.name] = bom_ref

            comp: dict[str, Any] = {
                "type": "library",
                "name": pkg.name,
                "version": pkg.version,
                "purl": pkg.purl,
                "bom-ref": bom_ref,
                "scope": "optional" if pkg.is_dev else "required",
            }

            # Licenses
            if pkg.license:
                lic_id = pkg.license.strip()
                if lic_id in _KNOWN_SPDX:
                    comp["licenses"] = [{"license": {"id": lic_id}}]
                else:
                    comp["licenses"] = [{"license": {"name": lic_id}}]

            # Hashes
            if pkg.checksums:
                comp["hashes"] = [
                    {"alg": cs.algorithm, "content": cs.value} for cs in pkg.checksums
                ]

            # Properties
            comp["properties"] = [
                {"name": "lh:direct", "value": "true" if pkg.direct else "false"},
                {"name": "lh:ecosystem", "value": pkg.ecosystem.value},
            ]

            components.append(comp)

        # Build dependencies section
        dependencies: list[dict[str, Any]] = []

        # Root dependency node
        root_depends_on: list[str] = [
            bom_ref_map[pkg.name] for pkg in self.graph.direct_packages if pkg.name in bom_ref_map
        ]
        dependencies.append(
            {
                "ref": root_bom_ref,
                "dependsOn": sorted(root_depends_on),
            }
        )

        # Edges between components
        for parent_name, child_names in self.graph.edges.items():
            if parent_name in bom_ref_map:
                parent_ref = bom_ref_map[parent_name]
                child_refs = [bom_ref_map[child] for child in child_names if child in bom_ref_map]
                if child_refs:
                    dependencies.append(
                        {
                            "ref": parent_ref,
                            "dependsOn": sorted(child_refs),
                        }
                    )

        sbom: dict[str, Any] = {
            "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": serial,
            "version": 1,
            "metadata": {
                "timestamp": now_iso,
                "tools": [
                    {
                        "vendor": "Logihertz Systems OPC Pvt Ltd",
                        "name": "lh-sbom-auditor",
                        "version": __version__,
                    }
                ],
                "component": {
                    "type": "application",
                    "name": self.graph.root_name,
                    "version": self.graph.root_version,
                    "bom-ref": root_bom_ref,
                    "purl": root_purl,
                },
            },
            "components": components,
            "dependencies": dependencies,
        }

        return sbom

    def generate_json(self, indent: int = 2) -> str:
        """Render CycloneDX SBOM as pretty-printed JSON string."""
        return json.dumps(self.generate_dict(), indent=indent)

    def _build_root_purl(self) -> str:
        """Build standard purl for root application."""
        clean_name = self.graph.root_name.strip().lower().replace("_", "-")
        ver = self.graph.root_version.strip() or "0.1.0"
        eco = "npm" if self.graph.ecosystem == Ecosystem.NPM else "generic"
        return f"pkg:{eco}/{clean_name}@{ver}"
