# ==============================================================================
# Product:       lh-sbom-auditor (lh-sbom)
# Module:        src.lh_sbom_auditor.parsers.package_lock
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Parser for Node.js package-lock.json files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lh_sbom_auditor.models import Checksum, DependencyGraph, Ecosystem, Package
from lh_sbom_auditor.parsers.base import AbstractLockfileParser


class PackageLockParser(AbstractLockfileParser):
    """Parses npm package-lock.json files (v1, v2, and v3)."""

    @property
    def name(self) -> str:
        """Parser name."""
        return "package-lock.json"

    @property
    def ecosystem(self) -> Ecosystem:
        """Target ecosystem."""
        return Ecosystem.NPM

    def can_parse(self, file_path: Path) -> bool:
        """Determine whether file is a package-lock.json file."""
        if file_path.name == "package-lock.json":
            return True
        if file_path.suffix == ".json":
            try:
                data = json.loads(file_path.read_text(encoding="utf-8"))
                return (
                    isinstance(data, dict)
                    and "lockfileVersion" in data
                    and ("packages" in data or "dependencies" in data)
                )
            except (json.JSONDecodeError, OSError):
                return False
        return False

    def parse(self, file_path: Path) -> DependencyGraph:
        """Parse package-lock.json into a normalized DependencyGraph."""
        content = file_path.read_text(encoding="utf-8")
        data = json.loads(content)

        root_name = str(data.get("name") or file_path.parent.name or "npm-project")
        root_version = str(data.get("version") or "1.0.0")

        graph = DependencyGraph(
            root_name=root_name,
            root_version=root_version,
            ecosystem=Ecosystem.NPM,
            manifest_path=str(file_path),
        )

        packages_data = data.get("packages")
        if isinstance(packages_data, dict) and packages_data:
            self._parse_v2_or_v3(graph, packages_data)
        elif "dependencies" in data and isinstance(data["dependencies"], dict):
            self._parse_v1(graph, data["dependencies"])

        return graph

    def _parse_v2_or_v3(self, graph: DependencyGraph, packages: dict[str, dict[str, Any]]) -> None:
        """Parse npm v2 / v3 packages dictionary structure."""
        root_info = packages.get("", {})
        root_dependencies = root_info.get("dependencies", {})
        root_dev_dependencies = root_info.get("devDependencies", {})

        direct_names: set[str] = set()
        if isinstance(root_dependencies, dict):
            direct_names.update(root_dependencies.keys())
        if isinstance(root_dev_dependencies, dict):
            direct_names.update(root_dev_dependencies.keys())

        for pkg_path, info in packages.items():
            if not pkg_path or not isinstance(info, dict):
                # Skip the root "" package itself
                continue

            # Extract clean package name from node_modules path
            # E.g. node_modules/express -> express
            # E.g. node_modules/@babel/core -> @babel/core
            # E.g. node_modules/a/node_modules/b -> b
            clean_name = self._extract_package_name(pkg_path, info)
            if not clean_name:
                continue

            version = str(info.get("version", "0.0.0"))
            is_direct = clean_name in direct_names
            is_dev = bool(info.get("dev", False))

            # License field
            license_val = self._extract_license(info.get("license"))

            # Integrity / Checksums
            checksums = self._parse_integrity(info.get("integrity"))

            resolved = info.get("resolved")
            resolved_url = str(resolved) if resolved else None

            # Dependencies
            dep_names: list[str] = []
            deps = info.get("dependencies", {})
            if isinstance(deps, dict):
                for dep_name in deps.keys():
                    dep_names.append(dep_name)
                    graph.add_dependency(clean_name, dep_name)

            is_pinned = self._is_version_pinned(version)

            package = Package(
                name=clean_name,
                version=version,
                ecosystem=Ecosystem.NPM,
                direct=is_direct,
                is_dev=is_dev,
                license=license_val,
                checksums=checksums,
                resolved_url=resolved_url,
                dependencies=dep_names,
                is_pinned=is_pinned,
            )
            graph.add_package(package)

    def _parse_v1(self, graph: DependencyGraph, dependencies: dict[str, dict[str, Any]]) -> None:
        """Parse npm v1 dependencies dictionary structure."""

        def walk(
            name: str,
            info: dict[str, Any],
            parent_name: str | None = None,
            is_direct: bool = True,
        ) -> None:
            if not isinstance(info, dict):
                return

            version = str(info.get("version", "0.0.0"))
            is_dev = bool(info.get("dev", False))
            checksums = self._parse_integrity(info.get("integrity"))
            resolved = info.get("resolved")
            resolved_url = str(resolved) if resolved else None
            license_val = self._extract_license(info.get("license"))

            dep_names: list[str] = []
            requires = info.get("requires", {})
            if isinstance(requires, dict):
                for req_name in requires.keys():
                    dep_names.append(req_name)
                    graph.add_dependency(name, req_name)

            if parent_name:
                graph.add_dependency(parent_name, name)

            if name not in graph.packages:
                package = Package(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.NPM,
                    direct=is_direct,
                    is_dev=is_dev,
                    license=license_val,
                    checksums=checksums,
                    resolved_url=resolved_url,
                    dependencies=dep_names,
                    is_pinned=self._is_version_pinned(version),
                )
                graph.add_package(package)

            nested_deps = info.get("dependencies", {})
            if isinstance(nested_deps, dict):
                for child_name, child_info in nested_deps.items():
                    walk(child_name, child_info, parent_name=name, is_direct=False)

        for dep_name, dep_info in dependencies.items():
            walk(dep_name, dep_info, parent_name=None, is_direct=True)

    @staticmethod
    def _extract_package_name(pkg_path: str, info: dict[str, Any]) -> str:
        """Extract package name from node_modules path or package info."""
        if "name" in info and isinstance(info["name"], str) and info["name"]:
            return info["name"]

        # Path: e.g. "node_modules/@scope/pkg" or "node_modules/pkg"
        parts = pkg_path.split("node_modules/")
        last_segment = parts[-1].strip("/")
        return last_segment

    @staticmethod
    def _extract_license(raw_license: Any) -> str | None:
        """Normalize license field from string or dict."""
        if isinstance(raw_license, str) and raw_license.strip():
            return raw_license.strip()
        if isinstance(raw_license, dict):
            lic_type = raw_license.get("type")
            if isinstance(lic_type, str) and lic_type.strip():
                return lic_type.strip()
        return None

    @staticmethod
    def _parse_integrity(integrity_str: Any) -> list[Checksum]:
        """Convert npm integrity string (e.g. sha512-... or sha1-...) to Checksum."""
        if not isinstance(integrity_str, str) or "-" not in integrity_str:
            return []
        alg, val = integrity_str.split("-", 1)
        alg_formatted = alg.upper()
        if alg_formatted == "SHA512":
            alg_formatted = "SHA-512"
        elif alg_formatted == "SHA1":
            alg_formatted = "SHA-1"
        elif alg_formatted == "SHA256":
            alg_formatted = "SHA-256"
        elif alg_formatted == "SHA384":
            alg_formatted = "SHA-384"
        return [Checksum(algorithm=alg_formatted, value=val)]

    @staticmethod
    def _is_version_pinned(version: str) -> bool:
        """Determine if version represents a pinned version."""
        if not version or version in {"*", "latest"}:
            return False
        if any(version.startswith(prefix) for prefix in ["^", "~", ">", "<", ">=", "<="]):
            return False
        return True
