# ==============================================================================
# Product:       lh-sbom-auditor (lh-sbom)
# Module:        src.lh_sbom_auditor.parsers.requirements
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Parser for pip requirements.txt manifest files."""

from __future__ import annotations

import re
from pathlib import Path

from lh_sbom_auditor.models import Checksum, DependencyGraph, Ecosystem, Package
from lh_sbom_auditor.parsers.base import AbstractLockfileParser

_HASH_REGEX = re.compile(r"--hash=([a-zA-Z0-9_-]+):([a-fA-F0-9]+)")
_REQ_SPLIT_REGEX = re.compile(r"([~!=<>]=?|===?|@)")


class RequirementsParser(AbstractLockfileParser):
    """Parses standard pip requirements.txt files."""

    @property
    def name(self) -> str:
        """Parser name."""
        return "requirements.txt"

    @property
    def ecosystem(self) -> Ecosystem:
        """Target ecosystem."""
        return Ecosystem.PYPI

    def can_parse(self, file_path: Path) -> bool:
        """Determine whether the file is a requirements.txt file."""
        fname = file_path.name.lower()
        if fname == "requirements.txt" or "requirements" in fname:
            return True
        if file_path.suffix == ".txt":
            try:
                first_lines = file_path.read_text(encoding="utf-8").splitlines()[:10]
                for line in first_lines:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if any(op in line for op in ["==", ">=", "<=", "~="]):
                            return True
            except OSError:
                return False
        return False

    def parse(self, file_path: Path) -> DependencyGraph:
        """Parse requirements.txt into a DependencyGraph."""
        content = file_path.read_text(encoding="utf-8")
        raw_lines = content.splitlines()

        # Handle line continuations (trailing backslash)
        lines: list[str] = []
        buf = ""
        for line in raw_lines:
            line_str = line.strip()
            if line_str.endswith("\\"):
                buf += line_str[:-1] + " "
            else:
                buf += line_str
                lines.append(buf.strip())
                buf = ""
        if buf:
            lines.append(buf.strip())

        root_name = file_path.parent.name or "python-project"
        graph = DependencyGraph(
            root_name=root_name,
            root_version="0.1.0",
            ecosystem=Ecosystem.PYPI,
            manifest_path=str(file_path),
        )

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Skip pip option flags (-r, -i, --index-url, -f, etc.)
            if line.startswith(("-r", "-i", "-f", "--index-url", "--extra-index-url")):
                continue

            # Handle editable flags: -e . or -e git+...
            if line.startswith(("-e ", "--editable ")):
                line = line.split(maxsplit=1)[1].strip()
                if line in {".", "./"}:
                    continue

            # Extract any hashes (--hash=sha256:...)
            checksums: list[Checksum] = []
            for match in _HASH_REGEX.finditer(line):
                alg, val = match.groups()
                checksums.append(Checksum(algorithm=alg.upper(), value=val))

            # Remove hashes and inline comments
            line = _HASH_REGEX.sub("", line)
            if " #" in line:
                line = line.split(" #", 1)[0]
            line = line.strip()
            if not line:
                continue

            # Strip environment markers (separated by ;)
            if ";" in line:
                line = line.split(";", 1)[0].strip()

            # Parse name and version specifier
            pkg_name, version, is_pinned, resolved_url = self._parse_requirement_line(line)
            if not pkg_name:
                continue

            package = Package(
                name=pkg_name,
                version=version,
                ecosystem=Ecosystem.PYPI,
                direct=True,
                is_dev=False,
                license=None,
                checksums=checksums,
                resolved_url=resolved_url,
                is_pinned=is_pinned,
            )
            graph.add_package(package)

        return graph

    def _parse_requirement_line(self, line: str) -> tuple[str, str, bool, str | None]:
        """Extract package name, version, pinned state, and optional URL."""
        line = line.strip()

        # Direct URL requirement: pkg @ https://...
        if "@" in line:
            parts = line.split("@", 1)
            raw_name = parts[0].strip()
            url = parts[1].strip()
            clean_name = self._clean_name(raw_name)
            # Direct URLs are unpinned unless explicitly tagged/hashed commit
            return clean_name, "direct", False, url

        # Search for version specifiers
        match = _REQ_SPLIT_REGEX.search(line)
        if not match:
            # Bare package name with no version specified (unpinned)
            clean_name = self._clean_name(line)
            return clean_name, "latest", False, None

        idx = match.start()
        raw_name = line[:idx].strip()
        specifier_part = line[idx:].strip()
        clean_name = self._clean_name(raw_name)

        # Evaluate exact pinning (== or === without wildcards)
        is_pinned = False
        version = specifier_part

        if specifier_part.startswith("==") and not specifier_part.startswith("==="):
            ver = specifier_part[2:].strip().split(",")[0].strip()
            if not ver.endswith(".*"):
                is_pinned = True
                version = ver
        elif specifier_part.startswith("==="):
            ver = specifier_part[3:].strip().split(",")[0].strip()
            is_pinned = True
            version = ver

        return clean_name, version, is_pinned, None

    @staticmethod
    def _clean_name(raw_name: str) -> str:
        """Strip extras e.g. requests[security] -> requests."""
        name = raw_name.strip()
        if "[" in name:
            name = name.split("[", 1)[0].strip()
        return name
