# ==============================================================================
# Product:       lh-sbom-auditor (lh-sbom)
# Module:        src.lh_sbom_auditor.parsers.base
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Base interfaces and discovery logic for package lockfile parsers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from lh_sbom_auditor.models import DependencyGraph, Ecosystem


class AbstractLockfileParser(ABC):
    """Abstract base class for lockfile and manifest parsers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the parser."""

    @property
    @abstractmethod
    def ecosystem(self) -> Ecosystem:
        """Target ecosystem parsed by this parser."""

    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        """Determine whether the specified file can be parsed by this parser."""

    @abstractmethod
    def parse(self, file_path: Path) -> DependencyGraph:
        """Parse the lockfile and produce a normalized DependencyGraph."""


def detect_and_parse(target_path: Path | str) -> DependencyGraph:
    """Auto-detect lockfile type from path and parse into a DependencyGraph.

    Supports both file paths and directory paths.
    """
    path = Path(target_path).resolve()

    if not path.exists():
        raise FileNotFoundError(f"Target path does not exist: {path}")

    # Deferred imports to avoid circular dependencies
    from lh_sbom_auditor.parsers.package_lock import PackageLockParser
    from lh_sbom_auditor.parsers.requirements import RequirementsParser
    from lh_sbom_auditor.parsers.uv_lock import UvLockParser

    parsers: list[AbstractLockfileParser] = [
        UvLockParser(),
        PackageLockParser(),
        RequirementsParser(),
    ]

    if path.is_file():
        for parser in parsers:
            if parser.can_parse(path):
                return parser.parse(path)
        raise ValueError(
            f"Unsupported lockfile format for file: '{path.name}'. "
            "Supported formats: uv.lock, requirements.txt, package-lock.json."
        )

    if path.is_dir():
        # Search candidate files in priority order
        candidates = [
            ("uv.lock", UvLockParser()),
            ("package-lock.json", PackageLockParser()),
            ("requirements.txt", RequirementsParser()),
        ]
        for candidate_name, parser in candidates:
            candidate_path = path / candidate_name
            if candidate_path.is_file():
                return parser.parse(candidate_path)

        raise FileNotFoundError(
            f"No recognized lockfile found in directory: '{path}'. "
            "Expected one of: uv.lock, package-lock.json, requirements.txt."
        )

    raise ValueError(f"Path is neither a regular file nor a directory: {path}")
