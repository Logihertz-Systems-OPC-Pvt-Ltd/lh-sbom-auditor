# ==============================================================================
# Product:       lh-sbom-auditor (lh-sbom)
# Module:        src.lh_sbom_auditor.auditor.rules
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Security and compliance audit rules for dependency supply chain analysis."""

from __future__ import annotations

from abc import ABC, abstractmethod

from lh_sbom_auditor.auditor.policy import AuditPolicy
from lh_sbom_auditor.models import Ecosystem, Finding, Package

# Curated knowledge base of known licenses for popular packages when not declared in lockfiles
_WELL_KNOWN_LICENSES: dict[str, str] = {
    # PyPI
    "requests": "Apache-2.0",
    "urllib3": "MIT",
    "fastapi": "MIT",
    "flask": "BSD-3-Clause",
    "django": "BSD-3-Clause",
    "click": "BSD-3-Clause",
    "typer": "MIT",
    "rich": "MIT",
    "pydantic": "MIT",
    "pytest": "MIT",
    "boto3": "Apache-2.0",
    "botocore": "Apache-2.0",
    "cryptography": "Apache-2.0",
    "jinja2": "BSD-3-Clause",
    "pyyaml": "MIT",
    "certifi": "MPL-2.0",
    "idna": "BSD-3-Clause",
    "charset-normalizer": "MIT",
    "numpy": "BSD-3-Clause",
    "pandas": "BSD-3-Clause",
    "scipy": "BSD-3-Clause",
    "hatchling": "MIT",
    "setuptools": "MIT",
    "wheel": "MIT",
    "pip": "MIT",
    # NPM
    "express": "MIT",
    "lodash": "MIT",
    "react": "MIT",
    "react-dom": "MIT",
    "axios": "MIT",
    "chalk": "MIT",
    "commander": "MIT",
    "debug": "MIT",
    "tslib": "0BSD",
    "moment": "MIT",
    "async": "MIT",
    "uuid": "MIT",
    "dotenv": "BSD-2-Clause",
    "webpack": "MIT",
    "next": "MIT",
    "vue": "MIT",
    "typescript": "Apache-2.0",
}

POPULAR_PYPI_PACKAGES = {
    "requests",
    "urllib3",
    "numpy",
    "pandas",
    "pip",
    "wheel",
    "setuptools",
    "cryptography",
    "pydantic",
    "pytest",
    "click",
    "typer",
    "rich",
    "boto3",
    "botocore",
    "certifi",
    "charset-normalizer",
    "idna",
    "six",
    "jinja2",
    "pyyaml",
    "typing-extensions",
    "scipy",
    "scikit-learn",
    "flask",
    "django",
    "fastapi",
    "aiohttp",
    "black",
    "ruff",
    "sqlalchemy",
    "celery",
    "redis",
    "pillow",
    "beautifulsoup4",
    "colorama",
    "tqdm",
    "virtualenv",
    "psutil",
    "attrs",
    "packaging",
}

POPULAR_NPM_PACKAGES = {
    "lodash",
    "express",
    "react",
    "react-dom",
    "axios",
    "chalk",
    "commander",
    "tslib",
    "debug",
    "moment",
    "async",
    "uuid",
    "dotenv",
    "webpack",
    "next",
    "vue",
    "typescript",
    "rxjs",
    "glob",
    "mocha",
    "jest",
    "core-js",
    "eslint",
    "prettier",
    "babel",
    "inquirer",
    "winston",
    "yargs",
    "cors",
    "body-parser",
    "cookie-parser",
    "mongoose",
    "semver",
    "minimist",
    "fs-extra",
    "nodemon",
}


def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate the Damerau-Levenshtein distance between two strings."""
    len1, len2 = len(s1), len(s2)
    d: dict[tuple[int, int], int] = {}

    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,  # deletion
                d[(i, j - 1)] + 1,  # insertion
                d[(i - 1, j - 1)] + cost,  # substitution
            )
            # Transposition of adjacent characters
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + 1)

    return d[(len1 - 1, len2 - 1)]


class AbstractAuditRule(ABC):
    """Abstract interface for a dependency audit rule."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique identifier for this rule."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable rule name."""

    @abstractmethod
    def evaluate(self, package: Package, policy: AuditPolicy) -> list[Finding]:
        """Evaluate package against this rule and return any findings."""


class UnpinnedVersionRule(AbstractAuditRule):
    """Detects dependencies with unpinned or range-based version constraints."""

    @property
    def rule_id(self) -> str:
        return "LH-RULE-001"

    @property
    def name(self) -> str:
        return "Unpinned Dependency Version"

    def evaluate(self, package: Package, policy: AuditPolicy) -> list[Finding]:
        if not policy.unpinned.enabled:
            return []

        version = package.version.strip()
        is_unpinned = (
            not package.is_pinned
            or not version
            or version in {"*", "latest", "direct"}
            or any(version.startswith(op) for op in [">", "<", ">=", "<=", "~=", "^", "!="])
        )

        if is_unpinned:
            finding = Finding(
                rule_id=self.rule_id,
                rule_name=self.name,
                package_name=package.name,
                package_version=package.version,
                severity=policy.unpinned.severity,
                title="Unpinned Dependency Version",
                description=(
                    f"Package '{package.name}' uses an unpinned version specifier "
                    f"'{package.version}'. Unpinned dependencies result in non-deterministic "
                    "builds and allow upstream compromises or breaking changes to be silently "
                    "introduced into your build."
                ),
                recommendation=(
                    f"Pin '{package.name}' to a concrete version (e.g. '==X.Y.Z') or lock its "
                    "exact hash and version in a deterministic lockfile."
                ),
                location=package.purl,
            )
            return [finding]

        return []


class LicenseComplianceRule(AbstractAuditRule):
    """Evaluates package licenses against organizational policy."""

    @property
    def rule_id(self) -> str:
        return "LH-RULE-002"

    @property
    def name(self) -> str:
        return "License Policy Compliance"

    def evaluate(self, package: Package, policy: AuditPolicy) -> list[Finding]:
        if not policy.licenses.enabled:
            return []

        lic = package.license
        if not lic:
            # Check knowledge base fallback
            lic = _WELL_KNOWN_LICENSES.get(package.name.lower())

        # Unknown or undeclared license
        if not lic or lic.upper() in {"UNKNOWN", "UNDEFINED", "NONE"}:
            if not policy.licenses.allow_unknown:
                return [
                    Finding(
                        rule_id="LH-RULE-003",
                        rule_name="Undeclared or Unknown License",
                        package_name=package.name,
                        package_version=package.version,
                        severity=policy.licenses.unknown_severity,
                        title="Unknown or Missing License",
                        description=(
                            f"Package '{package.name}@{package.version}' has no declared SPDX "
                            "license in its manifest. Distributing software with unknown "
                            "third-party licenses carries legal and intellectual property exposure."
                        ),
                        recommendation=(
                            f"Inspect the upstream repository for '{package.name}' and declare its "
                            "license or configure an exception in policy.yaml."
                        ),
                        location=package.purl,
                    )
                ]
            return []

        clean_lic = lic.strip()

        # Denied licenses (explicitly forbidden e.g. GPL-3.0, AGPL-3.0)
        is_denied = any(
            denied.lower() == clean_lic.lower() or denied.lower() in clean_lic.lower()
            for denied in policy.licenses.denied
        )
        if is_denied:
            return [
                Finding(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    package_name=package.name,
                    package_version=package.version,
                    severity=policy.licenses.denied_severity,
                    title="Forbidden License Detected",
                    description=(
                        f"Package '{package.name}@{package.version}' is licensed under "
                        f"'{clean_lic}', which is explicitly forbidden by policy."
                    ),
                    recommendation=(
                        f"Replace '{package.name}' with a permissively licensed alternative "
                        "or remove the dependency."
                    ),
                    location=package.purl,
                )
            ]

        # Allowed licenses check
        is_allowed = any(
            allowed.lower() == clean_lic.lower() for allowed in policy.licenses.allowed
        )
        if not is_allowed:
            return [
                Finding(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    package_name=package.name,
                    package_version=package.version,
                    severity=policy.licenses.denied_severity,
                    title="Disallowed License Detected",
                    description=(
                        f"Package '{package.name}@{package.version}' is licensed under "
                        f"'{clean_lic}', which is not included in the allowed licenses list."
                    ),
                    recommendation=(
                        f"Verify whether '{clean_lic}' meets compliance standards, and add it "
                        "to the policy allowed list or choose an alternative library."
                    ),
                    location=package.purl,
                )
            ]

        return []


class TyposquattingRule(AbstractAuditRule):
    """Detects potential typosquatting vectors against popular package names."""

    @property
    def rule_id(self) -> str:
        return "LH-RULE-004"

    @property
    def name(self) -> str:
        return "Typosquatting Risk Vector"

    def evaluate(self, package: Package, policy: AuditPolicy) -> list[Finding]:
        if not policy.typosquatting.enabled:
            return []

        pkg_name = package.name.strip().lower()

        # Build targets based on ecosystem and policy custom targets
        targets = set(policy.typosquatting.custom_targets)
        if package.ecosystem == Ecosystem.PYPI:
            targets.update(POPULAR_PYPI_PACKAGES)
        elif package.ecosystem == Ecosystem.NPM:
            targets.update(POPULAR_NPM_PACKAGES)

        # Normalize scoped npm names (e.g. @scope/lodash -> compare lodash)
        unscoped_name = pkg_name.split("/")[-1] if "/" in pkg_name else pkg_name

        for target in targets:
            target_clean = target.lower()

            # Exact match is legitimate package, NOT typosquatting
            if unscoped_name == target_clean:
                continue

            squat_type: str | None = None

            # 1. Separator confusion (e.g. python_dateutil vs python-dateutil)
            if unscoped_name.replace("-", "_") == target_clean.replace(
                "-", "_"
            ) or unscoped_name.replace(".", "-") == target_clean.replace(".", "-"):
                squat_type = "separator confusion (hyphen/underscore mismatch)"

            # 2. Visual / Confusable substitution
            elif self._is_visual_confusable(unscoped_name, target_clean):
                squat_type = "visual confusable / character homoglyph substitution"

            # 3. Affix impersonation (e.g. requests-python, node-lodash)
            elif self._is_affix_squat(unscoped_name, target_clean):
                squat_type = "affix impersonation (prefix or suffix wrapper)"

            # 4. Damerau-Levenshtein distance (insertions, deletions, transpositions)
            else:
                dist = damerau_levenshtein_distance(unscoped_name, target_clean)
                threshold = policy.typosquatting.threshold
                if dist <= threshold and len(unscoped_name) >= 3 and len(target_clean) >= 3:
                    squat_type = f"edit distance ({dist} character substitution)"
                elif (
                    dist <= 2
                    and len(target_clean) >= 7
                    and len(unscoped_name) >= 6
                    and abs(len(unscoped_name) - len(target_clean)) <= 1
                ):
                    squat_type = f"edit distance ({dist} character substitution)"

            if squat_type:
                return [
                    Finding(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        package_name=package.name,
                        package_version=package.version,
                        severity=policy.typosquatting.severity,
                        title="Potential Typosquatting Vector Detected",
                        description=(
                            f"Package '{package.name}' appears to be a typosquatting vector "
                            f"mimicking '{target}' via {squat_type}. Attackers deploy "
                            "typosquatted packages to compromise software supply chains."
                        ),
                        recommendation=(
                            f"Verify that you intentionally chose '{package.name}'. If your goal "
                            f"was to use the official library, replace it with '{target}'."
                        ),
                        location=package.purl,
                    )
                ]

        return []

    @staticmethod
    def _is_visual_confusable(s1: str, s2: str) -> bool:
        """Check for common visual confusables (e.g. 0/o, 1/l, rn/m, vv/w)."""
        if len(s1) < 3 or len(s2) < 3:
            return False

        def normalize_confusables(s: str) -> str:
            return (
                s.replace("0", "o")
                .replace("1", "l")
                .replace("rn", "m")
                .replace("vv", "w")
                .replace("q", "g")
            )

        norm1 = normalize_confusables(s1)
        norm2 = normalize_confusables(s2)
        return norm1 == norm2 and s1 != s2

    @staticmethod
    def _is_affix_squat(s1: str, s2: str) -> bool:
        """Detect wrappers like requests-python, node-lodash, etc."""
        affixes = [
            f"python-{s2}",
            f"{s2}-python",
            f"node-{s2}",
            f"{s2}-node",
            f"official-{s2}",
            f"{s2}-official",
            f"{s2}js",
            f"{s2}-js",
            f"{s2}-lib",
            f"lib-{s2}",
        ]
        return s1 in affixes
