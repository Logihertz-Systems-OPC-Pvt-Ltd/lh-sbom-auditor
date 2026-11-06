# ==============================================================================
# Product:       lh-sbom-auditor (lh-sbom)
# Module:        src.lh_sbom_auditor.auditor.policy
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Policy definitions and zero-dependency YAML/JSON policy loader."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from lh_sbom_auditor.models import Severity

DEFAULT_ALLOWED_LICENSES = {
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "CC0-1.0",
    "Unlicense",
    "0BSD",
    "Zlib",
}

DEFAULT_DENIED_LICENSES = {
    "GPL-2.0",
    "GPL-2.0-only",
    "GPL-3.0",
    "GPL-3.0-only",
    "AGPL-3.0",
    "AGPL-3.0-only",
    "SSPL-1.0",
}


@dataclass
class UnpinnedRuleConfig:
    """Configuration for unpinned versions risk rule."""

    enabled: bool = True
    severity: Severity = Severity.HIGH


@dataclass
class LicenseRuleConfig:
    """Configuration for license compliance risk rule."""

    enabled: bool = True
    allowed: set[str] = field(default_factory=lambda: set(DEFAULT_ALLOWED_LICENSES))
    denied: set[str] = field(default_factory=lambda: set(DEFAULT_DENIED_LICENSES))
    allow_unknown: bool = False
    unknown_severity: Severity = Severity.MEDIUM
    denied_severity: Severity = Severity.CRITICAL


@dataclass
class TyposquattingRuleConfig:
    """Configuration for typosquatting detection risk rule."""

    enabled: bool = True
    severity: Severity = Severity.HIGH
    threshold: int = 1
    custom_targets: set[str] = field(default_factory=set)


@dataclass
class AuditPolicy:
    """Comprehensive policy controlling dependency audit behavior."""

    version: str = "1.0"
    unpinned: UnpinnedRuleConfig = field(default_factory=UnpinnedRuleConfig)
    licenses: LicenseRuleConfig = field(default_factory=LicenseRuleConfig)
    typosquatting: TyposquattingRuleConfig = field(default_factory=TyposquattingRuleConfig)

    @classmethod
    def default_policy(cls) -> AuditPolicy:
        """Construct default recommended security policy."""
        return cls()

    @classmethod
    def from_file(cls, path: Path | str) -> AuditPolicy:
        """Load and parse policy from a YAML or JSON file."""
        file_path = Path(path).resolve()
        if not file_path.is_file():
            raise FileNotFoundError(f"Policy file not found: {file_path}")

        raw_text = file_path.read_text(encoding="utf-8")
        parsed_dict = parse_yaml_or_json(raw_text)
        return cls.from_dict(parsed_dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditPolicy:
        """Instantiate AuditPolicy from dictionary data."""
        if not isinstance(data, dict):
            return cls.default_policy()

        policy = cls()
        policy.version = str(data.get("version", "1.0"))

        rules = data.get("rules", data)
        if not isinstance(rules, dict):
            return policy

        # Unpinned versions rule
        unp_data = rules.get("unpinned_versions", rules.get("unpinned", {}))
        if isinstance(unp_data, dict):
            if "enabled" in unp_data:
                policy.unpinned.enabled = bool(unp_data["enabled"])
            if "severity" in unp_data:
                policy.unpinned.severity = _parse_severity(unp_data["severity"], Severity.HIGH)

        # Licenses rule
        lic_data = rules.get("licenses", {})
        if isinstance(lic_data, dict):
            if "enabled" in lic_data:
                policy.licenses.enabled = bool(lic_data["enabled"])
            if "allowed" in lic_data and isinstance(lic_data["allowed"], list):
                policy.licenses.allowed = {str(x).strip() for x in lic_data["allowed"]}
            if "denied" in lic_data and isinstance(lic_data["denied"], list):
                policy.licenses.denied = {str(x).strip() for x in lic_data["denied"]}
            if "allow_unknown" in lic_data:
                policy.licenses.allow_unknown = bool(lic_data["allow_unknown"])
            if "unknown_severity" in lic_data:
                policy.licenses.unknown_severity = _parse_severity(
                    lic_data["unknown_severity"], Severity.MEDIUM
                )
            if "denied_severity" in lic_data:
                policy.licenses.denied_severity = _parse_severity(
                    lic_data["denied_severity"], Severity.CRITICAL
                )

        # Typosquatting rule
        typo_data = rules.get("typosquatting", {})
        if isinstance(typo_data, dict):
            if "enabled" in typo_data:
                policy.typosquatting.enabled = bool(typo_data["enabled"])
            if "severity" in typo_data:
                policy.typosquatting.severity = _parse_severity(
                    typo_data["severity"], Severity.HIGH
                )
            if "threshold" in typo_data:
                raw_thresh = typo_data["threshold"]
                if isinstance(raw_thresh, int):
                    policy.typosquatting.threshold = raw_thresh
                elif isinstance(raw_thresh, str) and raw_thresh.isdigit():
                    policy.typosquatting.threshold = int(raw_thresh)
            if "custom_targets" in typo_data and isinstance(typo_data["custom_targets"], list):
                policy.typosquatting.custom_targets = {
                    str(x).strip().lower() for x in typo_data["custom_targets"]
                }

        return policy

    def to_dict(self) -> dict[str, Any]:
        """Serialize policy to dictionary representation."""
        return {
            "version": self.version,
            "rules": {
                "unpinned_versions": {
                    "enabled": self.unpinned.enabled,
                    "severity": self.unpinned.severity.value,
                },
                "licenses": {
                    "enabled": self.licenses.enabled,
                    "allowed": sorted(self.licenses.allowed),
                    "denied": sorted(self.licenses.denied),
                    "allow_unknown": self.licenses.allow_unknown,
                    "unknown_severity": self.licenses.unknown_severity.value,
                    "denied_severity": self.licenses.denied_severity.value,
                },
                "typosquatting": {
                    "enabled": self.typosquatting.enabled,
                    "severity": self.typosquatting.severity.value,
                    "threshold": self.typosquatting.threshold,
                    "custom_targets": sorted(self.typosquatting.custom_targets),
                },
            },
        }


def _parse_severity(val: Any, default: Severity) -> Severity:
    """Parse severity string to Severity enum."""
    if not isinstance(val, str):
        return default
    try:
        return Severity[val.strip().upper()]
    except KeyError:
        return default


def parse_yaml_or_json(content: str) -> dict[str, Any]:
    """Parse a YAML or JSON formatted text without external third-party dependencies."""
    stripped = content.strip()
    if not stripped:
        return {}

    # Attempt JSON parse first (JSON is valid YAML 1.2)
    if stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return _SimpleYamlParser(content).parse()

    return _SimpleYamlParser(content).parse()


class _SimpleYamlParser:
    """Lightweight clean-room YAML parser for policy configuration structures."""

    def __init__(self, text: str) -> None:
        self.raw_lines = text.splitlines()

    def parse(self) -> dict[str, Any]:
        """Parse structured YAML content."""
        clean_lines: list[tuple[int, str]] = []
        for line in self.raw_lines:
            # Strip inline comment
            code = self._strip_comment(line)
            if not code.strip():
                continue
            indent = len(code) - len(code.lstrip(" "))
            clean_lines.append((indent, code.strip()))

        if not clean_lines:
            return {}

        idx, result = self._parse_block(clean_lines, 0, clean_lines[0][0])
        return result if isinstance(result, dict) else {}

    def _strip_comment(self, line: str) -> str:
        """Remove comments from line while respecting quotes."""
        in_single = False
        in_double = False
        res: list[str] = []
        for ch in line:
            if ch == "'" and not in_double:
                in_single = not in_single
            elif ch == '"' and not in_single:
                in_double = not in_double
            elif ch == "#" and not in_single and not in_double:
                break
            res.append(ch)
        return "".join(res)

    def _parse_block(
        self, lines: list[tuple[int, str]], start_idx: int, current_indent: int
    ) -> tuple[int, Any]:
        """Parse a block of YAML lines at current indentation."""
        first_line = lines[start_idx][1]

        if first_line.startswith("- "):
            return self._parse_list(lines, start_idx, current_indent)
        return self._parse_dict(lines, start_idx, current_indent)

    def _parse_dict(
        self, lines: list[tuple[int, str]], start_idx: int, current_indent: int
    ) -> tuple[int, dict[str, Any]]:
        """Parse dictionary key-values."""
        result: dict[str, Any] = {}
        i = start_idx

        while i < len(lines):
            indent, text = lines[i]
            if indent < current_indent:
                break
            if indent > current_indent:
                # Malformed or unexpected deeper indentation, skip
                i += 1
                continue

            if text.startswith("- "):
                # Switch to list or list entry
                break

            if ":" not in text:
                i += 1
                continue

            key_part, val_part = text.split(":", 1)
            key = self._parse_scalar(key_part.strip())
            val_part = val_part.strip()

            if val_part:
                result[str(key)] = self._parse_scalar(val_part)
                i += 1
            else:
                # Value is on subsequent lines (nested block)
                if i + 1 < len(lines) and lines[i + 1][0] > indent:
                    next_indent = lines[i + 1][0]
                    next_i, nested_val = self._parse_block(lines, i + 1, next_indent)
                    result[str(key)] = nested_val
                    i = next_i
                else:
                    result[str(key)] = None
                    i += 1

        return i, result

    def _parse_list(
        self, lines: list[tuple[int, str]], start_idx: int, current_indent: int
    ) -> tuple[int, list[Any]]:
        """Parse bulleted list items."""
        result: list[Any] = []
        i = start_idx

        while i < len(lines):
            indent, text = lines[i]
            if indent < current_indent:
                break
            if indent > current_indent:
                i += 1
                continue

            if not text.startswith("- "):
                break

            item_text = text[2:].strip()
            if ":" in item_text and not item_text.startswith(("{", "[")):
                # List item is a dict
                k, v = item_text.split(":", 1)
                k_val = str(self._parse_scalar(k.strip()))
                v_part = v.strip()
                if v_part:
                    dict_item: dict[str, Any] = {k_val: self._parse_scalar(v_part)}
                    i += 1
                else:
                    if i + 1 < len(lines) and lines[i + 1][0] > indent:
                        next_i, sub_val = self._parse_block(lines, i + 1, lines[i + 1][0])
                        dict_item = {k_val: sub_val}
                        i = next_i
                    else:
                        dict_item = {k_val: None}
                        i += 1
                result.append(dict_item)
            elif item_text:
                result.append(self._parse_scalar(item_text))
                i += 1
            else:
                # Sub-block list item
                if i + 1 < len(lines) and lines[i + 1][0] > indent:
                    next_i, sub_val = self._parse_block(lines, i + 1, lines[i + 1][0])
                    result.append(sub_val)
                    i = next_i
                else:
                    result.append(None)
                    i += 1

        return i, result

    def _parse_scalar(self, val: str) -> Any:
        """Parse primitive scalar value."""
        val = val.strip()
        if not val:
            return ""

        # Quoted strings
        if (val.startswith('"') and val.endswith('"')) or (
            val.startswith("'") and val.endswith("'")
        ):
            return val[1:-1]

        # Booleans and Null
        low = val.lower()
        if low in {"true", "yes", "on"}:
            return True
        if low in {"false", "no", "off"}:
            return False
        if low in {"null", "none", "~"}:
            return None

        # Inline lists [a, b, c]
        if val.startswith("[") and val.endswith("]"):
            inner = val[1:-1].strip()
            if not inner:
                return []
            items = [self._parse_scalar(x.strip()) for x in inner.split(",") if x.strip()]
            return items

        # Integers and Floats
        if val.isdigit() or (val.startswith("-") and val[1:].isdigit()):
            return int(val)
        try:
            return float(val)
        except ValueError:
            return val

        return val
