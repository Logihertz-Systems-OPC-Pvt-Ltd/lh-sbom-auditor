# Security Rules Reference: lh-sbom-auditor

An enterprise software bill of materials (sbom) & supply-chain auditor developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-sbom-auditor`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `LH-RULE-001` | `HIGH` | Supply Chain | Unpinned Package Version in Dependency Manifest |
| `LH-RULE-002` | `HIGH` | License Compliance | Non-Compliant or Prohibited Open-Source License |
| `LH-RULE-003` | `CRITICAL` | Integrity | Missing Cryptographic Package Integrity Hash |
| `LH-RULE-004` | `CRITICAL` | Typosquatting | Package Name Typosquatting Vector Detected |
| `LH-RULE-005` | `HIGH` | Vulnerability | Known Vulnerable Package Version in SBOM |
| `LH-RULE-006` | `MEDIUM` | Maintenance | Deprecated or Unmaintained Package Dependency |
| `LH-RULE-007` | `HIGH` | Graph Hygiene | Circular Dependency Graph Topology Detected |
| `LH-RULE-008` | `MEDIUM` | License Compliance | Inconsistent License Declaration Across Dependency Tree |
| `LH-RULE-009` | `LOW` | Governance | Missing Supplier or Package Origin Metadata in SBOM |
| `LH-RULE-010` | `LOW` | SBOM Hygiene | CycloneDX 1.5 JSON Schema Validation Warning |

---

## Granular Rule Specifications

### `LH-RULE-001`: Unpinned Package Version in Dependency Manifest

- **Severity**: `HIGH`
- **Category**: `Supply Chain`
- **Description**: Package version declared with floating constraint or unpinned specification.
- **Remediation**: Pin exact dependency version in lockfile and manifest.

---

### `LH-RULE-002`: Non-Compliant or Prohibited Open-Source License

- **Severity**: `HIGH`
- **Category**: `License Compliance`
- **Description**: Dependency licensed under prohibited or viral copyleft license (e.g. GPL-3.0 in proprietary app).
- **Remediation**: Replace dependency with permissively licensed alternative (MIT, Apache-2.0, BSD).

---

### `LH-RULE-003`: Missing Cryptographic Package Integrity Hash

- **Severity**: `CRITICAL`
- **Category**: `Integrity`
- **Description**: CycloneDX SBOM component lacks cryptographic SHA-256 integrity digest.
- **Remediation**: Rebuild SBOM with lockfiles that record cryptographic package checksums.

---

### `LH-RULE-004`: Package Name Typosquatting Vector Detected

- **Severity**: `CRITICAL`
- **Category**: `Typosquatting`
- **Description**: Package name is dangerously similar (Levenshtein distance <= 2) to popular package.
- **Remediation**: Verify package provenance on official package registry and replace suspicious package.

---

### `LH-RULE-005`: Known Vulnerable Package Version in SBOM

- **Severity**: `HIGH`
- **Category**: `Vulnerability`
- **Description**: Package version matches active vulnerability entry in security advisory database.
- **Remediation**: Upgrade dependency to patched release identified in vulnerability advisory.

---

### `LH-RULE-006`: Deprecated or Unmaintained Package Dependency

- **Severity**: `MEDIUM`
- **Category**: `Maintenance`
- **Description**: Dependency marked deprecated by upstream maintainers or inactive for > 2 years.
- **Remediation**: Migrate codebase to modern maintained alternative package.

---

### `LH-RULE-007`: Circular Dependency Graph Topology Detected

- **Severity**: `HIGH`
- **Category**: `Graph Hygiene`
- **Description**: Circular dependency detected between package components.
- **Remediation**: Restructure modules to decouple circular dependency chain.

---

### `LH-RULE-008`: Inconsistent License Declaration Across Dependency Tree

- **Severity**: `MEDIUM`
- **Category**: `License Compliance`
- **Description**: Dependency declares conflicting license terms in package metadata and license file.
- **Remediation**: Verify actual license terms with upstream repository and document legal clearance.

---

### `LH-RULE-009`: Missing Supplier or Package Origin Metadata in SBOM

- **Severity**: `LOW`
- **Category**: `Governance`
- **Description**: Component in CycloneDX SBOM omits author, supplier, or upstream repo URL.
- **Remediation**: Populate package origin metadata in manifest before generating SBOM.

---

### `LH-RULE-010`: CycloneDX 1.5 JSON Schema Validation Warning

- **Severity**: `LOW`
- **Category**: `SBOM Hygiene`
- **Description**: Generated SBOM document contains minor schema validation warnings.
- **Remediation**: Ensure all required CycloneDX 1.5 JSON schema fields are populated during generation.

---
