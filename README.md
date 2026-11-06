# lh-sbom-auditor

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-sbom-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-sbom-auditor/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise cyclonedx & spdx sbom compliance auditor developed by **Logihertz Systems (OPC) Private Limited**.

Validates CycloneDX (v1.4–v1.6) and SPDX (v2.3) Software Bills of Materials for NTIA minimum elements, cryptographic component hashes, copyleft/restrictive license violations (GPL/AGPL), PURL syntax, and orphan dependencies.

---

## Key Features

- **CycloneDX v1.5 JSON Generation**: Parses manifests and generates compliant CycloneDX Software Bill of Materials documents.
- **Supply-Chain Risk Auditing**: Evaluates dependency trees against security policies (unpinned versions, restrictive/copyleft licenses).
- **Typosquatting Detection**: Employs Levenshtein distance algorithms to detect malicious packages mimicking popular open-source libraries.
- **Cryptographic Hash Verification**: Validates package checksums (SHA-256) to ensure integrity across builds.
- **Multi-Format Reporting**: Outputs rich terminal tables, machine-readable JSON, and OASIS SARIF v2.1.0.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `LH-RULE-001` | `HIGH` | Unpinned package version or floating wildcard constraint in dependency manifest |
| `LH-RULE-002` | `HIGH` | Non-compliant or prohibited open-source license detected in dependency tree |
| `LH-RULE-003` | `CRITICAL` | Missing cryptographic package integrity hash in CycloneDX SBOM |
| `LH-RULE-004` | `CRITICAL` | Package name typosquatting vector matching popular registry library |
| `LH-RULE-005` | `HIGH` | Known vulnerable package version identified in software bill of materials |
| `LH-RULE-006` | `MEDIUM` | Deprecated or unmaintained package dependency declared in manifest |
| `LH-RULE-007` | `HIGH` | Circular or deep unpruned dependency graph topology detected |
| `LH-RULE-008` | `MEDIUM` | Inconsistent license declaration across transitive dependency tree |
| `LH-RULE-009` | `LOW` | Missing supplier or package origin metadata in SBOM inventory |
| `LH-RULE-010` | `LOW` | CycloneDX 1.5 JSON schema validation warning or missing metadata |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-sbom-auditor.git
cd lh-sbom-auditor

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-sbom` (also accessible via `lh-sbom`).

```bash
# Generate a CycloneDX 1.5 JSON SBOM from repository dependencies
lh-sbom generate . --format cyclonedx --output sbom.json

# Audit dependencies against a custom security policy file
lh-sbom audit . --policy policy.yaml

# Export findings to OASIS SARIF v2.1.0
lh-sbom audit . --format sarif --output sbom-audit.sarif

# Filter by minimum severity threshold
lh-sbom audit . --min-severity HIGH
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).
