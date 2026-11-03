# lh-sbom-auditor

[![CI](https://github.com/logihertz/lh-sbom-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/logihertz/lh-sbom-auditor/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CycloneDX](https://img.shields.io/badge/CycloneDX-v1.5-brightgreen)](https://cyclonedx.org/)
[![SARIF](https://img.shields.io/badge/SARIF-v2.1.0-orange)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

A clean-room supply chain security CLI by **Logihertz Systems OPC Pvt Ltd** that parses package lockfiles, generates standard **CycloneDX 1.5 JSON Software Bills of Materials (SBOMs)**, and audits dependencies against known supply-chain risk rules (unpinned versions, restrictive/copyleft licenses, and typosquatting vectors).

---

## Features

- **Multi-Ecosystem Lockfile Parsing**:
  - Python `uv.lock` (TOML format with virtual workspace roots, sdist/wheel SHA-256 hashes)
  - Python `requirements.txt` (PEP 508 specifiers, hashes, editable flags, and line continuations)
  - Node.js `package-lock.json` (npm v1, v2, and v3 lockfile formats, scoped packages, integrity hashes)
- **CycloneDX 1.5 JSON SBOM Generation**:
  - Full compliance with the official CycloneDX v1.5 JSON specification
  - Complete component hierarchy with package URLs (`purl`), checksums, licenses, direct/transitive scopes, and dependency graph relationships
- **Automated Supply-Chain Risk Auditor**:
  - **Unpinned Dependencies (`LH-RULE-001`)**: Identifies packages without strict pinning (`==`) or using floating/range specifiers (`*`, `latest`, `>=`, `~=`)
  - **License Compliance (`LH-RULE-002`, `LH-RULE-003`)**: Flags forbidden copyleft licenses (GPL, AGPL, SSPL) or undeclared/unknown licenses based on customizable policy
  - **Typosquatting Risk Vectors (`LH-RULE-004`)**: Detects impersonation attacks against popular open-source packages using:
    - Damerau-Levenshtein edit distance & character transposition
    - Separator confusion (`-` vs `_` mismatch)
    - Visual homoglyphs / confusables (`0`/`o`, `1`/`l`, `rn`/`m`, `vv`/`w`)
    - Affix wrapper impersonation (`pkg-python`, `node-pkg`, `official-pkg`)
- **Flexible Exporters**:
  - **Rich Terminal Tables**: Interactive, colored console tables with severity metrics
  - **Structured JSON**: Machine-readable scan results and normalized graph schemas
  - **OASIS SARIF v2.1.0**: Native integration with GitHub Advanced Security code scanning, GitLab SAST, and CI/CD pipelines
- **Clean-Room Engineering**:
  - Zero copied third-party code
  - Strict Python 3.11+ type annotations
  - Comprehensive docstrings across all modules

---

## Installation

Install dependencies using [`uv`](https://astral.sh/uv):

```bash
# Clone the repository
git clone https://github.com/logihertz/lh-sbom-auditor.git
cd lh-sbom-auditor

# Create a virtual environment and install with dev dependencies
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

Or install the package directly:

```bash
uv pip install .
```

Verify installation:

```bash
lh-sbom --version
```

---

## Usage

The CLI entry point is `lh-sbom`. It provides two primary subcommands: `generate` and `audit`.

### 1. Generate SBOM (`lh-sbom generate`)

Generate CycloneDX 1.5 JSON SBOMs or inventory representations from lockfiles or directories.

```bash
# Generate CycloneDX 1.5 JSON SBOM to stdout
lh-sbom generate ./uv.lock

# Generate CycloneDX SBOM and save to file
lh-sbom generate ./uv.lock --format cyclonedx --output sbom.json

# Generate normalized graph JSON
lh-sbom generate ./package-lock.json --format json --output graph.json

# Generate OASIS SARIF v2.1.0 inventory report
lh-sbom generate ./requirements.txt --format sarif --output inventory.sarif
```

#### CLI Options for `generate`:
- `path` (argument): Path to lockfile (`uv.lock`, `requirements.txt`, `package-lock.json`) or a directory containing a lockfile.
- `--format`, `-f`: Output format (`cyclonedx` [default], `json`, `sarif`).
- `--output`, `-o`: Output destination file. If omitted, writes directly to stdout.

---

### 2. Audit Dependencies (`lh-sbom audit`)

Audit dependencies against supply chain risk rules with customizable organizational policies.

```bash
# Audit with terminal Rich table
lh-sbom audit ./requirements.txt

# Audit with custom security policy file
lh-sbom audit ./uv.lock --policy policy.yaml

# Export findings as structured JSON
lh-sbom audit ./package-lock.json --format json --output audit_report.json

# Export findings as OASIS SARIF v2.1.0 for GitHub Code Scanning
lh-sbom audit ./requirements.txt --format sarif --output results.sarif
```

#### CLI Options for `audit`:
- `path` (argument): Path to lockfile (`uv.lock`, `requirements.txt`, `package-lock.json`) or directory.
- `--policy`, `-p`: Path to custom policy file (`policy.yaml` or `policy.json`). If omitted, uses recommended default policy.
- `--format`, `-f`: Output format (`table` [default], `json`, `sarif`).
- `--output`, `-o`: File path to save the report to. If omitted, outputs to console.

#### Exit Codes:
- `0`: All dependencies pass security policy (clean or warnings only).
- `1`: Policy violations detected (Critical or High findings) or input error.

---

## Policy Configuration

You can provide a custom `policy.yaml` or `policy.json` to configure rules and thresholds:

```yaml
version: "1.0"
rules:
  unpinned_versions:
    enabled: true
    severity: high

  licenses:
    enabled: true
    allowed:
      - MIT
      - Apache-2.0
      - BSD-2-Clause
      - BSD-3-Clause
      - ISC
      - CC0-1.0
      - Unlicense
      - 0BSD
    denied:
      - GPL-2.0
      - GPL-3.0
      - AGPL-3.0
      - SSPL-1.0
    allow_unknown: false
    unknown_severity: medium
    denied_severity: critical

  typosquatting:
    enabled: true
    severity: high
    threshold: 1 # Maximum edit distance for short package names
    custom_targets:
      - internal-core-utils
      - proprietary-sdk
```

---

## Architecture Overview

```
src/lh_sbom_auditor/
├── __init__.py           # Package version and author metadata
├── cli.py                # Typer CLI application (generate and audit commands)
├── models.py             # Data models (Package, DependencyGraph, Finding, AuditReport)
├── parsers/              # Multi-ecosystem lockfile parsers
│   ├── base.py           # AbstractLockfileParser and auto-detection engine
│   ├── uv_lock.py        # Python uv.lock TOML parser
│   ├── requirements.py   # Python requirements.txt parser
│   └── package_lock.py   # Node.js package-lock.json (v1, v2, v3) parser
├── sbom/                 # SBOM generators
│   └── cyclonedx.py      # CycloneDX v1.5 JSON generator
├── auditor/              # Risk evaluation rules and policy engine
│   ├── engine.py         # Audit orchestrator
│   ├── policy.py         # Policy parser (zero-dependency YAML/JSON)
│   └── rules.py          # Unpinned, license compliance, and typosquatting rules
└── exporters/            # Reporting formats
    ├── table.py          # Rich terminal table renderer
    ├── json_exporter.py  # Structured JSON exporter
    └── sarif.py          # OASIS SARIF v2.1.0 exporter
```

---

## Development & Testing

Run all quality checks and tests locally:

```bash
# Linting with Ruff
ruff check src tests

# Formatting check
ruff format --check src tests

# AST Security scanning with Bandit
bandit -r src

# Run test suite with pytest & coverage
pytest tests/ --cov=src/lh_sbom_auditor --cov-report=term
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2026 Logihertz Systems OPC Pvt Ltd.
