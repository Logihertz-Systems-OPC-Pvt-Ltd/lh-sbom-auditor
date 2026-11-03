# Security Policy

## Supported Versions

Logihertz Systems actively maintains and releases security patches for the following versions of `lh-sbom-auditor`:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

---

## Reporting a Vulnerability

The Logihertz Systems engineering team takes supply chain and software security seriously. If you discover a security vulnerability within `lh-sbom-auditor`, please report it responsibly rather than opening a public GitHub issue.

### Reporting Procedure

1. **Email Contact**: Send an email describing the vulnerability to **`security@logihertz.com`**.
2. **Details to Include**:
   - Component / module affected (e.g. `parsers`, `auditor`, `sbom`, `cli`).
   - Description of the potential impact and attack vector.
   - Minimal reproducible proof-of-concept (PoC) manifest or command.
   - Proposed remediation or patch if available.
3. **Response Timeline**:
   - **Acknowledgment**: Within 24-48 business hours.
   - **Triage & Assessment**: Within 5 business days.
   - **Patch Release & Advisory**: Within 14-30 business days depending on severity.

### Safe Harbor

Logihertz Systems will not pursue civil or criminal action against security researchers who:
- Perform vulnerability research without compromising user data or disrupting systems.
- Give us reasonable time to remediate the vulnerability before public disclosure.
- Act in good faith and avoid privacy violations or destruction of data.

---

## Supply Chain Integrity Commitments

- **Clean-Room Implementation**: All parsers, risk evaluators, and exporters are clean-room implementations with zero copied third-party code.
- **Dependency Hygiene**: Runtime dependencies are kept to a strictly verified minimal set (`typer`, `rich`).
- **Static Analysis & SAST**: All code changes undergo mandatory static analysis with `ruff`, AST security scanning with `bandit`, and 100% test verification.

