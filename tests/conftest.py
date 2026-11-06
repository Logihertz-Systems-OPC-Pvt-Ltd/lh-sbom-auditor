# ==============================================================================
# Product:       lh-sbom-auditor (lh-sbom)
# Module:        tests.conftest
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Shared test fixtures and sample lockfile contents for lh-sbom-auditor tests."""

from __future__ import annotations

from pathlib import Path

import pytest

H1 = "1111111111111111111111111111111111111111111111111111111111111111"
H2 = "2222222222222222222222222222222222222222222222222222222222222222"

SAMPLE_UV_LOCK = f"""
version = 1
revision = 1
requires-python = ">=3.11"

[[package]]
name = "sample-app"
version = "0.1.0"
source = {{ virtual = "." }}
dependencies = [
    {{ name = "rich" }},
    {{ name = "typer" }},
    {{ name = "requests" }},
]

[[package]]
name = "rich"
version = "13.7.1"
source = {{ registry = "https://pypi.org/simple" }}
dependencies = [
    {{ name = "pygments" }},
]
sdist = {{ url = "https://pypi.org/rich.tar.gz", hash = "sha256:{H1}" }}
wheels = [
    {{ url = "https://pypi.org/rich.whl", hash = "sha256:{H2}" }},
]

[[package]]
name = "typer"
version = "0.12.0"
source = {{ registry = "https://pypi.org/simple" }}
dependencies = [
    {{ name = "click" }},
]

[[package]]
name = "requests"
version = "2.31.0"
source = {{ registry = "https://pypi.org/simple" }}
dependencies = [
    {{ name = "urllib3" }},
]

[[package]]
name = "urllib3"
version = "2.0.7"
source = {{ registry = "https://pypi.org/simple" }}

[[package]]
name = "click"
version = "8.1.7"
source = {{ registry = "https://pypi.org/simple" }}

[[package]]
name = "pygments"
version = "2.17.2"
source = {{ registry = "https://pypi.org/simple" }}
"""

SAMPLE_REQUIREMENTS_TXT = f"""
# Production dependencies
requests == 2.31.0 --hash=sha256:{H1}
urllib3 >= 2.0.0
flask == 3.0.0
unpinned-lib
typer ~= 0.12.0
gpl-tool == 1.0.0
reqeusts == 1.0.0 # Typosquatted requests
"""

SAMPLE_PACKAGE_LOCK_V3 = """{
  "name": "sample-node-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "sample-node-app",
      "version": "1.0.0",
      "dependencies": {
        "express": "^4.18.2",
        "lodash": "^4.17.21"
      },
      "devDependencies": {
        "jest": "^29.5.0"
      }
    },
    "node_modules/express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express.tgz",
      "integrity": "sha512-abc123==",
      "license": "MIT",
      "dependencies": {
        "accepts": "~1.3.8"
      }
    },
    "node_modules/accepts": {
      "version": "1.3.8",
      "resolved": "https://registry.npmjs.org/accepts.tgz",
      "integrity": "sha512-def456==",
      "license": "MIT"
    },
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash.tgz",
      "integrity": "sha512-ghi789==",
      "license": "MIT"
    },
    "node_modules/jest": {
      "version": "29.5.0",
      "resolved": "https://registry.npmjs.org/jest.tgz",
      "integrity": "sha512-jkl012==",
      "license": "MIT",
      "dev": true
    },
    "node_modules/@types/node": {
      "version": "18.15.0",
      "resolved": "https://registry.npmjs.org/node.tgz",
      "integrity": "sha512-z728362846==",
      "license": "MIT",
      "dev": true
    }
  }
}
"""

SAMPLE_PACKAGE_LOCK_V1 = """{
  "name": "sample-v1-app",
  "version": "1.0.0",
  "lockfileVersion": 1,
  "dependencies": {
    "express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express.tgz",
      "integrity": "sha512-abc123==",
      "dev": false,
      "requires": {
        "accepts": "1.3.8"
      },
      "dependencies": {
        "accepts": {
          "version": "1.3.8",
          "resolved": "https://registry.npmjs.org/accepts.tgz",
          "integrity": "sha512-def456=="
        }
      }
    }
  }
}
"""

SAMPLE_POLICY_YAML = """
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
      - BSD-3-Clause
    denied:
      - GPL-2.0
      - GPL-3.0
      - AGPL-3.0
    allow_unknown: false
    unknown_severity: medium
    denied_severity: critical
  typosquatting:
    enabled: true
    severity: high
    threshold: 1
    custom_targets:
      - custom-corp-lib
"""


@pytest.fixture
def sample_uv_lock_path(tmp_path: Path) -> Path:
    p = tmp_path / "uv.lock"
    p.write_text(SAMPLE_UV_LOCK, encoding="utf-8")
    return p


@pytest.fixture
def sample_requirements_path(tmp_path: Path) -> Path:
    p = tmp_path / "requirements.txt"
    p.write_text(SAMPLE_REQUIREMENTS_TXT, encoding="utf-8")
    return p


@pytest.fixture
def sample_package_lock_v3_path(tmp_path: Path) -> Path:
    p = tmp_path / "package-lock.json"
    p.write_text(SAMPLE_PACKAGE_LOCK_V3, encoding="utf-8")
    return p


@pytest.fixture
def sample_package_lock_v1_path(tmp_path: Path) -> Path:
    p = tmp_path / "package-lock.json"
    p.write_text(SAMPLE_PACKAGE_LOCK_V1, encoding="utf-8")
    return p


@pytest.fixture
def sample_policy_path(tmp_path: Path) -> Path:
    p = tmp_path / "policy.yaml"
    p.write_text(SAMPLE_POLICY_YAML, encoding="utf-8")
    return p
