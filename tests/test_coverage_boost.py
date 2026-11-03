"""Additional unit tests boosting coverage across edge cases and CLI flows."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from lh_sbom_auditor.auditor.policy import AuditPolicy, parse_yaml_or_json
from lh_sbom_auditor.cli import app
from lh_sbom_auditor.exporters.table import render_graph_table
from lh_sbom_auditor.models import Checksum, DependencyGraph, Ecosystem, Package
from lh_sbom_auditor.parsers.base import detect_and_parse
from lh_sbom_auditor.parsers.package_lock import PackageLockParser
from lh_sbom_auditor.parsers.requirements import RequirementsParser
from lh_sbom_auditor.parsers.uv_lock import UvLockParser

runner = CliRunner()


def test_requirements_parser_advanced(tmp_path: Path) -> None:
    """Test line continuations, direct URLs, and editable options in requirements."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(
        "flask == \\\n"
        "  3.0.0\n"
        "-r other.txt\n"
        "--index-url https://pypi.org/simple\n"
        "-e .\n"
        "my-pkg @ https://github.com/user/my-pkg/archive/main.zip\n"
        "pkg-three === 1.2.3\n"
        "pkg-four >= 1.0, < 2.0\n"
        "pkg-five == 1.0.*\n",
        encoding="utf-8",
    )
    parser = RequirementsParser()
    graph = parser.parse(req_file)

    assert graph.total_count == 5
    assert graph.get_package("flask").version == "3.0.0"
    assert graph.get_package("my-pkg").version == "direct"
    assert graph.get_package("pkg-three").is_pinned is True
    assert graph.get_package("pkg-four").is_pinned is False
    assert graph.get_package("pkg-five").is_pinned is False


def test_uv_lock_parser_without_virtual_root(tmp_path: Path) -> None:
    """Test parsing uv.lock when virtual root is omitted."""
    lock_file = tmp_path / "uv.lock"
    lock_file.write_text(
        "version = 1\n"
        "[[package]]\n"
        'name = "root-dep"\n'
        'version = "1.0.0"\n'
        'dependencies = [ { name = "transitive-dep" } ]\n'
        "[[package]]\n"
        'name = "transitive-dep"\n'
        'version = "2.0.0"\n',
        encoding="utf-8",
    )
    parser = UvLockParser()
    graph = parser.parse(lock_file)

    assert graph.total_count == 2
    root_pkg = graph.get_package("root-dep")
    assert root_pkg is not None
    assert root_pkg.direct is True
    trans_pkg = graph.get_package("transitive-dep")
    assert trans_pkg is not None
    assert trans_pkg.direct is False


def test_package_lock_parser_checksum_variations() -> None:
    """Test package lock integrity parsing for various algorithms."""
    parser = PackageLockParser()
    assert parser._parse_integrity(None) == []
    assert parser._parse_integrity("invalid") == []

    c_sha1 = parser._parse_integrity("sha1-abc==")
    assert c_sha1[0].algorithm == "SHA-1"

    c_sha384 = parser._parse_integrity("sha384-xyz==")
    assert c_sha384[0].algorithm == "SHA-384"

    c_sha256 = parser._parse_integrity("sha256-123==")
    assert c_sha256[0].algorithm == "SHA-256"


def test_render_graph_table(tmp_path: Path) -> None:
    """Test rendering dependency inventory table."""
    graph = DependencyGraph(
        root_name="test-app",
        root_version="1.0.0",
        ecosystem=Ecosystem.PYPI,
        manifest_path=str(tmp_path / "uv.lock"),
    )
    graph.add_package(
        Package(
            name="rich",
            version="13.7.1",
            ecosystem=Ecosystem.PYPI,
            direct=True,
            is_pinned=True,
            checksums=[Checksum("SHA-256", "abc")],
        )
    )
    render_graph_table(graph)


def test_cli_audit_table_output_file(sample_uv_lock_path: Path, tmp_path: Path) -> None:
    """Test saving table audit report to a file."""
    out_file = tmp_path / "audit_table.txt"
    result = runner.invoke(
        app,
        ["audit", str(sample_uv_lock_path), "--format", "table", "--output", str(out_file)],
    )
    assert result.exit_code == 0
    assert out_file.is_file()
    assert "Logihertz Systems" in out_file.read_text(encoding="utf-8")


def test_yaml_nested_lists_and_dicts() -> None:
    """Test YAML parser parsing nested dictionaries and lists."""
    yaml_content = """
    rules:
      custom_list:
        - key1: val1
        - key2: val2
      empty_block:
    """
    data = parse_yaml_or_json(yaml_content)
    assert "rules" in data
    assert len(data["rules"]["custom_list"]) == 2
    assert data["rules"]["custom_list"][0]["key1"] == "val1"


def test_policy_from_dict_and_to_dict() -> None:
    """Test round-trip serialization of AuditPolicy."""
    policy = AuditPolicy.default_policy()
    d = policy.to_dict()
    reloaded = AuditPolicy.from_dict(d)
    assert reloaded.version == policy.version
    assert reloaded.licenses.allowed == policy.licenses.allowed
    assert reloaded.unpinned.enabled == policy.unpinned.enabled


def test_detect_and_parse_directory_priority(tmp_path: Path) -> None:
    """Test that uv.lock is prioritized over requirements.txt when both exist in a directory."""
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    (tmp_path / "uv.lock").write_text("version = 1\n", encoding="utf-8")

    graph = detect_and_parse(tmp_path)
    assert Path(graph.manifest_path).name == "uv.lock"
