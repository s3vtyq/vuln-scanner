"""Unit tests for requirements scanner."""

import pytest
import tempfile
from pathlib import Path
from vuln_scanner.scanners.requirements import RequirementsScanner


def test_supports_requirements_txt():
    scanner = RequirementsScanner()
    assert scanner.supports("requirements.txt")
    assert scanner.supports("requirements-dev.txt")
    assert not scanner.supports("package.json")


def test_parse_simple_requirement():
    scanner = RequirementsScanner()

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("requests==2.28.0\n")
        f.write("flask>=2.0.0\n")
        f.write("django==4.0.0\n")
        temp_path = f.name

    try:
        packages = scanner.scan(temp_path)
        assert len(packages) == 3

        assert packages[0].name == "requests"
        assert packages[0].version == "2.28.0"
        assert packages[0].ecosystem == "pypi"

        assert packages[1].name == "flask"
        # Version operator is stripped for consistency
        assert packages[1].version == "2.0.0"

    finally:
        Path(temp_path).unlink()


def test_skip_comments_and_options():
    scanner = RequirementsScanner()

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("# This is a comment\n")
        f.write("-r other-requirements.txt\n")
        f.write("--index-url https://pypi.org/simple\n")
        f.write("package==1.0.0\n")
        temp_path = f.name

    try:
        packages = scanner.scan(temp_path)
        assert len(packages) == 1
        assert packages[0].name == "package"
    finally:
        Path(temp_path).unlink()
