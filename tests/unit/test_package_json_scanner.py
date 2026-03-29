"""Unit tests for package.json scanner."""

import pytest
import tempfile
import json
from pathlib import Path
from vuln_scanner.scanners.package_json import PackageJsonScanner


def test_supports_package_json():
    scanner = PackageJsonScanner()
    assert scanner.supports("package.json")
    assert not scanner.supports("requirements.txt")


def test_parse_package_json():
    scanner = PackageJsonScanner()

    data = {
        "name": "my-app",
        "dependencies": {
            "express": "^4.18.0",
            "lodash": "~4.17.21"
        },
        "devDependencies": {
            "jest": "29.0.0"
        }
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        temp_path = f.name

    try:
        packages = scanner.scan(temp_path)
        assert len(packages) == 3

        names = {p.name for p in packages}
        assert "express" in names
        assert "lodash" in names
        assert "jest" in names

        express = next(p for p in packages if p.name == "express")
        assert express.version == "4.18.0"
        assert express.ecosystem == "npm"
    finally:
        Path(temp_path).unlink()
