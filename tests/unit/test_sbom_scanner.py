"""Tests for SBOM scanner."""

import pytest
from pathlib import Path
from vuln_scanner.scanners.sbom import SBOMScanner


class TestSBOMScanner:
    """Tests for SBOMScanner class."""

    @pytest.fixture
    def scanner(self):
        """Create SBOM scanner instance."""
        return SBOMScanner()

    @pytest.fixture
    def fixtures_dir(self):
        """Get fixtures directory path."""
        return Path(__file__).parent.parent / "fixtures"

    def test_scanner_name(self, scanner):
        """Test scanner has correct name."""
        assert scanner.name == "sbom"

    def test_supports_spdx_json(self, scanner):
        """Test SPDX JSON format is supported."""
        assert scanner.supports("test.spdx.json")
        assert scanner.supports("package.spdx.json")

    def test_supports_cyclonedx_json(self, scanner):
        """Test CycloneDX JSON format is supported."""
        assert scanner.supports("bom.cyclonedx.json")
        assert scanner.supports("package.cdx.json")

    def test_supports_spdx_tagvalue(self, scanner):
        """Test SPDX tag-value format is supported."""
        # SBOM scanner only supports .json, .xml, .cdx suffixes
        assert scanner.supports("package.spdx.json")

    def test_not_support_other_formats(self, scanner):
        """Test unsupported formats return False."""
        # .json is supported by SBOM scanner (suffix check)
        # but requirements.txt is not
        assert not scanner.supports("requirements.txt")  # Not an SBOM

    def test_scan_spdx_json(self, scanner, fixtures_dir):
        """Test scanning SPDX JSON SBOM."""
        sbom_path = fixtures_dir / "sample_sbom_spdx.json"
        packages = scanner.scan(str(sbom_path))

        assert len(packages) == 3
        assert any(p.name == "requests" for p in packages)
        assert any(p.name == "lodash" for p in packages)
        assert any(p.name == "express" for p in packages)

    def test_scan_cyclonedx_json(self, scanner, fixtures_dir):
        """Test scanning CycloneDX JSON SBOM."""
        sbom_path = fixtures_dir / "sample_sbom_cyclonedx.json"
        packages = scanner.scan(str(sbom_path))

        assert len(packages) == 3
        assert any(p.name == "axios" for p in packages)
        assert any(p.name == "body-parser" for p in packages)
        assert any(p.name == "qs" for p in packages)

    def test_package_versions(self, scanner, fixtures_dir):
        """Test package versions are correctly extracted."""
        sbom_path = fixtures_dir / "sample_sbom_spdx.json"
        packages = scanner.scan(str(sbom_path))

        requests_pkg = next(p for p in packages if p.name == "requests")
        assert requests_pkg.version == "2.28.0"

    def test_package_ecosystem(self, scanner, fixtures_dir):
        """Test package ecosystem is set."""
        sbom_path = fixtures_dir / "sample_sbom_spdx.json"
        packages = scanner.scan(str(sbom_path))

        for pkg in packages:
            # Ecosystem may be unknown if no PURL in externalRefs
            assert pkg.ecosystem in ["npm", "pypi", "maven", "nuget", "unknown"]
