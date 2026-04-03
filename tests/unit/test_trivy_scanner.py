"""Tests for Trivy scanner."""

import pytest
from pathlib import Path
from vuln_scanner.scanners.trivy import TrivyScanner


class TestTrivyScanner:
    """Tests for TrivyScanner class."""

    @pytest.fixture
    def scanner(self):
        """Create Trivy scanner instance."""
        return TrivyScanner()

    @pytest.fixture
    def fixtures_dir(self):
        """Get fixtures directory path."""
        return Path(__file__).parent.parent / "fixtures"

    def test_scanner_name(self, scanner):
        """Test scanner has correct name."""
        assert scanner.name == "trivy"

    def test_supports_trivy_json(self, scanner, fixtures_dir):
        """Test Trivy JSON format is supported."""
        trivy_path = fixtures_dir / "sample_trivy.json"
        assert scanner.supports(str(trivy_path))

    def test_not_support_other_formats(self, scanner, fixtures_dir):
        """Test unsupported formats return False."""
        assert not scanner.supports("requirements.txt")
        # CycloneDX is not Trivy format
        cyclonedx_path = fixtures_dir / "sample_sbom_cyclonedx.json"
        assert not scanner.supports(str(cyclonedx_path))

    def test_scan_trivy_json(self, scanner, fixtures_dir):
        """Test scanning Trivy JSON output."""
        trivy_path = fixtures_dir / "sample_trivy.json"
        packages = scanner.scan(str(trivy_path))

        assert len(packages) >= 3
        assert any(p.name == "requests" for p in packages)
        assert any(p.name == "lodash" for p in packages)
        assert any(p.name == "semver" for p in packages)

    def test_package_versions(self, scanner, fixtures_dir):
        """Test package versions are correctly extracted."""
        trivy_path = fixtures_dir / "sample_trivy.json"
        packages = scanner.scan(str(trivy_path))

        requests_pkg = next(p for p in packages if p.name == "requests")
        assert requests_pkg.version == "2.28.0"

    def test_package_ecosystem(self, scanner, fixtures_dir):
        """Test package ecosystem is set."""
        trivy_path = fixtures_dir / "sample_trivy.json"
        packages = scanner.scan(str(trivy_path))

        for pkg in packages:
            # Ecosystem may be unknown if no Ecosystem field in fixture
            assert pkg.ecosystem in ["npm", "pypi", "gem", "pip", "unknown"]

    def test_vulnerabilities_extracted(self, scanner, fixtures_dir):
        """Test that Trivy vulnerabilities are not parsed as packages."""
        trivy_path = fixtures_dir / "sample_trivy.json"
        packages = scanner.scan(str(trivy_path))

        # Should get packages, not CVE IDs
        package_names = [p.name for p in packages]
        assert "CVE-2024-1234" not in package_names
        assert "CVE-2023-26115" not in package_names
