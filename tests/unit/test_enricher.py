"""Tests for CVE enricher."""

from datetime import datetime, timezone
import pytest
from unittest.mock import Mock, MagicMock, patch
from vuln_scanner.core.enricher import CVEEnricher
from vuln_scanner.nvd.models import VulnerabilityFinding, CVEData, CVEDescription, CVSSScore, CVEReference


class TestCVEEnricher:
    """Tests for CVEEnricher class."""

    @pytest.fixture
    def mock_nvd_client(self):
        """Create mock NVD client."""
        client = Mock()
        client.get_cve = Mock()
        return client

    @pytest.fixture
    def enricher(self, mock_nvd_client):
        """Create enricher with mock client."""
        return CVEEnricher(nvd_client=mock_nvd_client)

    @pytest.fixture
    def sample_finding(self):
        """Create sample vulnerability finding."""
        return VulnerabilityFinding(
            package_name="requests",
            installed_version="2.28.0",
            cve_id="CVE-2024-1234",
            severity=None,
            cvss_score=None,
        )

    @pytest.fixture
    def sample_cve_data(self):
        """Create sample CVE data."""
        return CVEData(
            id="CVE-2024-1234",
            source_identifier="nvd@nist.gov",
            published=datetime.now(timezone.utc),
            last_modified=datetime.now(timezone.utc),
            vuln_status="Analyzed",
            descriptions=[
                CVEDescription(lang="en", value="Test vulnerability description")
            ],
            descriptions_en="Test vulnerability description",
            metrics={
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": 7.5,
                            "baseSeverity": "HIGH",
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"
                        }
                    }
                ]
            },
            configurations=[],
            references=[
                CVEReference(url="https://nvd.nist.gov/vuln/detail/CVE-2024-1234", tags=["Source", "Patch"])
            ],
            weaknesses=[],
            publisher="NIST",
        )

    def test_enrich_with_cve_data(self, enricher, mock_nvd_client, sample_finding, sample_cve_data):
        """Test enriching a finding with CVE data."""
        mock_nvd_client.get_cve.return_value = sample_cve_data

        result = enricher.enrich(sample_finding)

        assert result.description == "Test vulnerability description"
        assert result.severity == "HIGH"
        assert result.cvss_score == 7.5
        assert result.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"
        assert len(result.references) > 0

    def test_enrich_preserves_existing_data(self, enricher, mock_nvd_client, sample_cve_data):
        """Test that existing data is not overwritten."""
        finding = VulnerabilityFinding(
            package_name="requests",
            installed_version="2.28.0",
            cve_id="CVE-2024-1234",
            description="Already have description",
            severity="CRITICAL",
            cvss_score=9.9,
        )

        mock_nvd_client.get_cve.return_value = sample_cve_data

        result = enricher.enrich(finding)

        assert result.description == "Already have description"
        assert result.severity == "CRITICAL"
        assert result.cvss_score == 9.9

    def test_enrich_no_cve_found(self, enricher, mock_nvd_client, sample_finding):
        """Test enrichment when no CVE data is found."""
        mock_nvd_client.get_cve.return_value = None

        result = enricher.enrich(sample_finding)

        assert result.package_name == "requests"
        assert result.description is None

    def test_enrich_batch(self, enricher, mock_nvd_client):
        """Test batch enrichment."""
        findings = [
            VulnerabilityFinding(package_name="pkg1", installed_version="1.0", cve_id="CVE-2024-1"),
            VulnerabilityFinding(package_name="pkg2", installed_version="2.0", cve_id="CVE-2024-2"),
        ]

        mock_nvd_client.get_cve.return_value = None

        results = enricher.enrich_batch(findings)

        assert len(results) == 2
        mock_nvd_client.get_cve.assert_called()

    def test_extract_fixed_version(self, enricher):
        """Test fixed version extraction from configurations."""
        from vuln_scanner.nvd.models import CVEConfiguration, CPEMatch

        cve_data = CVEData(
            id="CVE-2024-1234",
            source_identifier="nvd@nist.gov",
            published=datetime.now(timezone.utc),
            last_modified=datetime.now(timezone.utc),
            vuln_status="Analyzed",
            descriptions=[],
            configurations=[
                CVEConfiguration(
                    operator="AND",
                    vulnerable=True,
                    cpe_match=[
                        CPEMatch(
                            vulnerable=True,
                            criteria="cpe:2.3:a:requests:requests:*:*:*:*:*:*:*:*",
                            match_criteria_id="abc",
                            version_end_excluding="2.31.0"
                        )
                    ]
                )
            ],
            references=[],
            weaknesses=[],
            publisher="NIST",
        )

        result = enricher._extract_fixed_version(cve_data)

        assert result == "<2.31.0"

    def test_extract_fixed_version_including(self, enricher):
        """Test fixed version extraction with version_end_including."""
        from vuln_scanner.nvd.models import CVEConfiguration, CPEMatch

        cve_data = CVEData(
            id="CVE-2024-1234",
            source_identifier="nvd@nist.gov",
            published=datetime.now(timezone.utc),
            last_modified=datetime.now(timezone.utc),
            vuln_status="Analyzed",
            descriptions=[],
            configurations=[
                CVEConfiguration(
                    operator="AND",
                    vulnerable=True,
                    cpe_match=[
                        CPEMatch(
                            vulnerable=True,
                            criteria="cpe:2.3:a:lodash:lodash:*:*:*:*:*:*:*:*",
                            match_criteria_id="abc",
                            version_end_including="4.17.21"
                        )
                    ]
                )
            ],
            references=[],
            weaknesses=[],
            publisher="NIST",
        )

        result = enricher._extract_fixed_version(cve_data)

        assert result == "<=4.17.21"
