"""Tests for async enricher."""

from datetime import datetime, timezone
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from vuln_scanner.core.async_enricher import AsyncCVEEnricher, enrich_findings_async
from vuln_scanner.nvd.models import VulnerabilityFinding, CVEData, CVEDescription, CVSSScore


class TestAsyncCVEEnricher:
    """Tests for AsyncCVEEnricher class."""

    @pytest.fixture
    def mock_nvd_client(self):
        """Create mock async NVD client."""
        client = AsyncMock()
        client.get_cve = AsyncMock()
        client.close = AsyncMock()
        return client

    @pytest.fixture
    def enricher(self, mock_nvd_client):
        """Create enricher with mock client."""
        return AsyncCVEEnricher(nvd_client=mock_nvd_client)

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
            references=[],
            weaknesses=[],
            publisher="NIST",
        )

    @pytest.mark.asyncio
    async def test_enrich_single_finding(self, enricher, mock_nvd_client, sample_finding, sample_cve_data):
        """Test enriching a single finding with CVE data."""
        mock_nvd_client.get_cve.return_value = sample_cve_data

        result = await enricher.enrich(sample_finding)

        assert result.description == "Test vulnerability description"
        assert result.severity == "HIGH"
        assert result.cvss_score == 7.5
        mock_nvd_client.get_cve.assert_called_once_with("CVE-2024-1234")

    @pytest.mark.asyncio
    async def test_enrich_batch(self, enricher, mock_nvd_client, sample_finding, sample_cve_data):
        """Test batch enrichment of multiple findings."""
        findings = [
            sample_finding,
            VulnerabilityFinding(
                package_name="lodash",
                installed_version="4.17.20",
                cve_id="CVE-2023-5678",
                severity=None,
                cvss_score=None,
            )
        ]

        mock_cve_data_2 = CVEData(
            id="CVE-2023-5678",
            source_identifier="nvd@nist.gov",
            published=datetime.now(timezone.utc),
            last_modified=datetime.now(timezone.utc),
            vuln_status="Analyzed",
            descriptions=[
                CVEDescription(lang="en", value="Another vulnerability")
            ],
            descriptions_en="Another vulnerability",
            metrics={
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": 5.3,
                            "baseSeverity": "MEDIUM",
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
                        }
                    }
                ]
            },
            configurations=[],
            references=[],
            weaknesses=[],
            publisher="NIST",
        )

        async def mock_get_cve(cve_id):
            if cve_id == "CVE-2024-1234":
                return sample_cve_data
            return mock_cve_data_2

        mock_nvd_client.get_cve = AsyncMock(side_effect=mock_get_cve)

        results = await enricher.enrich_batch(findings)

        assert len(results) == 2
        assert results[0].description == "Test vulnerability description"
        assert results[1].description == "Another vulnerability"

    @pytest.mark.asyncio
    async def test_enrich_no_cve_data(self, enricher, mock_nvd_client, sample_finding):
        """Test enrichment when no CVE data is found."""
        mock_nvd_client.get_cve.return_value = None

        result = await enricher.enrich(sample_finding)

        # Finding should be returned unchanged
        assert result.package_name == "requests"
        assert result.description is None

    @pytest.mark.asyncio
    async def test_enrich_preserves_existing_data(self, enricher, mock_nvd_client):
        """Test that existing data is not overwritten."""
        finding = VulnerabilityFinding(
            package_name="requests",
            installed_version="2.28.0",
            cve_id="CVE-2024-1234",
            description="Already have description",
            severity="CRITICAL",
            cvss_score=9.9,
        )

        sample_cve_data = CVEData(
            id="CVE-2024-1234",
            source_identifier="nvd@nist.gov",
            published=datetime.now(timezone.utc),
            last_modified=datetime.now(timezone.utc),
            vuln_status="Analyzed",
            descriptions=[
                CVEDescription(lang="en", value="Different description from NVD")
            ],
            descriptions_en="Different description from NVD",
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
            references=[],
            weaknesses=[],
            publisher="NIST",
        )

        mock_nvd_client.get_cve.return_value = sample_cve_data

        result = await enricher.enrich(finding)

        # Existing data should be preserved
        assert result.description == "Already have description"
        assert result.severity == "CRITICAL"
        assert result.cvss_score == 9.9


class TestEnrichFindingsAsync:
    """Tests for convenience function."""

    @pytest.mark.asyncio
    async def test_enrich_findings_async(self):
        """Test the convenience function."""
        findings = [
            VulnerabilityFinding(
                package_name="requests",
                installed_version="2.28.0",
                cve_id="CVE-2024-1234",
                severity=None,
                cvss_score=None,
            )
        ]

        mock_cve_data = CVEData(
            id="CVE-2024-1234",
            source_identifier="nvd@nist.gov",
            published=datetime.now(timezone.utc),
            last_modified=datetime.now(timezone.utc),
            vuln_status="Analyzed",
            descriptions=[
                CVEDescription(lang="en", value="Test description")
            ],
            descriptions_en="Test description",
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
            references=[],
            weaknesses=[],
            publisher="NIST",
        )

        with patch('vuln_scanner.core.async_enricher.AsyncCVEEnricher') as MockEnricher:
            mock_instance = AsyncMock()
            mock_instance.enrich_batch.return_value = findings
            mock_instance.nvd_client.close = AsyncMock()
            MockEnricher.return_value = mock_instance

            result = await enrich_findings_async(findings)

            assert result == findings
            mock_instance.nvd_client.close.assert_called_once()
