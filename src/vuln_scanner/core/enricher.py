"""CVE Enricher - augments scanner findings with NVD data."""

from typing import Optional
from ..nvd.client import NVDClient
from ..nvd.models import CVEData, VulnerabilityFinding
from ..logging_config import get_logger

logger = get_logger("core.enricher")


class CVEEnricher:
    """Enriches vulnerability findings with NVD data."""

    def __init__(self, nvd_client: Optional[NVDClient] = None):
        self.nvd_client = nvd_client or NVDClient()

    def enrich(self, finding: VulnerabilityFinding) -> VulnerabilityFinding:
        """Enrich a single vulnerability finding with NVD data."""
        # Try to fetch CVE from NVD
        cve_data = self.nvd_client.get_cve(finding.cve_id)

        if cve_data:
            # Apply NVD data to finding
            if not finding.description:
                finding.description = cve_data.get_english_description()

            cvss_score = cve_data.get_cvss_score()
            if cvss_score:
                if not finding.cvss_score:
                    finding.cvss_score = cvss_score.base_score
                if not finding.severity:
                    finding.severity = cvss_score.severity
                if not finding.cvss_vector:
                    finding.cvss_vector = cvss_score.vector

            # Extract references
            if not finding.references:
                finding.references = [ref.url for ref in cve_data.references[:5]]

            # Try to extract fix version from configurations
            if not finding.fixed_version:
                finding.fixed_version = self._extract_fixed_version(cve_data)

        return finding

    def enrich_batch(self, findings: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
        """Enrich multiple findings."""
        logger.info(f"Enriching batch of {len(findings)} findings")
        return [self.enrich(f) for f in findings]

    def _extract_fixed_version(self, cve_data: CVEData) -> Optional[str]:
        """Extract fixed version from CVE configurations."""
        for config in cve_data.configurations:
            for cpe_match in config.cpe_match:
                if cpe_match.version_end_excluding:
                    return f"<{cpe_match.version_end_excluding}"
                if cpe_match.version_end_including:
                    return f"<={cpe_match.version_end_including}"
        return None
