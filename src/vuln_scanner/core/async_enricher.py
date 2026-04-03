"""Async CVE Enricher - augments scanner findings with NVD data asynchronously."""

import asyncio
from typing import Optional

from ..nvd.async_client import AsyncNVDClient
from ..nvd.models import VulnerabilityFinding
from ..logging_config import get_logger

logger = get_logger("core.async_enricher")


class AsyncCVEEnricher:
    """Async enriches vulnerability findings with NVD data."""

    def __init__(self, nvd_client: Optional[AsyncNVDClient] = None, max_concurrent: int = 6):
        self.nvd_client = nvd_client or AsyncNVDClient(max_concurrent=max_concurrent)

    async def enrich(self, finding: VulnerabilityFinding) -> VulnerabilityFinding:
        """Enrich a single vulnerability finding with NVD data."""
        cve_data = await self.nvd_client.get_cve(finding.cve_id)

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

    async def enrich_batch(self, findings: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
        """Enrich multiple findings concurrently using asyncio.gather."""
        logger.info(f"Async enriching batch of {len(findings)} findings")
        tasks = [self.enrich(f) for f in findings]
        return await asyncio.gather(*tasks)

    def _extract_fixed_version(self, cve_data) -> Optional[str]:
        """Extract fixed version from CVE configurations."""
        for config in cve_data.configurations:
            for cpe_match in config.cpe_match:
                if cpe_match.version_end_excluding:
                    return f"<{cpe_match.version_end_excluding}"
                if cpe_match.version_end_including:
                    return f"<={cpe_match.version_end_including}"
        return None


async def enrich_findings_async(
    findings: list[VulnerabilityFinding],
    max_concurrent: int = 6
) -> list[VulnerabilityFinding]:
    """
    Convenience function to enrich findings asynchronously.

    Args:
        findings: List of vulnerability findings to enrich
        max_concurrent: Maximum concurrent NVD API requests (default: 6)

    Returns:
        List of enriched vulnerability findings
    """
    enricher = AsyncCVEEnricher(max_concurrent=max_concurrent)
    try:
        return await enricher.enrich_batch(findings)
    finally:
        await enricher.nvd_client.close()
