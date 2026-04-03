"""Async NVD API v2 client with semaphore rate limiting."""

import asyncio
from typing import Optional
from datetime import datetime

import httpx

from .models import CVEData, CVEDescription, CVEReference, CVEConfiguration, CPEMatch
from .cache import NVDCache


class AsyncNVDClient:
    """Async client for NVD NIST API v2 with semaphore rate limiting."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Rate limits
    UNAUTH_LIMIT = 50  # requests per day
    AUTH_LIMIT = 6  # requests per minute

    def __init__(self, api_key: Optional[str] = None, cache_dir: Optional[str] = None, max_concurrent: int = 6):
        import os
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.cache = NVDCache(cache_dir)
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create async HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self._client

    async def close(self) -> None:
        """Close the async HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def get_cve(self, cve_id: str, use_cache: bool = True) -> Optional[CVEData]:
        """Fetch a single CVE by ID asynchronously."""
        # Check cache first
        if use_cache:
            cached = self.cache.get(cve_id)
            if cached:
                return cached

        # Fetch from API with semaphore rate limiting
        url = f"{self.BASE_URL}?cveId={cve_id}"
        async with self._semaphore:
            try:
                client = await self._get_client()
                headers = {}
                if self.api_key:
                    headers["apiKey"] = self.api_key

                response = await client.get(url, headers=headers)
                response.raise_for_status()

                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])

                if not vulnerabilities:
                    return None

                vuln = vulnerabilities[0].get("cve", {})
                cve_data = self._parse_cve(vuln)

                # Cache the result
                if cve_data:
                    self.cache.set(cve_id, cve_data)

                return cve_data

            except httpx.HTTPError as e:
                import logging
                logger = logging.getLogger("vuln_scanner.nvd.async_client")
                logger.error(f"Error fetching CVE {cve_id}: {e}")
                return None

    async def get_cves_batch(self, cve_ids: list[str]) -> dict[str, Optional[CVEData]]:
        """Fetch multiple CVEs concurrently."""
        tasks = [self.get_cve(cve_id) for cve_id in cve_ids]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        return {
            cve_id: result if not isinstance(result, Exception) else None
            for cve_id, result in zip(cve_ids, results)
        }

    def _parse_cve(self, vuln: dict) -> Optional[CVEData]:
        """Parse raw NVD CVE data into our model."""
        try:
            # Extract English description
            descriptions = []
            for desc in vuln.get("descriptions", []):
                descriptions.append(CVEDescription(
                    lang=desc.get("lang", "en"),
                    value=desc.get("value", "")
                ))

            english_desc = next(
                (d.value for d in descriptions if d.lang == "en"),
                descriptions[0].value if descriptions else ""
            )

            # Parse metrics
            metrics = vuln.get("metrics", {})

            # Parse configurations
            configurations = []
            for config in vuln.get("configurations", []):
                configs = self._parse_configuration(config)
                configurations.extend(configs)

            return CVEData(
                id=vuln.get("id", ""),
                source_identifier=vuln.get("sourceIdentifier", ""),
                published=datetime.fromisoformat(
                    vuln.get("published", "1970-01-01T00:00:00").replace("Z", "+00:00")
                ),
                last_modified=datetime.fromisoformat(
                    vuln.get("lastModified", "1970-01-01T00:00:00").replace("Z", "+00:00")
                ),
                vuln_status=vuln.get("vulnStatus", ""),
                descriptions=descriptions,
                descriptions_en=english_desc,
                references=[
                    CVEReference(
                        url=ref.get("url", ""),
                        source=ref.get("source", ""),
                        tags=ref.get("tags", [])
                    )
                    for ref in vuln.get("references", [])
                ],
                metrics=metrics,
                configurations=configurations,
                weaknesses=vuln.get("weaknesses", []),
                publisher=vuln.get("publisher", ""),
            )

        except Exception as e:
            import logging
            logger = logging.getLogger("vuln_scanner.nvd.async_client")
            logger.error(f"Error parsing CVE: {e}")
            return None

    def _parse_configuration(self, config: dict) -> list[CVEConfiguration]:
        """Parse NVD configuration including nested ones."""
        configurations = []

        if "nodes" in config:
            for node in config["nodes"]:
                for match in node.get("cpeMatch", []):
                    configurations.append(CVEConfiguration(
                        operator=node.get("operator", "OR"),
                        negate=node.get("negate", False),
                        vulnerable=match.get("vulnerable", True),
                        cpe_match=[CPEMatch(
                            vulnerable=match.get("vulnerable", True),
                            criteria=match.get("criteria", ""),
                            match_criteria_id=match.get("matchCriteriaId", ""),
                            version_start_including=match.get("versionStartIncluding"),
                            version_end_excluding=match.get("versionEndExcluding"),
                            version_start_excluding=match.get("versionStartExcluding"),
                            version_end_including=match.get("versionEndIncluding"),
                        )]
                    ))

        return configurations
