"""NVD API v2 client with rate limiting and caching."""

import os
import time
from typing import Optional
from datetime import datetime
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from .models import CVEData, CVEDescription, CVEReference, CVEConfiguration, CPEMatch
from .cache import NVDCache
from ..logging_config import get_logger

logger = get_logger("nvd.client")


class NVDAPIRateLimit(Exception):
    """Raised when NVD API rate limit is hit."""
    pass


class NVDClient:
    """Client for NVD NIST API v2."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Rate limits
    UNAUTH_LIMIT = 50  # requests per day
    AUTH_LIMIT = 6  # requests per minute

    def __init__(self, api_key: Optional[str] = None, cache_dir: Optional[str] = None):
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.cache = NVDCache(cache_dir)
        self._request_times: list[float] = []
        self._daily_requests: list[float] = []

    def _should_rate_limit(self) -> None:
        """Check if we should wait before making a request."""
        now = time.time()

        # Clean old entries
        self._request_times = [t for t in self._request_times if now - t < 60]
        self._daily_requests = [t for t in self._daily_requests if now - t < 86400]

        if self.api_key:
            if len(self._request_times) >= self.AUTH_LIMIT:
                sleep_time = 60 - (now - self._request_times[0])
                if sleep_time > 0:
                    time.sleep(sleep_time)
        else:
            if len(self._daily_requests) >= self.UNAUTH_LIMIT:
                raise NVDAPIRateLimit(
                    f"Daily limit of {self.UNAUTH_LIMIT} requests reached. "
                    "Use NVD_API_KEY for higher limits."
                )

    def _record_request(self) -> None:
        """Record that a request was made."""
        now = time.time()
        self._request_times.append(now)
        self._daily_requests.append(now)

    @retry(
        retry=retry_if_exception_type((httpx.HTTPError, NVDAPIRateLimit)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=60)
    )
    def _make_request(self, url: str) -> dict:
        """Make HTTP request with retry logic."""
        self._should_rate_limit()

        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        with httpx.Client(timeout=30.0) as client:
            response = client.get(url, headers=headers)
            response.raise_for_status()

            if response.status_code == 403 or response.status_code == 429:
                raise NVDAPIRateLimit("Rate limit hit")

            self._record_request()
            return response.json()

    def get_cve(self, cve_id: str, use_cache: bool = True) -> Optional[CVEData]:
        """Fetch a single CVE by ID."""
        # Check cache first
        if use_cache:
            cached = self.cache.get(cve_id)
            if cached:
                return cached

        # Fetch from API
        url = f"{self.BASE_URL}?cveId={cve_id}"
        try:
            data = self._make_request(url)
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
            logger.error(f"Error fetching CVE {cve_id}: {e}")
            return None

    def get_cves_by_cpe(self, cpe_name: str, max_results: int = 100) -> list[CVEData]:
        """Fetch CVEs by CPE name."""
        cves = []
        start_index = 0

        while len(cves) < max_results:
            url = f"{self.BASE_URL}?cpeName={cpe_name}&startIndex={start_index}"

            try:
                data = self._make_request(url)
                vulnerabilities = data.get("vulnerabilities", [])

                if not vulnerabilities:
                    break

                for vuln in vulnerabilities:
                    cve_data = self._parse_cve(vuln.get("cve", {}))
                    if cve_data:
                        cves.append(cve_data)

                total = data.get("totalResults", 0)
                if start_index + len(vulnerabilities) >= total:
                    break

                start_index += len(vulnerabilities)

            except httpx.HTTPError:
                break

        return cves[:max_results]

    def get_recent_cves(self, days: int = 7, max_results: int = 100) -> list[CVEData]:
        """Fetch recent CVEs from the last N days."""
        from datetime import timedelta

        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)

        cves = []
        start_index = 0

        while len(cves) < max_results:
            url = (
                f"{self.BASE_URL}?"
                f"pubStartDate={start_date.isoformat()}Z&"
                f"pubEndDate={end_date.isoformat()}Z&"
                f"startIndex={start_index}"
            )

            try:
                data = self._make_request(url)
                vulnerabilities = data.get("vulnerabilities", [])

                if not vulnerabilities:
                    break

                for vuln in vulnerabilities:
                    cve_data = self._parse_cve(vuln.get("cve", {}))
                    if cve_data:
                        cves.append(cve_data)

                total = data.get("totalResults", 0)
                if start_index + len(vulnerabilities) >= total:
                    break

                start_index += len(vulnerabilities)

            except httpx.HTTPError:
                break

        return cves[:max_results]

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
