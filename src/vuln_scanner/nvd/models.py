"""NVD API data models."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class CVSSScore(BaseModel):
    """CVSS score data."""
    version: str
    base_score: float
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    vector: Optional[str] = None


class CVEReference(BaseModel):
    """CVE reference URL."""
    url: str
    source: Optional[str] = None
    tags: list[str] = Field(default_factory=list)


class CVEConfiguration(BaseModel):
    """NVD configuration for a CVE (includes fix info)."""
    operator: str = "AND"  # AND, OR
    negate: bool = False
    vulnerable: bool = True
    cpe_match: list["CPEMatch"] = Field(default_factory=list)


class CPEMatch(BaseModel):
    """CPE match entry."""
    vulnerable: bool
    criteria: str
    match_criteria_id: str
    version_start_including: Optional[str] = None
    version_end_excluding: Optional[str] = None
    version_start_excluding: Optional[str] = None
    version_end_including: Optional[str] = None


class CVEDescription(BaseModel):
    """CVE description."""
    lang: str
    value: str


class CVEData(BaseModel):
    """Full CVE data from NVD API."""
    id: str  # CVE ID like "CVE-2024-1234"
    source_identifier: str
    published: datetime
    last_modified: datetime
    vuln_status: str
    descriptions: list[CVEDescription] = Field(default_factory=list)
    references: list[CVEReference] = Field(default_factory=list)
    metrics: dict = Field(default_factory=dict)  # cvss_metric_v31, cvss_metric_v30, etc.
    configurations: list[CVEConfiguration] = Field(default_factory=list)
    weaknesses: list[dict] = Field(default_factory=list)
    publisher: Optional[str] = None
    descriptions_en: Optional[str] = None  # Flattened English description

    def get_english_description(self) -> str:
        """Get English description."""
        for desc in self.descriptions:
            if desc.lang == "en":
                return desc.value
        return self.descriptions[0].value if self.descriptions else ""

    def get_cvss_score(self) -> Optional[CVSSScore]:
        """Extract CVSS score from metrics."""
        # Try v3.1 first, then v3.0, then v2.0
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in self.metrics and self.metrics[version]:
                metric = self.metrics[version][0]
                cvss = metric.get("cvssData", {})
                return CVSSScore(
                    version=cvss.get("version", version),
                    base_score=cvss.get("baseScore", 0.0),
                    severity=cvss.get("baseSeverity", "UNKNOWN"),
                    vector=cvss.get("vectorString"),
                )
        return None


class CVEListResponse(BaseModel):
    """Response from NVD CVE list endpoint."""
    results_per_page: int
    start_index: int
    total_results: int
    format: str
    version: str
    timestamp: datetime
    vulnerabilities: list[dict] = Field(default_factory=list)


class VulnerabilityFinding(BaseModel):
    """Represents a vulnerability finding from any scanner."""
    package_name: str
    installed_version: str
    cve_id: str
    cpe: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    references: list[str] = Field(default_factory=list)
    fixed_version: Optional[str] = None
    fix_suggestion: Optional[str] = None
    ai_confidence: Optional[float] = None  # 0.0 to 1.0 if AI generated
