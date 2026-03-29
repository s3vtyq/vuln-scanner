"""CSV formatter for vulnerability reports."""

import csv
from typing import TextIO
from ..nvd.models import VulnerabilityFinding


class CSVFormatter:
    """Format findings as CSV."""

    def format(self, findings: list[VulnerabilityFinding], output: TextIO) -> None:
        """Write findings as CSV."""
        fieldnames = [
            "package_name", "installed_version", "cve_id",
            "severity", "cvss_score", "description",
            "fixed_version", "fix_suggestion"
        ]

        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()

        for finding in findings:
            writer.writerow({
                "package_name": finding.package_name,
                "installed_version": finding.installed_version,
                "cve_id": finding.cve_id,
                "severity": finding.severity or "UNKNOWN",
                "cvss_score": finding.cvss_score or "",
                "description": (finding.description or "")[:200],
                "fixed_version": finding.fixed_version or "",
                "fix_suggestion": finding.fix_suggestion or "",
            })
