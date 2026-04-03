"""Scanner for Trivy JSON output - for enrichment."""

import json
from pathlib import Path
from ..scanners.base import BaseScanner, Package


class TrivyScanner(BaseScanner):
    """Scanner for Trivy JSON output files (for enrichment)."""

    name = "trivy"

    def supports(self, input_path: str) -> bool:
        """Check if input is a Trivy JSON file."""
        path = Path(input_path)
        if not path.suffix.lower() == ".json":
            return False

        # Try to detect if it's Trivy format
        try:
            with open(path, "r") as f:
                data = json.load(f)
                return (
                    "Results" in data or
                    "Vulnerabilities" in data or
                    data.get("ArtifactName") is not None
                )
        except (json.JSONDecodeError, UnicodeDecodeError, FileNotFoundError):
            return False

    def scan(self, input_path: str) -> list[Package]:
        """Parse Trivy JSON and return affected packages."""
        packages = []
        path = Path(input_path)

        if not path.exists():
            raise FileNotFoundError(f"Trivy file not found: {input_path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Trivy has different formats depending on type
        if "Results" in data:
            packages.extend(self._parse_results_format(data["Results"]))
        elif "results" in data:
            packages.extend(self._parse_results_format(data["results"]))
        elif "Vulnerabilities" in data:
            packages.extend(self._parse_vulns_format(data["Vulnerabilities"]))

        return packages

    def _parse_results_format(self, results: list) -> list[Package]:
        """Parse Trivy's Results format."""
        packages = []

        for result in results:
            for vuln in result.get("Vulnerabilities", []) or []:
                packages.append(Package(
                    name=vuln.get("PkgName", "unknown"),
                    version=vuln.get("InstalledVersion", "*"),
                    ecosystem=self._detect_ecosystem(vuln),
                ))

        return packages

    def _parse_vulns_format(self, vulns: list) -> list[Package]:
        """Parse Trivy's Vulnerabilities format."""
        packages = []

        for vuln in vulns:
            packages.append(Package(
                name=vuln.get("package", "unknown"),
                version=vuln.get("installedVersion", "*"),
                ecosystem=self._detect_ecosystem(vuln),
            ))

        return packages

    def _detect_ecosystem(self, vuln: dict) -> str:
        """Detect ecosystem from vulnerability data."""
        # Try to detect from vulnerability ID pattern or ecosystem field
        if "Ecosystem" in vuln:
            return vuln["Ecosystem"].lower()
        return "unknown"
