"""Scanner for SPDX and CycloneDX SBOM files."""

import json
from pathlib import Path
from ..scanners.base import BaseScanner, Package


class SBOMScanner(BaseScanner):
    """Scanner for SPDX and CycloneDX SBOM formats."""

    name = "sbom"

    def supports(self, input_path: str) -> bool:
        """Check if input is an SBOM file."""
        path = Path(input_path)
        suffix = path.suffix.lower()
        return suffix in [".json", ".xml", ".cdx"] or path.stem.lower() in [
            "sbom", "bom", "spdx", "cyclonedx"
        ]

    def scan(self, input_path: str) -> list[Package]:
        """Parse SBOM and return packages."""
        path = Path(input_path)

        if not path.exists():
            raise FileNotFoundError(f"SBOM file not found: {input_path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Detect SBOM format and parse accordingly
        if self._is_spdx(data):
            return self._parse_spdx(data)
        elif self._is_cyclonedx(data):
            return self._parse_cyclonedx(data)
        else:
            return []

    def _is_spdx(self, data: dict) -> bool:
        """Check if SBOM is SPDX format."""
        return data.get("spdxVersion") is not None

    def _is_cyclonedx(self, data: dict) -> bool:
        """Check if SBOM is CycloneDX format."""
        return data.get("bomFormat") == "CycloneDX" or "components" in data

    def _parse_spdx(self, data: dict) -> list[Package]:
        """Parse SPDX SBOM."""
        packages = []

        for pkg in data.get("packages", []):
            name = pkg.get("name", "")
            version = pkg.get("versionInfo", "*")
            ecosystem = self._detect_ecosystem_from_spdx(pkg)

            packages.append(Package(
                name=name,
                version=version,
                ecosystem=ecosystem,
                cpe=pkg.get("externalRefs", [{}])[0].get("referenceLocator"),
            ))

        return packages

    def _parse_cyclonedx(self, data: dict) -> list[Package]:
        """Parse CycloneDX SBOM."""
        packages = []

        for comp in data.get("components", []):
            if comp.get("type") != "library":
                continue

            name = comp.get("name", "")
            version = comp.get("version", "*")

            # Detect ecosystem
            purl = comp.get("purl", "")
            if "npm" in purl:
                ecosystem = "npm"
            elif "pypi" in purl:
                ecosystem = "pypi"
            elif "maven" in purl:
                ecosystem = "maven"
            else:
                ecosystem = "unknown"

            packages.append(Package(
                name=name,
                version=version,
                ecosystem=ecosystem,
                cpe=comp.get("cpe"),
            ))

        return packages

    def _detect_ecosystem_from_spdx(self, pkg: dict) -> str:
        """Detect ecosystem from SPDX package."""
        # Check package manager from external references
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType", "").startswith("purl"):
                purl = ref.get("referenceLocator", "")
                if "npm" in purl:
                    return "npm"
                elif "pypi" in purl:
                    return "pypi"
                elif "maven" in purl:
                    return "maven"
        return "unknown"
