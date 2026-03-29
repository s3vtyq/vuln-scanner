"""Extract fix suggestions from NVD data."""

from typing import Optional
from ..nvd.models import CVEData


class NVDFixExtractor:
    """Extract fix information from NVD CVE data."""

    def get_fix_suggestion(self, cve_data: CVEData) -> Optional[str]:
        """Extract fix suggestion from NVD configuration data."""
        fixes = []

        for config in cve_data.configurations:
            for cpe_match in config.cpe_match:
                if cpe_match.version_end_excluding:
                    fixes.append(f"Upgrade to version >= {cpe_match.version_end_excluding}")
                if cpe_match.version_end_including:
                    fixes.append(f"Upgrade to version > {cpe_match.version_end_including}")

        # Look for patches in references
        for ref in cve_data.references:
            if "patch" in ref.tags or "vendor" in ref.tags:
                fixes.append(f"Apply patch: {ref.url}")

        # Deduplicate and limit
        unique_fixes = list(dict.fromkeys(fixes))
        return "; ".join(unique_fixes[:2]) if unique_fixes else None

    def get_affected_versions(self, cve_data: CVEData) -> Optional[str]:
        """Get string describing affected versions."""
        for config in cve_data.configurations:
            for cpe_match in config.cpe_match:
                parts = []
                if cpe_match.version_start_including:
                    parts.append(f">= {cpe_match.version_start_including}")
                if cpe_match.version_start_excluding:
                    parts.append(f"> {cpe_match.version_start_excluding}")
                if cpe_match.version_end_including:
                    parts.append(f"<= {cpe_match.version_end_including}")
                if cpe_match.version_end_excluding:
                    parts.append(f"< {cpe_match.version_end_excluding}")

                if parts:
                    return ", ".join(parts)

        return None
