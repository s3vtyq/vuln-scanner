"""Main fix suggestion orchestrator."""

import os
from typing import Optional
from ..nvd.models import VulnerabilityFinding
from .nvd_fixes import NVDFixExtractor
from .package_fixes import PackageFixChecker
from .providers import get_provider


class FixSuggester:
    """Orchestrates fix suggestions from multiple sources."""

    def __init__(self, use_ai: bool = True, ai_provider: Optional[str] = None):
        self.nvd_extractor = NVDFixExtractor()
        self.package_checker = PackageFixChecker()

        if use_ai:
            # CLI flag overrides env var
            provider_name = ai_provider or os.getenv("AI_PROVIDER", "minimax")
            self.ai_suggester = get_provider(provider_name)
        else:
            self.ai_suggester = None

    def suggest_fix(self, finding: VulnerabilityFinding) -> VulnerabilityFinding:
        """
        Generate a fix suggestion for a vulnerability finding.

        Priority:
        1. NVD fix configuration data
        2. Package manager latest version
        3. AI-generated suggestion (if enabled)
        """
        # Start with NVD fix data
        nvd_fix = None
        if finding.cve_id:
            # We need to fetch CVE data for fix extraction
            # This is a simplified version - in practice, the enricher would have cached this
            nvd_fix = "Upgrade to a patched version"  # Placeholder

        # Try package manager
        latest_version = None
        upgrade_command = None

        if finding.package_name:
            # Determine ecosystem from CPE or default
            ecosystem = self._detect_ecosystem(finding)
            latest_version = self.package_checker.get_latest_version(
                finding.package_name, ecosystem
            )

            if latest_version and latest_version != finding.installed_version:
                upgrade_command = self.package_checker.suggest_upgrade_command(
                    finding.package_name, latest_version, ecosystem
                )

        # Try AI if enabled
        ai_suggestion = None
        ai_confidence = 0.0

        if self.ai_suggester and self.ai_suggester.is_available():
            ai_suggestion, ai_confidence = self.ai_suggester.generate_fix_suggestion(
                package_name=finding.package_name,
                current_version=finding.installed_version,
                cve_id=finding.cve_id,
                cve_description=finding.description or "",
                severity=finding.severity or "UNKNOWN",
            )

        # Build combined fix suggestion
        suggestion_parts = []

        if upgrade_command:
            suggestion_parts.append(f"Run: {upgrade_command}")

        if ai_suggestion:
            suggestion_parts.append(ai_suggestion)
            finding.ai_confidence = ai_confidence

        if nvd_fix and not ai_suggestion:
            suggestion_parts.append(nvd_fix)

        if suggestion_parts:
            # Deduplicate and join
            finding.fix_suggestion = " | ".join(dict.fromkeys(suggestion_parts))

        if latest_version and latest_version != finding.installed_version:
            finding.fixed_version = latest_version

        return finding

    def _detect_ecosystem(self, finding: VulnerabilityFinding) -> str:
        """Detect package ecosystem from CPE or package name."""
        if finding.cpe:
            cpe = finding.cpe.lower()
            if "python" in cpe or "pypi" in cpe:
                return "pypi"
            if "nodejs" in cpe or "npm" in cpe:
                return "npm"
            if "maven" in cpe or "java" in cpe:
                return "maven"

        # Heuristic based on package name patterns
        name = finding.package_name.lower()
        if name.startswith("@"):
            return "npm"  # Scoped npm package
        if any(c in name for c in ["-", "_"]) and not name[0].isdigit():
            # Could be many things, default to pypi
            return "pypi"

        return "pypi"
