"""AI Provider interface for fix suggestions."""

from typing import Protocol, Optional


class AIProvider(Protocol):
    """Protocol for AI-powered fix suggestion providers."""

    def is_available(self) -> bool:
        """Check if the provider is configured and available."""
        ...

    def generate_fix_suggestion(
        self,
        package_name: str,
        current_version: str,
        cve_id: str,
        cve_description: str,
        severity: str,
    ) -> tuple[Optional[str], float]:
        """
        Generate an AI-powered fix suggestion.

        Returns:
            Tuple of (suggestion_text, confidence_score)
        """
        ...
