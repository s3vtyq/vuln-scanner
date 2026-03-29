"""AI-powered fix suggestions using MiniMax API."""

import os
import json
from typing import Optional
import httpx


class MiniMaxFixSuggester:
    """Generate fix suggestions using MiniMax AI."""

    API_URL = "https://api.minimax.chat/v1/text/chatcompletion_pro"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("MINIMAX_API_KEY")
        self.group_id = os.getenv("MINIMAX_GROUP_ID", "")

    def is_available(self) -> bool:
        """Check if MiniMax API is configured."""
        return bool(self.api_key)

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
            Tuple of (suggestion, confidence_score)
        """
        if not self.is_available():
            return None, 0.0

        prompt = self._build_prompt(
            package_name, current_version, cve_id, cve_description, severity
        )

        try:
            suggestion = self._call_api(prompt)
            return suggestion, 0.85  # AI confidence
        except Exception as e:
            print(f"MiniMax API error: {e}")
            return None, 0.0

    def _build_prompt(
        self,
        package_name: str,
        current_version: str,
        cve_id: str,
        cve_description: str,
        severity: str,
    ) -> str:
        """Build prompt for fix suggestion."""
        return f"""You are a security expert helping developers fix vulnerabilities.

CVE: {cve_id}
Package: {package_name}
Current Version: {current_version}
Severity: {severity}
Description: {cve_description[:500]}

Provide a concise fix suggestion that includes:
1. Recommended action (upgrade, patch, workaround)
2. Target version if upgrade is recommended
3. Any critical notes about the fix

Keep it brief - 1-3 sentences. If no safe upgrade exists, suggest checking the references.

Example format:
"Upgrade {package_name} to version 2.4.1 or later. The vulnerability was patched in this release. Run: pip install {package_name}==2.4.1"
"""

    def _call_api(self, prompt: str) -> Optional[str]:
        """Call MiniMax API."""
        if not self.api_key:
            return None

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": "MiniMax-Text-01",
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "max_tokens": 200,
            "temperature": 0.3
        }

        # Add group_id if available
        if self.group_id:
            payload["group_id"] = self.group_id

        with httpx.Client(timeout=30.0) as client:
            response = client.post(
                self.API_URL,
                headers=headers,
                json=payload
            )
            response.raise_for_status()

            data = response.json()
            choices = data.get("choices", [])
            if choices:
                return choices[0].get("messages", [{}])[0].get("content", "").strip()

        return None
