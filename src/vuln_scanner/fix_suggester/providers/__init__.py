"""AI providers for fix suggestions."""

import os
from typing import Optional

import httpx

from .base import AIProvider


PROVIDERS = {
    "minimax": "MiniMaxFixSuggester",
    "openai": "OpenAIProvider",
    "anthropic": "AnthropicProvider",
    "gemini": "GeminiProvider",
    "ollama": "OllamaProvider",
}


def get_provider(name: str) -> Optional[AIProvider]:
    """Get a provider instance by name."""
    provider_map = {
        "minimax": MiniMaxFixSuggester,
        "openai": OpenAIProvider,
        "anthropic": AnthropicProvider,
        "gemini": GeminiProvider,
        "ollama": OllamaProvider,
    }
    provider_cls = provider_map.get(name)
    if provider_cls:
        return provider_cls()
    return None


class MiniMaxFixSuggester:
    """Generate fix suggestions using MiniMax AI."""

    API_URL = "https://api.minimax.chat/v1/text/chatcompletion_pro"

    def is_available(self) -> bool:
        """Check if MiniMax API is configured."""
        return bool(os.getenv("MINIMAX_API_KEY"))

    def generate_fix_suggestion(
        self,
        package_name: str,
        current_version: str,
        cve_id: str,
        cve_description: str,
        severity: str,
    ) -> tuple[Optional[str], float]:
        if not self.is_available():
            return None, 0.0

        prompt = self._build_prompt(
            package_name, current_version, cve_id, cve_description, severity
        )

        try:
            suggestion = self._call_api(prompt)
            return suggestion, 0.85
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
        api_key = os.getenv("MINIMAX_API_KEY")
        group_id = os.getenv("MINIMAX_GROUP_ID", "")

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": "MiniMax-Text-01",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 200,
            "temperature": 0.3
        }

        if group_id:
            payload["group_id"] = group_id

        with httpx.Client(timeout=30.0) as client:
            response = client.post(self.API_URL, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()
            choices = data.get("choices", [])
            if choices:
                return choices[0].get("messages", [{}])[0].get("content", "").strip()
        return None


class OpenAIProvider:
    """Generate fix suggestions using OpenAI GPT models."""

    API_URL = "https://api.openai.com/v1/chat/completions"

    def is_available(self) -> bool:
        return bool(os.getenv("OPENAI_API_KEY"))

    def generate_fix_suggestion(
        self,
        package_name: str,
        current_version: str,
        cve_id: str,
        cve_description: str,
        severity: str,
    ) -> tuple[Optional[str], float]:
        if not self.is_available():
            return None, 0.0

        prompt = self._build_prompt(
            package_name, current_version, cve_id, cve_description, severity
        )

        try:
            suggestion = self._call_api(prompt)
            return suggestion, 0.85
        except Exception as e:
            print(f"OpenAI API error: {e}")
            return None, 0.0

    def _build_prompt(
        self,
        package_name: str,
        current_version: str,
        cve_id: str,
        cve_description: str,
        severity: str,
    ) -> str:
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
        api_key = os.getenv("OPENAI_API_KEY")

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 200,
            "temperature": 0.3
        }

        with httpx.Client(timeout=30.0) as client:
            response = client.post(self.API_URL, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()
            choices = data.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", "").strip()
        return None


class AnthropicProvider:
    """Generate fix suggestions using Anthropic Claude models."""

    API_URL = "https://api.anthropic.com/v1/messages"

    def is_available(self) -> bool:
        return bool(os.getenv("ANTHROPIC_API_KEY"))

    def generate_fix_suggestion(
        self,
        package_name: str,
        current_version: str,
        cve_id: str,
        cve_description: str,
        severity: str,
    ) -> tuple[Optional[str], float]:
        if not self.is_available():
            return None, 0.0

        prompt = self._build_prompt(
            package_name, current_version, cve_id, cve_description, severity
        )

        try:
            suggestion = self._call_api(prompt)
            return suggestion, 0.85
        except Exception as e:
            print(f"Anthropic API error: {e}")
            return None, 0.0

    def _build_prompt(
        self,
        package_name: str,
        current_version: str,
        cve_id: str,
        cve_description: str,
        severity: str,
    ) -> str:
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
        api_key = os.getenv("ANTHROPIC_API_KEY")

        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json"
        }

        payload = {
            "model": "claude-sonnet-4-5",
            "max_tokens": 200,
            "messages": [{"role": "user", "content": prompt}]
        }

        with httpx.Client(timeout=30.0) as client:
            response = client.post(self.API_URL, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()
            return data.get("content", [{}])[0].get("text", "").strip()
        return None


class GeminiProvider:
    """Generate fix suggestions using Google Gemini models."""

    API_URL = "https://generativelanguage.googleapis.comv1beta/models/gemini-2.0-flash:generateContent"

    def is_available(self) -> bool:
        return bool(os.getenv("GEMINI_API_KEY"))

    def generate_fix_suggestion(
        self,
        package_name: str,
        current_version: str,
        cve_id: str,
        cve_description: str,
        severity: str,
    ) -> tuple[Optional[str], float]:
        if not self.is_available():
            return None, 0.0

        prompt = self._build_prompt(
            package_name, current_version, cve_id, cve_description, severity
        )

        try:
            suggestion = self._call_api(prompt)
            return suggestion, 0.85
        except Exception as e:
            print(f"Gemini API error: {e}")
            return None, 0.0

    def _build_prompt(
        self,
        package_name: str,
        current_version: str,
        cve_id: str,
        cve_description: str,
        severity: str,
    ) -> str:
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
        api_key = os.getenv("GEMINI_API_KEY")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"

        headers = {"Content-Type": "application/json"}

        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": 200, "temperature": 0.3}
        }

        with httpx.Client(timeout=30.0) as client:
            response = client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()
            return data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "").strip()
        return None


class OllamaProvider:
    """Generate fix suggestions using local Ollama models."""

    def is_available(self) -> bool:
        base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.get(f"{base_url}/api/tags")
                return response.status_code == 200
        except Exception:
            return False

    def generate_fix_suggestion(
        self,
        package_name: str,
        current_version: str,
        cve_id: str,
        cve_description: str,
        severity: str,
    ) -> tuple[Optional[str], float]:
        if not self.is_available():
            return None, 0.0

        prompt = self._build_prompt(
            package_name, current_version, cve_id, cve_description, severity
        )

        try:
            suggestion = self._call_api(prompt)
            return suggestion, 0.80
        except Exception as e:
            print(f"Ollama API error: {e}")
            return None, 0.0

    def _build_prompt(
        self,
        package_name: str,
        current_version: str,
        cve_id: str,
        cve_description: str,
        severity: str,
    ) -> str:
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
        base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

        payload = {
            "model": os.getenv("OLLAMA_MODEL", "llama3.2"),
            "prompt": prompt,
            "stream": False
        }

        with httpx.Client(timeout=60.0) as client:
            response = client.post(f"{base_url}/api/generate", json=payload)
            response.raise_for_status()
            data = response.json()
            return data.get("response", "").strip()
        return None
