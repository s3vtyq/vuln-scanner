"""Package manager integration for fix suggestions."""

import httpx
from typing import Optional


class PackageFixChecker:
    """Check package managers for latest versions and fixes."""

    def get_latest_version(self, package_name: str, ecosystem: str) -> Optional[str]:
        """Query package manager for latest version."""
        if ecosystem == "pypi":
            return self._get_pypi_latest(package_name)
        elif ecosystem == "npm":
            return self._get_npm_latest(package_name)
        return None

    def _get_pypi_latest(self, package_name: str) -> Optional[str]:
        """Get latest version from PyPI."""
        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.get(f"https://pypi.org/pypi/{package_name}/json")
                if response.status_code == 200:
                    data = response.json()
                    return data["info"]["version"]
        except httpx.HTTPError:
            pass
        return None

    def _get_npm_latest(self, package_name: str) -> Optional[str]:
        """Get latest version from npm registry."""
        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.get(
                    f"https://registry.npmjs.org/{package_name}/latest"
                )
                if response.status_code == 200:
                    data = response.json()
                    return data.get("version")
        except httpx.HTTPError:
            pass
        return None

    def suggest_upgrade_command(self, package_name: str, new_version: str, ecosystem: str) -> str:
        """Generate command to upgrade package."""
        if ecosystem == "pypi":
            return f"pip install {package_name}=={new_version}"
        elif ecosystem == "npm":
            return f"npm install {package_name}@{new_version}"
        return f"# Upgrade {package_name} to {new_version}"
