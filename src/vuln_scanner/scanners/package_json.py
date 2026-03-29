"""Scanner for npm package.json files."""

import json
from pathlib import Path
from ..scanners.base import BaseScanner, Package


class PackageJsonScanner(BaseScanner):
    """Scanner for npm package.json files."""

    name = "package_json"

    def supports(self, input_path: str) -> bool:
        """Check if input is a package.json file."""
        path = Path(input_path)
        return path.name.lower() == "package.json"

    def scan(self, input_path: str) -> list[Package]:
        """Parse package.json and return dependencies/devDependencies."""
        packages = []
        path = Path(input_path)

        if not path.exists():
            raise FileNotFoundError(f"package.json not found: {input_path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Scan both dependencies and devDependencies
        for key in ["dependencies", "devDependencies"]:
            if key in data:
                for name, version_spec in data[key].items():
                    packages.append(Package(
                        name=name,
                        version=self._clean_version(version_spec),
                        ecosystem="npm",
                        cpe=self._build_cpe(name)
                    ))

        return packages

    def _clean_version(self, version_spec: str) -> str:
        """Clean version specifier (remove ^, ~, etc)."""
        # Remove common prefixes
        for prefix in ["^", "~", ">=", "<=", ">", "<", "=", "v"]:
            if version_spec.startswith(prefix):
                version_spec = version_spec[1:]
        # Handle ranges - take first version
        if " " in version_spec or "-" in version_spec:
            version_spec = version_spec.split()[0].split("-")[0]
        return version_spec or "*"

    def _build_cpe(self, package_name: str) -> str:
        """Build a CPE string for an npm package."""
        return f"cpe:2.3:a:{package_name}:{package_name}:*:*:*:*:*:nodejs:*:*"
