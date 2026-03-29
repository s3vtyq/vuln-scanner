"""Scanner for Python requirements.txt files."""

import re
from pathlib import Path
from ..scanners.base import BaseScanner, Package


class RequirementsScanner(BaseScanner):
    """Scanner for Python requirements.txt files."""

    name = "requirements"

    # Regex for package==version or package>=version etc.
    PACKAGE_PATTERN = re.compile(
        r'^([a-zA-Z0-9][-a-zA-Z0-9._]*)'  # Package name
        r'(?:[=<>!~]+)'                    # Operator
        r'([0-9][a-zA-Z0-9._*,-]*)'         # Version
        r'?$'
    )

    def supports(self, input_path: str) -> bool:
        """Check if input is a requirements.txt file."""
        path = Path(input_path)
        name = path.name.lower()
        return (
            name == "requirements.txt" or
            name.startswith("requirements") and name.endswith(".txt") or
            name.endswith(".txt") and "requirements" in name
        )

    def scan(self, input_path: str) -> list[Package]:
        """Parse requirements.txt and return packages."""
        packages = []
        path = Path(input_path)

        if not path.exists():
            raise FileNotFoundError(f"Requirements file not found: {input_path}")

        with open(path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue

                # Skip -r, -e, -c, --index-url, etc.
                if line.startswith("-"):
                    continue

                # Skip URLs and file paths
                if "://" in line or line.startswith("/"):
                    continue

                # Parse package
                package = self._parse_line(line)
                if package:
                    packages.append(package)

        return packages

    def _parse_line(self, line: str) -> Package | None:
        """Parse a single requirements line."""
        # Handle multiple packages on one line (rare but exists)
        line = line.split(",")[0]

        match = self.PACKAGE_PATTERN.match(line)
        if match:
            name = match.group(1).lower().replace("_", "-")
            version = match.group(2) if match.lastindex >= 2 else "*"

            return Package(
                name=name,
                version=version,
                ecosystem="pypi",
                cpe=self._build_cpe(name)
            )

        return None

    def _build_cpe(self, package_name: str) -> str:
        """Build a CPE string for a package."""
        # Standard CPE format for Python packages
        return f"cpe:2.3:a:*:{package_name}:*:*:*:*:*:python:*:*"
