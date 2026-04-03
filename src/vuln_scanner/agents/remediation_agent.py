"""RemediationAgent - automates vulnerability fixes via GitHub PRs."""

import re
from typing import Optional

from ..nvd.models import VulnerabilityFinding
from ..fix_suggester.suggester import FixSuggester
from ..fix_suggester.package_fixes import PackageFixChecker
from .github_client import GitHubClient
from .models import RemediationResult, FixStrategy


class RemediationAgent:
    """Agent that automates vulnerability remediation via GitHub PRs."""

    def __init__(
        self,
        github_token: Optional[str] = None,
        owner: Optional[str] = None,
        repo: Optional[str] = None,
        base_branch: str = "main",
    ):
        self.github = GitHubClient(github_token, owner, repo)
        self.fix_suggester = FixSuggester()
        self.package_checker = PackageFixChecker()
        self.base_branch = base_branch

    def determine_fix_strategy(self, finding: VulnerabilityFinding) -> Optional[FixStrategy]:
        """Determine how to fix a vulnerability."""
        # Get fix suggestion from enricher
        self.fix_suggester.suggest_fix(finding)

        if not finding.fixed_version and not finding.fix_suggestion:
            return None

        # Parse the fixed version
        fixed_version = finding.fixed_version or ""
        if fixed_version.startswith("<="):
            new_version = fixed_version[2:]
            action = "upgrade"
        elif fixed_version.startswith("<"):
            new_version = fixed_version[1:]
            action = "upgrade"
        else:
            new_version = fixed_version
            action = "upgrade" if new_version else "remove"

        # Determine risk level
        risk, breaking = self._assess_risk(finding.installed_version, new_version)

        # Build command
        ecosystem = getattr(finding, 'ecosystem', None) or self._detect_ecosystem(finding)
        command = self._build_upgrade_command(finding.package_name, new_version, ecosystem)

        return FixStrategy(
            action=action,
            new_version=new_version,
            command=command,
            risk_level=risk,
            breaking_change=breaking,
            explanation=self._build_explanation(finding, new_version, risk)
        )

    def _assess_risk(self, old_version: str, new_version: str) -> tuple[str, bool]:
        """Assess the risk of upgrading from old to new version."""
        if not new_version or new_version == "*":
            return "high", True

        old_parts = self._parse_version(old_version)
        new_parts = self._parse_version(new_version)

        if not old_parts or not new_parts:
            return "high", True

        # Major version change = breaking
        if new_parts[0] > old_parts[0]:
            return "high", True

        # Minor version change = might have breaking changes
        if new_parts[1] > old_parts[1]:
            return "medium", False

        # Patch version change = low risk
        return "low", False

    def _parse_version(self, version: str) -> Optional[tuple[int, ...]]:
        """Parse version string into tuple of ints."""
        match = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", version)
        if match:
            parts = []
            for g in match.groups():
                if g is not None:
                    parts.append(int(g))
                else:
                    parts.append(0)
            return tuple(parts) if parts else None
        return None

    def _detect_ecosystem(self, finding: VulnerabilityFinding) -> str:
        """Detect ecosystem from finding."""
        # Try from package name heuristics
        name = finding.package_name.lower()

        # Common Python packages
        python_packages = ["requests", "flask", "django", "numpy", "pandas", "pytest"]
        if any(p in name for p in python_packages):
            return "pypi"

        # Common npm packages (usually have slashes or scoped)
        if "/" in name or name.startswith("@"):
            return "npm"

        # Default to pypi
        return "pypi"

    def _build_upgrade_command(self, package: str, version: str, ecosystem: str) -> str:
        """Build the upgrade command."""
        if ecosystem == "npm":
            if version:
                return f"npm install {package}@{version}"
            return f"npm uninstall {package}"
        elif ecosystem == "pypi":
            if version:
                return f"pip install {package}=={version}"
            return f"# Consider removing {package} entirely"
        return f"# Update {package} to {version}"

    def _build_explanation(self, finding: VulnerabilityFinding, new_version: str, risk: str) -> str:
        """Build explanation for the fix."""
        lines = [
            f"## Vulnerability: {finding.cve_id}",
            "",
            f"**Package:** {finding.package_name}",
            f"**Current Version:** {finding.installed_version}",
            f"**Fixed Version:** {new_version or 'N/A'}",
            f"**Risk Level:** {risk.upper()}",
            "",
        ]

        if finding.description:
            lines.append(f"**Description:** {finding.description[:200]}...")
            lines.append("")

        if finding.cvss_score:
            lines.append(f"**CVSS Score:** {finding.cvss_score}")
            lines.append("")

        if risk == "high":
            lines.append("⚠️ **Warning:** This is a major version upgrade and may introduce breaking changes.")
            lines.append("Please review the changelog and run your test suite before merging.")
        elif risk == "medium":
            lines.append("ℹ️ **Note:** This is a minor version upgrade. Review the release notes for any deprecations.")
        else:
            lines.append("✅ This is a patch-level upgrade with minimal risk.")

        return "\n".join(lines)

    def _update_requirements_txt(self, content: str, package: str, new_version: str) -> str:
        """Update a requirements.txt style content."""
        lines = content.split("\n")
        updated = False

        for i, line in enumerate(lines):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Parse requirement line
            req_match = re.match(r"([a-zA-Z0-9_\-\.]+)([<>=!~]+)?(.*)", line)
            if req_match and req_match.group(1).lower() == package.lower():
                if new_version:
                    lines[i] = f"{req_match.group(1)}=={new_version}"
                else:
                    lines[i] = f"# REMOVED: {line}  # Vulnerable"
                updated = True
                break

        if not updated and new_version:
            lines.append(f"{package}=={new_version}")

        return "\n".join(lines)

    def _update_package_json(self, content: str, package: str, new_version: str) -> str:
        """Update a package.json style content."""
        import json

        try:
            data = json.loads(content)
            updated = False

            # Check dependencies
            for key in ["dependencies", "devDependencies"]:
                if key in data and package in data[key]:
                    if new_version:
                        data[key][package] = f"^{new_version}"
                    else:
                        del data[key][package]
                    updated = True
                    break

            if updated:
                return json.dumps(data, indent=2)
        except json.JSONDecodeError:
            pass

        return content

    async def remediate(
        self,
        findings: list[VulnerabilityFinding],
        dry_run: bool = False,
        min_severity: str = "low"
    ) -> list[RemediationResult]:
        """Create fix PRs for vulnerabilities."""
        results = []

        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        min_level = severity_order.get(min_severity, 0)

        for finding in findings:
            # Skip if below severity threshold
            severity = (finding.severity or "low").lower()
            if severity_order.get(severity, 0) < min_level:
                results.append(RemediationResult(
                    cve_id=finding.cve_id,
                    package_name=finding.package_name,
                    status="skipped",
                    message=f"Below severity threshold ({severity})"
                ))
                continue

            # Determine fix strategy
            strategy = self.determine_fix_strategy(finding)

            if not strategy:
                results.append(RemediationResult(
                    cve_id=finding.cve_id,
                    package_name=finding.package_name,
                    status="skipped",
                    message="No fix available"
                ))
                continue

            # Check if PR already exists
            branch_name = f"fix/{finding.cve_id}/{finding.package_name}"
            if self.github.pr_exists(branch_name, self.base_branch):
                results.append(RemediationResult(
                    cve_id=finding.cve_id,
                    package_name=finding.package_name,
                    status="skipped",
                    message="PR already exists for this fix"
                ))
                continue

            if dry_run:
                results.append(RemediationResult(
                    cve_id=finding.cve_id,
                    package_name=finding.package_name,
                    status="skipped",
                    message=f"[DRY RUN] Would create PR: {strategy.command}"
                ))
                continue

            # Create the branch
            branch = self.github.create_branch(branch_name, self.base_branch)
            if not branch:
                results.append(RemediationResult(
                    cve_id=finding.cve_id,
                    package_name=finding.package_name,
                    status="failed",
                    message="Failed to create branch"
                ))
                continue

            # Determine which file to update
            ecosystem = getattr(finding, 'ecosystem', None) or self._detect_ecosystem(finding)
            dep_file = "requirements.txt" if ecosystem == "pypi" else "package.json"

            # Get current content
            content = self.github.get_file_content(dep_file, self.base_branch)
            if not content:
                results.append(RemediationResult(
                    cve_id=finding.cve_id,
                    package_name=finding.package_name,
                    status="failed",
                    message=f"Could not read {dep_file}"
                ))
                continue

            # Update content
            if ecosystem == "pypi":
                new_content = self._update_requirements_txt(content, finding.package_name, strategy.new_version or "")
            else:
                new_content = self._update_package_json(content, finding.package_name, strategy.new_version or "")

            # Commit the change
            if not self.github.update_file(
                dep_file,
                new_content,
                f"fix: {finding.cve_id} - upgrade {finding.package_name}",
                branch_name
            ):
                results.append(RemediationResult(
                    cve_id=finding.cve_id,
                    package_name=finding.package_name,
                    status="failed",
                    message="Failed to update file"
                ))
                continue

            # Create PR
            pr_body = f"""# Fix {finding.cve_id}: {finding.package_name}

{strategy.explanation}

**Suggested Command:**
```bash
{strategy.command}
```

---
*Created by VulnScanner RemediationAgent*"""

            pr_url = self.github.create_pr(
                title=f"fix: {finding.cve_id} - upgrade {finding.package_name}",
                body=pr_body,
                head=branch_name,
                base=self.base_branch
            )

            if pr_url:
                results.append(RemediationResult(
                    cve_id=finding.cve_id,
                    package_name=finding.package_name,
                    status="created",
                    pr_url=pr_url,
                    fix_applied=strategy.command,
                    message=f"Created PR: {pr_url}"
                ))
            else:
                results.append(RemediationResult(
                    cve_id=finding.cve_id,
                    package_name=finding.package_name,
                    status="failed",
                    message="Failed to create PR"
                ))

        return results
