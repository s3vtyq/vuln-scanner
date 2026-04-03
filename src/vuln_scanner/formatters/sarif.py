"""SARIF 2.1.0 formatter for vulnerability reports."""

import json
from typing import TextIO
from ..nvd.models import VulnerabilityFinding


class SARIFFormatter:
    """Format findings as SARIF 2.1.0 JSON."""

    def __init__(self):
        self._findings: list[VulnerabilityFinding] = []

    def format(self, findings: list[VulnerabilityFinding], output: TextIO) -> None:
        """Write findings as SARIF 2.1.0 JSON."""
        self._findings = findings
        sarif = self._build_sarif(findings)
        json.dump(sarif, output, indent=2)

    def _build_sarif(self, findings: list[VulnerabilityFinding]) -> dict:
        """Build SARIF document from findings."""
        return {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": self._build_tool(),
                    "results": [self._build_result(f) for f in findings],
                    "properties": {
                        "filename": "vuln-scanner"
                    }
                }
            ]
        }

    def _build_tool(self) -> dict:
        """Build SARIF tool driver."""
        return {
            "driver": {
                "name": "vuln-scanner",
                "version": "0.1.0",
                "informationUri": "https://github.com/example/vuln-scanner",
                "rules": self._build_rules()
            }
        }

    def _build_rules(self) -> dict:
        """Build SARIF rule definitions."""
        rules = {}
        for finding in self._unique_findings():
            rule_id = self._cve_to_rule_id(finding.cve_id)
            rules[rule_id] = {
                "id": rule_id,
                "name": finding.cve_id,
                "shortDescription": {
                    "text": f"Vulnerability in {finding.package_name}"
                },
                "fullDescription": {
                    "text": finding.description or f"Vulnerability {finding.cve_id} in {finding.package_name}"
                },
                "defaultConfiguration": {
                    "level": self._severity_to_level(finding.severity)
                },
                "properties": {
                    "tags": ["vulnerability", finding.severity.lower() if finding.severity else "unknown"]
                }
            }
        return rules

    def _build_result(self, finding: VulnerabilityFinding) -> dict:
        """Build SARIF result from finding."""
        rule_id = self._cve_to_rule_id(finding.cve_id)

        message_parts = [
            f"Package: {finding.package_name}@{finding.installed_version}",
            f"CVE: {finding.cve_id}",
        ]
        if finding.fixed_version:
            message_parts.append(f"Fixed version: {finding.fixed_version}")
        if finding.fix_suggestion:
            message_parts.append(f"\n\n## Fix Suggestion\n{self._markdown_code_block(finding.fix_suggestion)}")

        return {
            "ruleId": rule_id,
            "ruleIndex": 0,
            "level": self._severity_to_level(finding.severity),
            "message": {
                "text": "\n".join(message_parts)
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.package_name
                        },
                        "region": {
                            "startLine": 1
                        }
                    }
                }
            ],
            "properties": {
                "package_name": finding.package_name,
                "installed_version": finding.installed_version,
                "cvss_score": finding.cvss_score,
                "cvss_vector": finding.cvss_vector,
                "fixed_version": finding.fixed_version,
                "fix_suggestion": finding.fix_suggestion,
                "ai_confidence": finding.ai_confidence
            }
        }

    def _severity_to_level(self, severity: str | None) -> str:
        """Map severity to SARIF result level."""
        if severity is None:
            return "warning"
        severity = severity.upper()
        if severity in ("CRITICAL", "HIGH"):
            return "error"
        elif severity == "MEDIUM":
            return "warning"
        elif severity == "LOW":
            return "note"
        return "warning"

    def _cve_to_rule_id(self, cve_id: str) -> str:
        """Convert CVE ID to valid SARIF rule ID."""
        return cve_id.replace("-", "_").replace("CVE", "CVE")

    def _markdown_code_block(self, text: str) -> str:
        """Format text as markdown code block."""
        return f"```\n{text}\n```"

    def _unique_findings(self) -> list[VulnerabilityFinding]:
        """Return unique findings by CVE ID."""
        return list({f.cve_id: f for f in self._findings}.values())
