"""Tests for SARIF formatter."""

import json
import pytest
from io import StringIO
from vuln_scanner.formatters.sarif import SARIFFormatter
from vuln_scanner.nvd.models import VulnerabilityFinding


class TestSARIFFormatter:
    """Tests for SARIFFormatter class."""

    @pytest.fixture
    def formatter(self):
        """Create SARIF formatter instance."""
        return SARIFFormatter()

    @pytest.fixture
    def sample_findings(self):
        """Create sample vulnerability findings."""
        return [
            VulnerabilityFinding(
                package_name="requests",
                installed_version="2.28.0",
                cve_id="CVE-2024-1234",
                severity="HIGH",
                cvss_score=7.5,
                description="HTTP request smuggling vulnerability",
                fixed_version="<2.31.0",
                fix_suggestion="Upgrade to requests>=2.31.0",
            ),
            VulnerabilityFinding(
                package_name="lodash",
                installed_version="4.17.20",
                cve_id="CVE-2023-1234",
                severity="MEDIUM",
                cvss_score=5.3,
                description="Prototype pollution vulnerability",
                fixed_version="<4.17.21",
            ),
        ]

    def test_format_output_structure(self, formatter, sample_findings):
        """Test SARIF output has correct top-level structure."""
        output = StringIO()
        formatter.format(sample_findings, output)
        output.seek(0)

        sarif = json.load(output)

        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

    def test_format_tool_driver(self, formatter, sample_findings):
        """Test SARIF tool driver is correctly formatted."""
        output = StringIO()
        formatter.format(sample_findings, output)
        output.seek(0)

        sarif = json.load(output)
        tool = sarif["runs"][0]["tool"]

        assert "driver" in tool
        assert tool["driver"]["name"] == "vuln-scanner"
        assert tool["driver"]["version"] == "0.1.0"

    def test_format_results_count(self, formatter, sample_findings):
        """Test results array has correct number of entries."""
        output = StringIO()
        formatter.format(sample_findings, output)
        output.seek(0)

        sarif = json.load(output)
        results = sarif["runs"][0]["results"]

        assert len(results) == 2

    def test_severity_mapping_critical(self, formatter):
        """Test CRITICAL severity maps to error level."""
        findings = [
            VulnerabilityFinding(
                package_name="pkg",
                installed_version="1.0.0",
                cve_id="CVE-2024-1",
                severity="CRITICAL",
                cvss_score=9.8,
            )
        ]
        output = StringIO()
        formatter.format(findings, output)
        output.seek(0)

        sarif = json.load(output)
        result = sarif["runs"][0]["results"][0]

        assert result["level"] == "error"

    def test_severity_mapping_high(self, formatter):
        """Test HIGH severity maps to error level."""
        findings = [
            VulnerabilityFinding(
                package_name="pkg",
                installed_version="1.0.0",
                cve_id="CVE-2024-1",
                severity="HIGH",
                cvss_score=8.5,
            )
        ]
        output = StringIO()
        formatter.format(findings, output)
        output.seek(0)

        sarif = json.load(output)
        result = sarif["runs"][0]["results"][0]

        assert result["level"] == "error"

    def test_severity_mapping_medium(self, formatter):
        """Test MEDIUM severity maps to warning level."""
        findings = [
            VulnerabilityFinding(
                package_name="pkg",
                installed_version="1.0.0",
                cve_id="CVE-2024-1",
                severity="MEDIUM",
                cvss_score=5.0,
            )
        ]
        output = StringIO()
        formatter.format(findings, output)
        output.seek(0)

        sarif = json.load(output)
        result = sarif["runs"][0]["results"][0]

        assert result["level"] == "warning"

    def test_severity_mapping_low(self, formatter):
        """Test LOW severity maps to note level."""
        findings = [
            VulnerabilityFinding(
                package_name="pkg",
                installed_version="1.0.0",
                cve_id="CVE-2024-1",
                severity="LOW",
                cvss_score=2.0,
            )
        ]
        output = StringIO()
        formatter.format(findings, output)
        output.seek(0)

        sarif = json.load(output)
        result = sarif["runs"][0]["results"][0]

        assert result["level"] == "note"

    def test_severity_mapping_unknown(self, formatter):
        """Test unknown severity maps to warning level."""
        findings = [
            VulnerabilityFinding(
                package_name="pkg",
                installed_version="1.0.0",
                cve_id="CVE-2024-1",
                severity=None,
            )
        ]
        output = StringIO()
        formatter.format(findings, output)
        output.seek(0)

        sarif = json.load(output)
        result = sarif["runs"][0]["results"][0]

        assert result["level"] == "warning"

    def test_fix_suggestion_in_message(self, formatter):
        """Test fix_suggestion appears in result message."""
        findings = [
            VulnerabilityFinding(
                package_name="requests",
                installed_version="2.28.0",
                cve_id="CVE-2024-1234",
                severity="HIGH",
                cvss_score=7.5,
                fix_suggestion="Upgrade to requests>=2.31.0",
            )
        ]
        output = StringIO()
        formatter.format(findings, output)
        output.seek(0)

        sarif = json.load(output)
        message = sarif["runs"][0]["results"][0]["message"]["text"]

        assert "Upgrade to requests>=2.31.0" in message

    def test_fixed_version_in_message(self, formatter):
        """Test fixed_version appears in result message."""
        findings = [
            VulnerabilityFinding(
                package_name="requests",
                installed_version="2.28.0",
                cve_id="CVE-2024-1234",
                severity="HIGH",
                cvss_score=7.5,
                fixed_version="<2.31.0",
            )
        ]
        output = StringIO()
        formatter.format(findings, output)
        output.seek(0)

        sarif = json.load(output)
        message = sarif["runs"][0]["results"][0]["message"]["text"]

        assert "<2.31.0" in message

    def test_result_contains_properties(self, formatter):
        """Test result includes properties for additional data."""
        findings = [
            VulnerabilityFinding(
                package_name="requests",
                installed_version="2.28.0",
                cve_id="CVE-2024-1234",
                severity="HIGH",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                ai_confidence=0.95,
            )
        ]
        output = StringIO()
        formatter.format(findings, output)
        output.seek(0)

        sarif = json.load(output)
        props = sarif["runs"][0]["results"][0]["properties"]

        assert props["package_name"] == "requests"
        assert props["installed_version"] == "2.28.0"
        assert props["cvss_score"] == 7.5
        assert props["ai_confidence"] == 0.95
