"""HTML formatter for vulnerability reports."""

from typing import TextIO
from datetime import datetime
from jinja2 import Template
from ..nvd.models import VulnerabilityFinding


HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Scan Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #eee; padding-bottom: 10px; }
        .summary { display: flex; gap: 20px; margin: 20px 0; }
        .stat { background: #f8f9fa; padding: 15px 25px; border-radius: 6px; text-align: center; }
        .stat-value { font-size: 2em; font-weight: bold; color: #333; }
        .stat-label { color: #666; font-size: 0.9em; }
        .critical { color: #dc3545; }
        .high { color: #fd7e14; }
        .medium { color: #ffc107; }
        .low { color: #28a745; }
        .severity-critical { background: #dc3545; color: white; padding: 2px 8px; border-radius: 3px; }
        .severity-high { background: #fd7e14; color: white; padding: 2px 8px; border-radius: 3px; }
        .severity-medium { background: #ffc107; color: black; padding: 2px 8px; border-radius: 3px; }
        .severity-low { background: #28a745; color: white; padding: 2px 8px; border-radius: 3px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { background: #f8f9fa; text-align: left; padding: 12px; border-bottom: 2px solid #dee2e6; }
        td { padding: 12px; border-bottom: 1px solid #dee2e6; vertical-align: top; }
        tr:hover { background: #f8f9fa; }
        .fix-suggestion { background: #e8f5e9; padding: 8px 12px; border-radius: 4px; margin-top: 5px; font-family: monospace; font-size: 0.9em; }
        .ai-badge { background: #7c4dff; color: white; padding: 1px 5px; border-radius: 3px; font-size: 0.7em; }
        .timestamp { color: #666; font-size: 0.9em; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Vulnerability Scan Report</h1>

        <div class="summary">
            <div class="stat">
                <div class="stat-value">{{ findings|length }}</div>
                <div class="stat-label">Total Vulnerabilities</div>
            </div>
            <div class="stat">
                <div class="stat-value critical">{{ critical_count }}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat">
                <div class="stat-value high">{{ high_count }}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat">
                <div class="stat-value medium">{{ medium_count }}</div>
                <div class="stat-label">Medium</div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Package</th>
                    <th>Version</th>
                    <th>CVE</th>
                    <th>Severity</th>
                    <th>CVSS</th>
                    <th>Description / Fix</th>
                </tr>
            </thead>
            <tbody>
                {% for f in findings %}
                <tr>
                    <td><strong>{{ f.package_name }}</strong></td>
                    <td>{{ f.installed_version }}</td>
                    <td><a href="https://nvd.nist.gov/vuln/detail/{{ f.cve_id }}" target="_blank">{{ f.cve_id }}</a></td>
                    <td>
                        <span class="severity-{{ f.severity|lower if f.severity else 'unknown' }}">
                            {{ f.severity or 'UNKNOWN' }}
                        </span>
                    </td>
                    <td>{{ f.cvss_score|default('N/A') }}</td>
                    <td>
                        <div>{{ f.description|truncate(150) if f.description else 'No description' }}</div>
                        {% if f.fix_suggestion %}
                        <div class="fix-suggestion">
                            {% if f.ai_confidence %} <span class="ai-badge">AI</span> {% endif %}
                            {{ f.fix_suggestion }}
                        </div>
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <div class="timestamp">
            Generated: {{ timestamp }}
        </div>
    </div>
</body>
</html>
"""


class HTMLFormatter:
    """Format findings as HTML report."""

    def __init__(self):
        self.template = Template(HTML_TEMPLATE)

    def format(self, findings: list[VulnerabilityFinding], output: TextIO) -> None:
        """Write findings as HTML report."""
        critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity == "HIGH")
        medium_count = sum(1 for f in findings if f.severity == "MEDIUM")

        html = self.template.render(
            findings=findings,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        output.write(html)
