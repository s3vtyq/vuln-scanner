"""JSON formatter for vulnerability reports."""

import json
from typing import TextIO
from ..nvd.models import VulnerabilityFinding


class JSONFormatter:
    """Format findings as JSON."""

    def format(self, findings: list[VulnerabilityFinding], output: TextIO) -> None:
        """Write findings as JSON."""
        output_data = {
            "total": len(findings),
            "findings": [f.model_dump(mode="json") for f in findings]
        }
        json.dump(output_data, output, indent=2, default=str)
