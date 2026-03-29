# VulnScanner

**A production-ready vulnerability scanner wrapper with NVD API integration and AI-powered fix suggestions.**

[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## Overview

VulnScanner bridges the gap between raw vulnerability data and actionable security insights. It scans dependency files (requirements.txt, package.json, SBOMs), enriches findings with real CVE data from the National Vulnerability Database (NVD), and generates intelligent fix recommendations powered by AI.

### Key Capabilities

| Feature | Description |
|---------|-------------|
| **Multi-format scanning** | requirements.txt, package.json, SPDX/CycloneDX SBOMs, Trivy output |
| **NVD API integration** | Real-time CVE lookup with CVSS scores, severity ratings, and references |
| **Smart caching** | SQLite-based caching reduces API calls and improves performance |
| **AI fix suggestions** | Contextual remediation recommendations via MiniMax AI API |
| **Multiple outputs** | JSON, CSV, and styled HTML reports |
| **CI/CD ready** | SARIF format for GitHub Advanced Security integration |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                            CLI                                   │
│                    (Click + Rich tables)                         │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │  Scanners   │───▶│  Enricher   │───▶│     Formatters      │  │
│  │  (Adapter)  │    │  (NVD data)  │    │ (JSON/CSV/HTML)     │  │
│  └─────────────┘    └─────────────┘    └─────────────────────┘  │
│                            │                                     │
│                            ▼                                     │
│                    ┌─────────────────┐                          │
│                    │  Fix Suggester  │                          │
│                    │  (AI + NVD +    │                          │
│                    │   Package Mgr)   │                          │
│                    └─────────────────┘                          │
├─────────────────────────────────────────────────────────────────┤
│         ┌─────────────────┐         ┌─────────────────────────┐ │
│         │   NVD API v2   │         │     MiniMax AI API       │ │
│         │ (Rate limited, │         │ (Fix suggestions)       │ │
│         │   cached)      │         │                         │ │
│         └─────────────────┘         └─────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Design Patterns

- **Adapter Pattern**: Scanner implementations are swappable (requirements.txt, package.json, SBOM, Trivy)
- **Registry Pattern**: New scanners self-register via `ScannerRegistry`
- **Strategy Pattern**: Multiple formatters with a common interface
- **Fallback Chain**: Fix suggestions cascade from NVD data → Package manager → AI

---

## Installation

### Prerequisites

- Python 3.11 or higher
- pip or uv

### Quick Install

```bash
pip install -e .
```

### Development Install

```bash
pip install -e ".[dev]"
```

---

## Quick Start

### Scan a requirements file

```bash
vuln-scanner scan -i requirements.txt
```

**Output:**
```
Scanning requirements.txt...
Using scanner: requirements
Found 3 packages
┏━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Package  ┃ Version ┃ CVE           ┃ Severity ┃ CVSS ┃ Fix                   ┃
┡━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━┩
│ requests │ 2.28.0  │ CVE-2024-0001 │ HIGH     │  7.5 │ Run: pip install      │
│          │         │               │          │      │ requests==2.33.0...    │
└──────────┴─────────┴───────────────┴──────────┴──────┴───────────────────────┘
```

### Generate an HTML report

```bash
vuln-scanner scan -i requirements.txt --format html -o report.html
```

### Enable AI-powered fix suggestions

```bash
export MINIMAX_API_KEY="your-api-key"
vuln-scanner scan -i requirements.txt --ai-fix
```

### Enrich existing Trivy scan results

```bash
# First, run Trivy
trivy image myapp:latest -f json > trivy-results.json

# Then enrich with NVD data and fixes
vuln-scanner enrich -i trivy-results.json --format html -o enriched-report.html
```

### Monitor packages for new CVEs

```bash
vuln-scanner monitor -i requirements.txt
```

---

## Usage

### CLI Commands

| Command | Description |
|---------|-------------|
| `scan` | Scan a dependency file for vulnerabilities |
| `enrich` | Enrich existing scan results with NVD data |
| `monitor` | Watch for new CVE disclosures affecting your packages |

### Command Options

#### `scan` Command

```
-vuln-scanner scan [OPTIONS]

Options:
  -i, --input PATH        Input file to scan (required)
  -o, --output PATH       Output file (default: stdout)
  -f, --format [json|csv|html]  Output format (default: json)
  --ai-fix                Enable AI-powered fix suggestions
```

#### `enrich` Command

```
vuln-scanner enrich [OPTIONS]

Options:
  -i, --input PATH        Input file with scan results (required)
  -o, --output PATH       Output file (default: stdout)
  -f, --format [json|csv|html]  Output format (default: json)
  --ai-fix                Enable AI-powered fix suggestions
```

#### `monitor` Command

```
vuln-scanner monitor [OPTIONS]

Options:
  -i, --input PATH        Input file to watch (required)
  --watch                 Poll daily for new CVEs
```

---

## Supported Input Formats

| Format | File Examples | Description |
|--------|---------------|-------------|
| **requirements.txt** | `requirements.txt`, `requirements-dev.txt` | Python pip dependencies |
| **package.json** | `package.json` | Node.js npm dependencies |
| **SBOM (SPDX)** | `sbom.spdx.json` | SPDX Software Bill of Materials |
| **SBOM (CycloneDX)** | `bom.json`, `bom.cdx.json` | CycloneDX Software Bill of Materials |
| **Trivy JSON** | `trivy-results.json` | Trivy vulnerability scan output |

---

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `MINIMAX_API_KEY` | API key for MiniMax AI fix suggestions | No (AI features disabled without) |
| `NVD_API_KEY` | API key for NVD (higher rate limits: 6 req/min vs 50/day) | No |

### Rate Limits

| API | Without Key | With Key |
|-----|-------------|----------|
| NVD API v2 | 50 requests/day | 6 requests/minute |
| MiniMax AI | N/A | Varies by plan |

---

## Project Structure

```
vuln-scanner/
├── src/vuln_scanner/
│   ├── __init__.py              # Package entry
│   ├── cli/
│   │   └── main.py              # Click CLI commands
│   ├── core/
│   │   └── enricher.py          # CVE enrichment logic
│   ├── nvd/
│   │   ├── client.py            # NVD API v2 client
│   │   ├── models.py            # CVE/CPE/Package dataclasses
│   │   └── cache.py             # SQLite caching layer
│   ├── scanners/
│   │   ├── base.py              # Scanner protocol & registry
│   │   ├── requirements.py      # Python requirements.txt
│   │   ├── package_json.py      # npm package.json
│   │   ├── sbom.py              # SPDX/CycloneDX SBOM
│   │   └── trivy.py             # Trivy JSON enrichment
│   ├── formatters/
│   │   ├── json.py              # JSON output
│   │   ├── csv.py               # CSV output
│   │   └── html.py              # HTML report with styling
│   └── fix_suggester/
│       ├── suggester.py         # Orchestrator
│       ├── nvd_fixes.py         # NVD configuration extraction
│       ├── package_fixes.py     # PyPI/npm version lookup
│       └── ai_suggester.py       # MiniMax AI integration
├── tests/
│   ├── unit/                    # Unit tests
│   └── integration/             # Integration tests
├── pyproject.toml               # Project configuration
└── README.md
```

---

## Development

### Run Tests

```bash
pytest tests/ -v
```

### Run with Coverage

```bash
pytest tests/ --cov=vuln_scanner --cov-report=html
```

### Lint Code

```bash
ruff check src/
```

### Type Check

```bash
mypy src/
```

---

## How It Works

### 1. Scanning

The scanner registry detects the input format and delegates to the appropriate scanner adapter:

```python
registry = get_registry()
scanner = registry.get_scanner("requirements.txt")
packages = scanner.scan("requirements.txt")
```

### 2. Enrichment

Each package is looked up against the NVD API to find associated CVEs:

```python
enricher = CVEEnricher()
for finding in findings:
    finding = enricher.enrich(finding)
```

### 3. Fix Suggestion

Fix suggestions follow a priority chain:

1. **NVD Configuration Data**: Extracts fix versions from `vulnConfigurations`
2. **Package Manager**: Queries PyPI/npm for the latest patched version
3. **AI (Optional)**: MiniMax API generates contextual remediation advice

---

## API Integration Examples

### NVD API Query

```python
from vuln_scanner.nvd import NVDClient

client = NVDClient(api_key="your-nvd-key")
cve = client.get_cve("CVE-2024-1234")
print(f"Severity: {cve.get_cvss_score().severity}")
```

### Using as a Library

```python
from vuln_scanner.scanners import get_registry
from vuln_scanner.core.enricher import CVEEnricher

# Find appropriate scanner
registry = get_registry()
scanner = registry.get_scanner("package.json")

# Scan and enrich
packages = scanner.scan("package.json")
enricher = CVEEnricher()
findings = enricher.enrich_batch([...])
```

---

## Configuration Files

### pyproject.toml

```toml
[project]
name = "vuln-scanner"
version = "0.1.0"
requires-python = ">=3.11"

[project.scripts]
vuln-scanner = "vuln_scanner.cli.main:cli"
```

---

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

---

## License

MIT License - see [LICENSE](LICENSE) for details.
