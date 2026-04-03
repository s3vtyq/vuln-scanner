# VulnScanner

<p align="center">
  <strong>Production-ready vulnerability scanner with NVD API integration, AI fix suggestions, and web dashboard</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/tests-47%20passed-success.svg" alt="Tests">
</p>

---

## Overview

VulnScanner bridges the gap between raw vulnerability data and actionable security insights. It scans dependency files, enriches findings with real CVE data from the National Vulnerability Database, and generates intelligent fix recommendations powered by AI.

## Features

| Capability | Description |
|:-----------|:-----------|
| **Multi-format Scanning** | requirements.txt, package.json, SPDX/CycloneDX SBOMs, Trivy output |
| **NVD API Integration** | Real-time CVE lookup with CVSS scores, severity ratings, and references |
| **Smart Caching** | SQLite-based caching reduces API calls and improves performance |
| **AI Fix Suggestions** | Contextual remediation via OpenAI, Claude, Gemini, Ollama, or MiniMax |
| **Multiple Outputs** | JSON, CSV, HTML, and SARIF formats |
| **CI/CD Ready** | SARIF output for GitHub Advanced Security integration |
| **Web Dashboard** | Modern UI with dependency visualization |
| **Async Enrichment** | Concurrent NVD lookups for faster batch processing |

---

## Quick Start

### Installation

```bash
pip install -e .
```

### Scan Dependencies

```bash
vuln-scanner scan -i requirements.txt
```

```
Scanning requirements.txt...
Using scanner: requirements
Found 3 packages

┏━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Package  ┃ Version ┃ CVE           ┃ Severity ┃ CVSS ┃ Fix                   ┃
┡━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━┩
│ requests │ 2.28.0  │ CVE-2024-0001 │ HIGH     │  7.5 │ Upgrade to 2.33.0     │
│ lodash   │ 4.17.20 │ CVE-2023-44487│ HIGH     │  7.5 │ Upgrade to 4.17.21   │
│ express  │ 4.18.2  │ CVE-2023-26115│ MEDIUM   │  5.3 │ Upgrade to 4.19.0    │
└──────────┴─────────┴───────────────┴──────────┴──────┴───────────────────────┘
```

### Generate HTML Report

```bash
vuln-scanner scan -i requirements.txt --format html -o report.html
```

### Enable AI Fix Suggestions

```bash
export OPENAI_API_KEY="your-key"    # or ANTHROPIC_API_KEY, GEMINI_API_KEY, etc.
vuln-scanner scan -i requirements.txt --ai-fix --ai-provider openai
```

### View Dashboard

```bash
vuln-scanner dashboard
# Open http://localhost:8000
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                              CLI                                       │
│                    (Click + Rich tables)                               │
├──────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────────┐   │
│  │  Scanners   │───▶│  Enricher   │───▶│     Formatters          │   │
│  │  (Adapter)  │    │  (NVD data) │    │ (JSON/CSV/HTML/SARIF)   │   │
│  └─────────────┘    └─────────────┘    └─────────────────────────┘   │
│                            │                                          │
│                            ▼                                          │
│                    ┌─────────────────┐                                │
│                    │  Fix Suggester  │                                │
│                    │  (AI + NVD +   │                                │
│                    │   Package Mgr)  │                                │
│                    └─────────────────┘                                │
├──────────────────────────────────────────────────────────────────────┤
│         ┌─────────────────┐         ┌─────────────────────────────┐   │
│         │   NVD API v2   │         │   AI Providers              │   │
│         │ (Rate limited, │         │ (Fix suggestions)           │   │
│         │   cached)      │         │ OpenAI/Claude/Gemini/       │   │
│         └─────────────────┘         │ Ollama/MiniMax              │   │
│                                     └─────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────┘
```

### Design Patterns

- **Adapter Pattern**: Scanner implementations are swappable
- **Registry Pattern**: New scanners self-register via `ScannerRegistry`
- **Strategy Pattern**: Multiple formatters with a common interface
- **Fallback Chain**: Fix suggestions cascade NVD → Package Manager → AI

---

## Supported Input Formats

| Format | Files | Ecosystem |
|:-------|:------|:----------|
| **requirements.txt** | `requirements*.txt` | Python |
| **package.json** | `package.json` | Node.js |
| **SBOM SPDX** | `*.spdx.json` | Multi |
| **SBOM CycloneDX** | `bom.json`, `*.cdx.json` | Multi |
| **Trivy JSON** | `trivy*.json` | Multi |

---

## CLI Commands

| Command | Description |
|:--------|:------------|
| `scan` | Scan a dependency file for vulnerabilities |
| `enrich` | Enrich existing scan results with NVD data |
| `monitor` | Watch for new CVE disclosures |
| `dashboard` | Start web dashboard |

### Scan Command

```bash
vuln-scanner scan [OPTIONS]

Options:
  -i, --input PATH                      Input file to scan (required)
  -o, --output PATH                     Output file (default: stdout)
  -f, --format [json|csv|html|sarif]  Output format (default: json)
  --ai-fix                              Enable AI fix suggestions
  --ai-provider [minimax|openai|anthropic|gemini|ollama]
                                        AI provider
  --async                               Use async NVD enrichment
```

---

## GitHub Actions Integration

```yaml
name: Vulnerability Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  vuln-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -e .
      - run: vuln-scanner scan -i requirements.txt -f sarif -o results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## Environment Variables

### AI Providers

| Variable | Provider |
|:---------|:---------|
| `OPENAI_API_KEY` | OpenAI |
| `ANTHROPIC_API_KEY` | Anthropic Claude |
| `GEMINI_API_KEY` | Google Gemini |
| `MINIMAX_API_KEY` | MiniMax |
| `OLLAMA_BASE_URL` | Ollama (default: `http://localhost:11434`) |

### NVD API

| Variable | Description | Default |
|:---------|:------------|:--------|
| `NVD_API_KEY` | Higher rate limits (6 req/min vs 50/day) | Optional |

---

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Lint
ruff check src/

# Type check
mypy src/
```

---

## Project Structure

```
vuln-scanner/
├── src/vuln_scanner/
│   ├── cli/main.py                 # CLI entry point
│   ├── core/
│   │   ├── enricher.py            # CVE enrichment
│   │   └── async_enricher.py      # Async enrichment
│   ├── nvd/
│   │   ├── client.py              # NVD API v2 client
│   │   ├── async_client.py        # Async NVD client
│   │   ├── models.py              # Data models
│   │   └── cache.py               # SQLite caching
│   ├── scanners/
│   │   ├── base.py                # Scanner protocol
│   │   ├── requirements.py        # Python
│   │   ├── package_json.py        # npm
│   │   ├── sbom.py               # SPDX/CycloneDX
│   │   └── trivy.py              # Trivy
│   ├── formatters/
│   │   ├── json.py, csv.py, html.py, sarif.py
│   ├── dashboard/
│   │   ├── server.py              # FastAPI
│   │   └── templates/             # HTML UI
│   └── fix_suggester/             # AI suggestions
├── tests/
│   ├── unit/                      # Unit tests
│   ├── integration/               # Integration tests
│   └── fixtures/                  # Test data
├── .github/workflows/             # CI/CD
└── pyproject.toml
```

---

## License

MIT License - see [LICENSE](LICENSE)
