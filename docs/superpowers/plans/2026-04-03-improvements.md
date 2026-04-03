# VulnScanner Improvements Plan - 2026-04-03

## Overview
Implement 7 major improvements to the vuln-scanner Python project.

---

## Chunk 1: Async NVD Enrichment (Agent: async-dev)

### Files to Create
- `src/vuln_scanner/nvd/async_client.py` - Async NVD client with semaphore rate limiting
- `src/vuln_scanner/core/async_enricher.py` - Async enricher using asyncio
- `tests/unit/test_async_enricher.py` - Tests for async enricher

### Files to Modify
- `src/vuln_scanner/cli/main.py` - Add `--async` flag for async scanning

### Requirements
- Use `asyncio.Semaphore` for rate limiting (max 6 concurrent requests)
- Implement `AsyncNVDClient` with same interface as sync `NVDClient`
- `AsyncCVEEnricher.enrich_batch()` should process CVEs concurrently
- Target: 2x faster than sync for batch of 5+ CVEs

### Steps
1. Create `src/vuln_scanner/nvd/async_client.py` with `AsyncNVDClient`
2. Create `src/vuln_scanner/core/async_enricher.py` with `AsyncCVEEnricher`
3. Write tests in `tests/unit/test_async_enricher.py`
4. Modify CLI to add `--async` flag to `scan` and `enrich` commands
5. Verify tests pass

---

## Chunk 2: Expanded Test Coverage (Agent: test-dev)

### Files to Create
- `tests/fixtures/sample_sbom.json` - Sample SPDX SBOM
- `tests/fixtures/sample_trivy.json` - Sample Trivy scan result
- `tests/unit/test_nvd_client.py` - NVD parsing tests
- `tests/unit/test_sbom_scanner.py` - SBOM scanner tests
- `tests/unit/test_trivy_scanner.py` - Trivy scanner tests
- `tests/unit/test_enricher.py` - Enricher tests
- `tests/integration/test_scan_enrich_flow.py` - Integration test

### Requirements
- Use TDD approach - write tests before implementation
- All tests must use pytest fixtures
- Integration test should cover scan → enrich → format flow
- Target: 90%+ code coverage

### Steps
1. Create fixture files in `tests/fixtures/`
2. Write tests for NVD client parsing
3. Write tests for SBOM scanner
4. Write tests for Trivy scanner
5. Write tests for enricher
6. Write integration test
7. Verify all tests pass

---

## Chunk 3: Dashboard Scanning (Agent: dashboard-dev)

### Files to Modify
- `src/vuln_scanner/dashboard/server.py` - Add `/api/scan` endpoint
- `src/vuln_scanner/dashboard/templates/index.html` - Add scan tab

### Files to Create
- `src/vuln_scanner/dashboard/templates/scan.html` - Dependency visualization page

### Requirements
- Add `/api/scan` POST endpoint that accepts file upload
- Supports requirements.txt, package.json, SBOM, Trivy JSON
- Returns findings in same format as CLI
- Add "Scan" tab to dashboard UI

### Steps
1. Add `/api/scan` endpoint to `server.py`
2. Add scan tab to `index.html` dashboard
3. Create `scan.html` with dependency graph
4. Test endpoint with sample files

---

## Chunk 4: Dependency Graph (Agent: dashboard-dev)

### Files to Create
- `src/vuln_scanner/dashboard/templates/scan.html` - D3.js dependency visualization

### Requirements
- Display vulnerability findings as interactive node graph
- Nodes = packages, Edges = dependency relationships
- Node color = severity (critical=red, high=orange, medium=yellow, low=green)
- Click node to see CVE details
- Use D3.js force-directed graph

### Steps
1. Create `scan.html` with D3.js visualization
2. Add graph data endpoint to server
3. Make nodes interactive with tooltips
4. Test with sample scan data

---

## Chunk 5: SARIF Formatter (Agent: formatter-dev)

### Files to Create
- `src/vuln_scanner/formatters/sarif.py` - SARIF 2.1.0 formatter
- `tests/unit/test_sarif_formatter.py` - SARIF tests

### Files to Modify
- `src/vuln_scanner/cli/main.py` - Add `--format sarif` option

### Requirements
- Output must be valid SARIF 2.1.0 JSON
- Include run information, tool details
- Map severity: critical→error, high→error, medium→warning, low→note
- Include fix suggestion in markdown

### Steps
1. Create `src/vuln_scanner/formatters/sarif.py`
2. Write tests validating SARIF 2.1.0 schema
3. Add `--format sarif` to CLI
4. Validate output against SARIF schema

---

## Chunk 6: Structured Logging (Agent: formatter-dev)

### Files to Create
- `src/vuln_scanner/logging_config.py` - Centralized logging configuration

### Files to Modify
- Replace `print()` statements throughout codebase with proper logging

### Requirements
- Use Python `logging` module with structured output
- Log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
- Include context: request_id, cve_id, package_name where relevant
- Configurable via environment variable `VULN_SCANNER_LOG_LEVEL`

### Steps
1. Create `logging_config.py` with `setup_logging()`
2. Replace print statements in:
   - `src/vuln_scanner/nvd/client.py`
   - `src/vuln_scanner/core/enricher.py`
   - `src/vuln_scanner/cli/main.py`
   - `src/vuln_scanner/scanners/*.py`
3. Verify no print statements remain (except in CLI output)

---

## Chunk 7: Real SBOM/Trivy Support (Agent: test-dev)

### Files to Create
- `tests/fixtures/` with real-world sample files

### Requirements
- Support SPDX format (tag-value and JSON)
- Support CycloneDX format (JSON and XML)
- Support Trivy JSON output format v2
- Test parsing of real-world samples

### Steps
1. Create `tests/fixtures/sample_sbom_spdx.json`
2. Create `tests/fixtures/sample_sbom_cyclonedx.json`
3. Create `tests/fixtures/sample_trivy.json`
4. Ensure scanners handle real-world formats

---

## Success Criteria
- [ ] `pytest tests/ -v` passes 100%
- [ ] `ruff check src/` passes with no errors
- [ ] `mypy src/` passes with no errors
- [ ] All 4 commits created with meaningful messages
- [ ] Dashboard: upload JSON or scan files directly
- [ ] SARIF output valid against SARIF 2.1.0 schema
- [ ] Async enrichment completes 2x faster than sync for 5+ CVEs
