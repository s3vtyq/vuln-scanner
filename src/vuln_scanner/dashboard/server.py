"""Dashboard web server for vuln-scanner."""

import json
import tempfile
from pathlib import Path

from fastapi import FastAPI, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
import uvicorn

from ..scanners import register_all_scanners, get_registry
from ..nvd.models import VulnerabilityFinding
from ..core.enricher import CVEEnricher
from ..nvd.client import NVDClient


app = FastAPI(title="VulnScanner Dashboard")

# Initialize scanners on startup
register_all_scanners()

BASE_DIR = Path(__file__).parent.resolve()
INDEX_HTML = BASE_DIR / "templates" / "index.html"
SCAN_HTML = BASE_DIR / "templates" / "scan.html"
STATIC_DIR = BASE_DIR / "static"


@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the main dashboard page."""
    return FileResponse(str(INDEX_HTML))


@app.post("/api/upload")
async def upload_scan(file: UploadFile = File(...)) -> JSONResponse:
    """
    Upload and parse scan results JSON.

    Expected format:
    {
      "findings": [
        {
          "package_name": "requests",
          "installed_version": "2.28.0",
          "cve_id": "CVE-2024-1234",
          "severity": "HIGH",
          "cvss_score": 7.5,
          "description": "...",
          "fix_suggestion": "..."
        }
      ]
    }
    """
    if not file.filename.endswith(".json"):
        return JSONResponse(
            {"error": "Only JSON files are supported"},
            status_code=400
        )

    try:
        contents = await file.read()
        data = json.loads(contents)

        findings = data.get("findings", [])
        if not isinstance(findings, list):
            return JSONResponse(
                {"error": "Invalid format: 'findings' must be an array"},
                status_code=400
            )

        # Calculate summary
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        for f in findings:
            severity = (f.get("severity") or "UNKNOWN").lower()
            if severity in summary:
                summary[severity] += 1
            else:
                summary["unknown"] += 1

        return JSONResponse({
            "success": True,
            "total": len(findings),
            "summary": summary,
            "findings": findings
        })

    except json.JSONDecodeError:
        return JSONResponse(
            {"error": "Invalid JSON file"},
            status_code=400
        )
    except Exception as e:
        return JSONResponse(
            {"error": str(e)},
            status_code=500
        )


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok"}


@app.post("/api/scan")
async def scan_file(file: UploadFile = File(...)) -> JSONResponse:
    """
    Scan a dependency file directly.

    Supports: requirements.txt, package.json, SBOM (SPDX/CycloneDX), Trivy JSON
    """
    # Determine file type from filename
    filename = file.filename or ""

    try:
        # Read uploaded file
        contents = await file.read()

        # Create temp file for scanner
        with tempfile.NamedTemporaryFile(mode='wb', suffix=filename, delete=False) as tmp:
            tmp.write(contents)
            tmp_path = tmp.name

        try:
            # Get scanner for file
            registry = get_registry()
            scanner = registry.get_scanner(tmp_path)

            if not scanner:
                return JSONResponse(
                    {"error": f"No scanner found for {filename}"},
                    status_code=400
                )

            # Scan packages
            packages = scanner.scan(tmp_path)

            # Create initial findings
            findings = []
            for package in packages:
                finding = VulnerabilityFinding(
                    package_name=package.name,
                    installed_version=package.version,
                    cve_id=f"CVE-TEMP-{package.name}",
                    cpe=package.cpe,
                    description=f"Scanned {package.name}@{package.version}",
                    severity="UNKNOWN",
                    cvss_score=None,
                )
                findings.append(finding)

            # Enrich with NVD
            nvd_client = NVDClient()
            enricher = CVEEnricher(nvd_client)
            enriched = enricher.enrich_batch(findings)

            # Calculate summary
            summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
            for f in enriched:
                severity = (f.severity or "UNKNOWN").lower()
                if severity in summary:
                    summary[severity] += 1
                else:
                    summary["unknown"] += 1

            return JSONResponse({
                "success": True,
                "total": len(enriched),
                "scanner": scanner.name,
                "packages_found": len(packages),
                "summary": summary,
                "findings": [f.model_dump(mode="json") for f in enriched]
            })

        finally:
            import os
            os.unlink(tmp_path)

    except Exception as e:
        return JSONResponse(
            {"error": str(e)},
            status_code=500
        )


@app.get("/api/graph/{scan_id}")
async def get_dependency_graph(scan_id: str):
    """Get dependency graph data for a scan."""
    # In a real implementation, this would fetch from a database
    # For now, return placeholder
    return JSONResponse({
        "nodes": [],
        "edges": []
    })


@app.get("/scan")
async def scan_page():
    """Serve the dependency graph scan page."""
    return FileResponse(str(SCAN_HTML))


@app.get("/static/{path:str}")
async def static_files(path: str):
    """Serve static files."""
    file_path = STATIC_DIR / path
    if file_path.exists():
        return FileResponse(str(file_path))
    return JSONResponse({"error": "Not found"}, status_code=404)


def run_server(host: str = "127.0.0.1", port: int = 8000):
    """Run the dashboard server."""
    uvicorn.run(app, host=host, port=port)
