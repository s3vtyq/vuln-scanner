"""Dashboard web server for vuln-scanner."""

import json
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
import uvicorn


app = FastAPI(title="VulnScanner Dashboard")

BASE_DIR = Path(__file__).parent.resolve()
INDEX_HTML = BASE_DIR / "templates" / "index.html"
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
