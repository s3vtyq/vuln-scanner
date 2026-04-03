"""Dashboard web server for vuln-scanner."""

from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn


app = FastAPI(title="VulnScanner Dashboard")

# Paths
BASE_DIR = Path(__file__).parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

# Mount static files
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Serve the main dashboard page."""
    return templates.TemplateResponse("index.html", {"request": request})


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
        import json
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


def run_server(host: str = "127.0.0.1", port: int = 8000):
    """Run the dashboard server."""
    uvicorn.run(app, host=host, port=port)
