"""Data models for the RemediationAgent."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class FixStrategy:
    """Represents how a vulnerability can be fixed."""
    action: str  # "upgrade", "remove", "patch"
    new_version: Optional[str]
    command: str
    risk_level: str  # "low", "medium", "high"
    breaking_change: bool
    explanation: str


@dataclass
class RemediationResult:
    """Result of attempting to remediate a vulnerability."""
    cve_id: str
    package_name: str
    status: str  # "created", "skipped", "failed"
    pr_url: Optional[str] = None
    fix_applied: Optional[str] = None
    message: str = ""


@dataclass
class BranchInfo:
    """Information about a created branch."""
    name: str
    sha: str
