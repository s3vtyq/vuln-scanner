"""GitHub client for creating branches and PRs."""

import subprocess
import os
from typing import Optional
from .models import BranchInfo


class GitHubClient:
    """GitHub API client using gh CLI."""

    def __init__(
        self,
        github_token: Optional[str] = None,
        owner: Optional[str] = None,
        repo: Optional[str] = None,
    ):
        self.token = github_token or os.getenv("GITHUB_TOKEN")
        self.owner = owner or self._get_repo_owner()
        self.repo = repo or self._get_repo_name()

    def _get_repo_owner(self) -> str:
        """Get repo owner from git remote."""
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode == 0:
            url = result.stdout.strip()
            if "github.com" in url:
                parts = url.split("/")
                if len(parts) >= 2:
                    return parts[-2] if parts[-1].endswith(".git") else parts[-1]
        return ""

    def _get_repo_name(self) -> str:
        """Get repo name from git remote."""
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode == 0:
            url = result.stdout.strip()
            if "github.com" in url:
                parts = url.split("/")
                if len(parts) >= 2:
                    name = parts[-1]
                    if name.endswith(".git"):
                        name = name[:-4]
                    return name
        return ""

    def _run_gh(self, args: list[str], input_str: Optional[str] = None) -> subprocess.CompletedProcess:
        """Run gh CLI command."""
        env = os.environ.copy()
        if self.token:
            env["GH_TOKEN"] = self.token

        return subprocess.run(
            ["gh"] + args,
            capture_output=True,
            text=True,
            input=input_str,
            env=env,
            check=False
        )

    def create_branch(self, branch_name: str, base_branch: str = "main") -> Optional[BranchInfo]:
        """Create a new branch."""
        # First get the SHA of the base branch
        result = self._run_gh(["api", f"repos/{self.owner}/{self.repo}/git/ref/heads/{base_branch}"])
        if result.returncode != 0:
            return None

        import json
        try:
            ref_data = json.loads(result.stdout)
            base_sha = ref_data["object"]["sha"]
        except (json.JSONDecodeError, KeyError):
            return None

        # Create the branch
        result = self._run_gh([
            "api",
            f"repos/{self.owner}/{self.repo}/git/refs",
            "-f", f"ref=refs/heads/{branch_name}",
            "-f", f"sha={base_sha}"
        ])

        if result.returncode == 0:
            return BranchInfo(name=branch_name, sha=base_sha)
        return None

    def get_file_content(self, path: str, branch: str = "main") -> Optional[str]:
        """Get file content from a branch."""
        result = self._run_gh([
            "api",
            f"repos/{self.owner}/{self.repo}/contents/{path}",
            "--ref", branch
        ])

        if result.returncode != 0:
            return None

        import json
        import base64
        try:
            data = json.loads(result.stdout)
            if "content" in data:
                return base64.b64decode(data["content"]).decode("utf-8")
        except (json.JSONDecodeError, KeyError, ValueError):
            pass
        return None

    def update_file(
        self,
        path: str,
        content: str,
        commit_message: str,
        branch: str
    ) -> bool:
        """Update a file on a branch."""
        # Get current file SHA if exists
        sha = None
        result = self._run_gh([
            "api",
            f"repos/{self.owner}/{self.repo}/contents/{path}",
            "--ref", branch
        ])

        if result.returncode == 0:
            import json
            try:
                data = json.loads(result.stdout)
                sha = data["sha"]
            except (json.JSONDecodeError, KeyError):
                pass

        # Create/update the file
        args = [
            "api",
            f"repos/{self.owner}/{self.repo}/contents/{path}",
            "-f", f"message={commit_message}",
            "-f", f"content={content}",
            "--method", "PUT" if sha else "POST",
            "-f", f"branch={branch}"
        ]

        if sha:
            args.extend(["-f", f"sha={sha}"])

        result = self._run_gh(args)
        return result.returncode == 0

    def create_pr(
        self,
        title: str,
        body: str,
        head: str,
        base: str = "main"
    ) -> Optional[str]:
        """Create a PR and return the URL."""
        result = self._run_gh([
            "pr", "create",
            "--title", title,
            "--body", body,
            "--head", head,
            "--base", base
        ])

        if result.returncode == 0:
            # Extract PR URL from output
            for line in result.stdout.split("\n"):
                if "https://github.com" in line:
                    return line.strip()
        return None

    def pr_exists(self, head: str, base: str = "main") -> bool:
        """Check if PR already exists for branch."""
        result = self._run_gh(["pr", "list", "--head", head, "--base", base, "--json", "number"])

        if result.returncode == 0:
            import json
            try:
                prs = json.loads(result.stdout)
                return len(prs) > 0
            except json.JSONDecodeError:
                pass
        return False

    def comment_on_pr(self, pr_number: int, comment: str) -> bool:
        """Add a comment to a PR."""
        result = self._run_gh([
            "api",
            f"repos/{self.owner}/{self.repo}/issues/{pr_number}/comments",
            "-f", f"body={comment}",
            "--method", "POST"
        ])
        return result.returncode == 0
