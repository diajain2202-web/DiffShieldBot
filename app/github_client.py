"""
github_client.py - GitHub App REST client and offline test double.

Pure REST with only required endpoints. Generates RS256 App JWT,
exchanges for installation access tokens, and provides FakeGitHubClient
for 100% offline testing.
"""

from __future__ import annotations

import base64
import datetime
import logging
import time
from typing import Dict, Any, List, Optional

import httpx
import jwt

from engine.render import MARKER

logger = logging.getLogger("diffshield.github")


class GitHubClient:
    """Production GitHub App client using App JWT & installation tokens."""

    API_BASE = "https://api.github.com"

    def __init__(self, app_id: str, private_key: str, dry_run: bool = False):
        self.app_id = app_id
        self.private_key = private_key
        self.dry_run = dry_run
        self._installation_tokens: Dict[int, Tuple[str, float]] = {}

    def _generate_app_jwt(self) -> str:
        """Create a 10-minute RS256 JWT for GitHub App authentication."""
        now = int(time.time())
        payload = {
            "iat": now - 60,
            "exp": now + (10 * 60),
            "iss": self.app_id
        }
        return jwt.encode(payload, self.private_key, algorithm="RS256")

    async def get_installation_token(self, installation_id: int) -> str:
        """Fetch or return cached installation access token."""
        now = time.time()
        if installation_id in self._installation_tokens:
            token, expiry = self._installation_tokens[installation_id]
            if now < expiry - 60:
                return token

        jwt_token = self._generate_app_jwt()
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "DiffShield-App/1.0"
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.API_BASE}/app/installations/{installation_id}/access_tokens",
                headers=headers
            )
            resp.raise_for_status()
            data = resp.json()
            token = data["token"]
            self._installation_tokens[installation_id] = (token, now + 3600)
            return token

    async def _headers(self, installation_id: int, extra_accept: Optional[str] = None) -> Dict[str, str]:
        token = await self.get_installation_token(installation_id)
        accept = extra_accept or "application/vnd.github+json"
        return {
            "Authorization": f"token {token}",
            "Accept": accept,
            "User-Agent": "DiffShield-App/1.0"
        }

    async def get_pull_request_diff(self, repo: str, pr_number: int, installation_id: int) -> str:
        """Fetch raw unified diff for a pull request."""
        headers = await self._headers(installation_id, extra_accept="application/vnd.github.v3.diff")
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{self.API_BASE}/repos/{repo}/pulls/{pr_number}", headers=headers)
            resp.raise_for_status()
            return resp.text

    async def get_file_content(self, repo: str, path: str, ref: str, installation_id: int) -> Optional[str]:
        """Fetch file content at specific commit ref (used to read base .diffshield.yml)."""
        headers = await self._headers(installation_id)
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{self.API_BASE}/repos/{repo}/contents/{path}?ref={ref}", headers=headers)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data = resp.json()
            if data.get("encoding") == "base64" and "content" in data:
                return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
            return None

    async def post_or_update_comment(self, repo: str, pr_number: int, body: str, installation_id: int) -> Optional[int]:
        """
        Post or update in place a single rolling comment identified by MARKER.
        Prevents PR spam on multiple commits.
        """
        if self.dry_run:
            logger.info(f"[DRY RUN] Would post comment to {repo}#{pr_number}")
            return 999999

        headers = await self._headers(installation_id)
        async with httpx.AsyncClient() as client:
            # Check existing comments for marker
            resp = await client.get(f"{self.API_BASE}/repos/{repo}/issues/{pr_number}/comments", headers=headers)
            resp.raise_for_status()
            comments = resp.json()

            existing_id = None
            for c in comments:
                if MARKER in c.get("body", ""):
                    existing_id = c["id"]
                    break

            if existing_id is not None:
                # Update in place
                update_resp = await client.patch(
                    f"{self.API_BASE}/repos/{repo}/issues/comments/{existing_id}",
                    headers=headers,
                    json={"body": body}
                )
                update_resp.raise_for_status()
                return existing_id
            else:
                # Create new comment
                create_resp = await client.post(
                    f"{self.API_BASE}/repos/{repo}/issues/{pr_number}/comments",
                    headers=headers,
                    json={"body": body}
                )
                create_resp.raise_for_status()
                return create_resp.json().get("id")

    async def create_check_run(
        self,
        repo: str,
        head_sha: str,
        name: str,
        conclusion: str,
        output: Dict[str, Any],
        installation_id: int
    ) -> Optional[int]:
        """Create or complete a Check Run (diffshield/security)."""
        if self.dry_run:
            logger.info(f"[DRY RUN] Would create check run on {repo} @ {head_sha} with conclusion {conclusion}")
            return 888888

        headers = await self._headers(installation_id)
        payload = {
            "name": name,
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": conclusion,
            "completed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "output": output
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{self.API_BASE}/repos/{repo}/check-runs", headers=headers, json=payload)
            resp.raise_for_status()
            return resp.json().get("id")

    async def create_commit_status(
        self,
        repo: str,
        sha: str,
        state: str,  # success, failure, pending, error
        description: str,
        context: str,
        installation_id: int
    ) -> None:
        """Create a Commit Status context (for repos protecting branches with status checks)."""
        if self.dry_run:
            logger.info(f"[DRY RUN] Would create commit status on {repo} @ {sha}: {state}")
            return

        headers = await self._headers(installation_id)
        payload = {
            "state": state,
            "description": description[:140],
            "context": context
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{self.API_BASE}/repos/{repo}/statuses/{sha}", headers=headers, json=payload)
            resp.raise_for_status()

    async def add_label(self, repo: str, pr_number: int, label: str, installation_id: int) -> None:
        if self.dry_run:
            return
        headers = await self._headers(installation_id)
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{self.API_BASE}/repos/{repo}/issues/{pr_number}/labels",
                headers=headers,
                json={"labels": [label]}
            )

    async def remove_label(self, repo: str, pr_number: int, label: str, installation_id: int) -> None:
        if self.dry_run:
            return
        headers = await self._headers(installation_id)
        async with httpx.AsyncClient() as client:
            await client.delete(
                f"{self.API_BASE}/repos/{repo}/issues/{pr_number}/labels/{label}",
                headers=headers
            )

    async def close_pull_request(self, repo: str, pr_number: int, installation_id: int) -> None:
        if self.dry_run:
            return
        headers = await self._headers(installation_id)
        async with httpx.AsyncClient() as client:
            await client.patch(
                f"{self.API_BASE}/repos/{repo}/pulls/{pr_number}",
                headers=headers,
                json={"state": "closed"}
            )


class FakeGitHubClient:
    """
    In-memory GitHub client double for 100% offline test execution.
    Tracks comments, check runs, statuses, labels, and simulates base policy responses.
    """

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.comments: List[Dict[str, Any]] = []
        self.check_runs: List[Dict[str, Any]] = []
        self.statuses: List[Dict[str, Any]] = []
        self.labels: Dict[str, Set[str]] = {}  # "repo:pr" -> set of labels
        self.files: Dict[str, str] = {}  # "repo:path:ref" -> content
        self.diffs: Dict[str, str] = {}  # "repo:pr" -> diff
        self.pr_states: Dict[str, str] = {}  # "repo:pr" -> 'open' | 'closed'
        self._next_id = 1000

    async def get_pull_request_diff(self, repo: str, pr_number: int, installation_id: int) -> str:
        key = f"{repo}:{pr_number}"
        return self.diffs.get(key, "")

    async def get_file_content(self, repo: str, path: str, ref: str, installation_id: int) -> Optional[str]:
        key = f"{repo}:{path}:{ref}"
        return self.files.get(key, None)

    async def post_or_update_comment(self, repo: str, pr_number: int, body: str, installation_id: int) -> Optional[int]:
        if self.dry_run:
            return None

        # Check for existing comment with MARKER
        for c in self.comments:
            if c["repo"] == repo and c["pr_number"] == pr_number and MARKER in c["body"]:
                c["body"] = body
                c["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                return c["id"]

        self._next_id += 1
        cid = self._next_id
        self.comments.append({
            "id": cid,
            "repo": repo,
            "pr_number": pr_number,
            "body": body,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        })
        return cid

    async def create_check_run(
        self,
        repo: str,
        head_sha: str,
        name: str,
        conclusion: str,
        output: Dict[str, Any],
        installation_id: int
    ) -> Optional[int]:
        if self.dry_run:
            return None

        self._next_id += 1
        c_id = self._next_id
        self.check_runs.append({
            "id": c_id,
            "repo": repo,
            "head_sha": head_sha,
            "name": name,
            "conclusion": conclusion,
            "output": output
        })
        return c_id

    async def create_commit_status(
        self,
        repo: str,
        sha: str,
        state: str,
        description: str,
        context: str,
        installation_id: int
    ) -> None:
        if self.dry_run:
            return

        self.statuses.append({
            "repo": repo,
            "sha": sha,
            "state": state,
            "description": description,
            "context": context
        })

    async def add_label(self, repo: str, pr_number: int, label: str, installation_id: int) -> None:
        if self.dry_run:
            return
        key = f"{repo}:{pr_number}"
        if key not in self.labels:
            self.labels[key] = set()
        self.labels[key].add(label)

    async def remove_label(self, repo: str, pr_number: int, label: str, installation_id: int) -> None:
        if self.dry_run:
            return
        key = f"{repo}:{pr_number}"
        if key in self.labels:
            self.labels[key].discard(label)

    async def close_pull_request(self, repo: str, pr_number: int, installation_id: int) -> None:
        if self.dry_run:
            return
        key = f"{repo}:{pr_number}"
        self.pr_states[key] = "closed"

