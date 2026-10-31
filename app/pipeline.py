"""
pipeline.py - Orchestration of GitHub events, analysis, holds, and commands.

Enforces:
- Base-branch trust boundary for .diffshield.yml
- Strict idempotency on (repo, pr_number, head_sha)
- Rolling in-place comments and dual check-run + commit-status reporting
- Maintainer command channel (/diffshield release, override, recheck)
- Quarantine expiration re-analysis loop
"""

from __future__ import annotations

import logging
from typing import Dict, Any, Optional, Union

from app.config import RepoPolicy, Settings
from app.github_client import GitHubClient, FakeGitHubClient
from app.store import Store, HoldRow
from engine.analyse import analyse_pr, Report
from engine.render import render_check_run

logger = logging.getLogger("diffshield.pipeline")

ClientType = Union[GitHubClient, FakeGitHubClient]

AUTHORIZED_ROLES = {"OWNER", "MEMBER", "COLLABORATOR"}


class Pipeline:
    """Coordinates incoming GitHub events with deterministic analysis and storage."""

    def __init__(self, store: Store, github_client: ClientType, settings: Optional[Settings] = None):
        self.store = store
        self.client = github_client
        self.settings = settings or Settings()

    async def handle_pull_request_event(self, payload: Dict[str, Any]) -> Optional[Report]:
        """
        Process PR actions: opened, synchronize, reopened, ready_for_review, edited, closed.
        """
        action = payload.get("action", "")
        pr = payload.get("pull_request", {})
        repo_data = payload.get("repository", {})
        repo = repo_data.get("full_name", "")
        pr_number = pr.get("number", 0)
        installation_id = payload.get("installation", {}).get("id", 0)

        if not repo or not pr_number:
            return None

        # If PR was closed, release any active hold
        if action == "closed":
            open_hold = self.store.get_open_hold(repo, pr_number)
            if open_hold:
                self.store.release_hold(open_hold.id, actor="github", kind="closed")
                self.store.record_audit(repo, pr_number, "diffshield", "hold-closed", "PR closed on GitHub")
            return None

        if action not in ("opened", "synchronize", "reopened", "ready_for_review", "edited"):
            return None

        head_sha = pr.get("head", {}).get("sha", "")
        base_sha = pr.get("base", {}).get("sha", "")
        pr_title = pr.get("title", "")

        # 1. Trust boundary: Fetch .diffshield.yml from BASE commit ref
        policy_yaml = await self.client.get_file_content(repo, ".diffshield.yml", ref=base_sha, installation_id=installation_id)
        policy = RepoPolicy.from_yaml(policy_yaml)

        # 2. Fetch raw unified diff
        raw_diff = await self.client.get_pull_request_diff(repo, pr_number, installation_id)

        # 3. Execute deterministic multi-layer analysis
        report = analyse_pr(
            raw_diff=raw_diff,
            repo=repo,
            pr_number=pr_number,
            head_sha=head_sha,
            title=pr_title,
            enforcement=policy.enforcement,
            hold_hours=policy.hold_hours,
            ignore_patterns=policy.ignore_paths
        )

        # 4. Save canonical report in SQLite
        self.store.upsert_report(repo, pr_number, head_sha, report.decision, report.score, report.to_dict())

        # 5. Post or update rolling PR comment (idempotent via marker)
        comment_id = await self.client.post_or_update_comment(repo, pr_number, report.markdown_comment, installation_id)

        # 6. Create Check Run & Commit Status
        check_run_payload = render_check_run(report.to_dict())
        check_run_id = await self.client.create_check_run(
            repo=repo,
            head_sha=head_sha,
            name="diffshield/security",
            conclusion=check_run_payload["conclusion"],
            output=check_run_payload["output"],
            installation_id=installation_id
        )

        status_state = "failure" if report.decision == "quarantine" else "success"
        status_desc = f"DiffShield: {report.decision.upper()} ({report.score}/100 {report.band.upper()})"
        await self.client.create_commit_status(
            repo=repo,
            sha=head_sha,
            state=status_state,
            description=status_desc,
            context="diffshield/security",
            installation_id=installation_id
        )

        # 7. Apply quarantine hold and label
        if report.decision == "quarantine":
            await self.client.add_label(repo, pr_number, "diffshield:quarantine", installation_id)
            self.store.upsert_hold(
                repo=repo,
                pr_number=pr_number,
                installation=installation_id,
                head_sha=head_sha,
                decision=report.decision,
                score=report.score,
                band=report.band,
                reason=f"Flagged with score {report.score}/100",
                hold_hours=report.hold_hours,
                comment_id=comment_id,
                check_run_id=check_run_id
            )
            self.store.record_audit(
                repo, pr_number, "diffshield", "quarantine-hold",
                f"Quarantine scheduled for {report.hold_hours}h @ {head_sha}"
            )

            # If policy explicitly requests closing PR
            if policy.enforcement == "close":
                await self.client.close_pull_request(repo, pr_number, installation_id)
                self.store.record_audit(repo, pr_number, "diffshield", "pr-closed", "PR closed per policy")
        else:
            # PR passed: remove quarantine label if present
            await self.client.remove_label(repo, pr_number, "diffshield:quarantine", installation_id)
            open_hold = self.store.get_open_hold(repo, pr_number)
            if open_hold:
                self.store.release_hold(open_hold.id, actor="diffshield", kind="auto")
                self.store.record_audit(repo, pr_number, "diffshield", "hold-released", "Clean PR released hold")

        return report

    async def handle_comment_command(self, payload: Dict[str, Any]) -> Optional[str]:
        """
        Process maintainer command channel:
          /diffshield release <reason>
          /diffshield override <reason>
          /diffshield recheck
        Restricted to OWNER, MEMBER, COLLABORATOR.
        """
        comment = payload.get("comment", {})
        body = comment.get("body", "").strip()
        if not body.startswith("/diffshield"):
            return None

        repo = payload.get("repository", {}).get("full_name", "")
        issue = payload.get("issue", {})
        pr_number = issue.get("number", 0)
        installation_id = payload.get("installation", {}).get("id", 0)
        sender = payload.get("sender", {}).get("login", "unknown")
        author_assoc = comment.get("author_association", "")

        # Role enforcement
        if author_assoc not in AUTHORIZED_ROLES:
            msg = f"@{sender} Permission denied: only repository maintainers ({', '.join(AUTHORIZED_ROLES)}) may issue DiffShield commands."
            await self.client.post_or_update_comment(repo, pr_number, msg, installation_id)
            self.store.record_audit(repo, pr_number, sender, "command-denied", f"Unauthorized role: {author_assoc}")
            return "denied"

        parts = body.split(maxsplit=2)
        cmd = parts[1].lower() if len(parts) > 1 else ""
        reason = parts[2].strip() if len(parts) > 2 else ""

        open_hold = self.store.get_open_hold(repo, pr_number)

        if cmd == "release":
            if open_hold:
                self.store.release_hold(open_hold.id, actor=sender, kind="release")
                await self.client.remove_label(repo, pr_number, "diffshield:quarantine", installation_id)
                # Flip commit status to success
                await self.client.create_commit_status(
                    repo=repo,
                    sha=open_hold.head_sha,
                    state="success",
                    description=f"Released by @{sender}: {reason or 'no reason'}"[:140],
                    context="diffshield/security",
                    installation_id=installation_id
                )
            self.store.record_audit(repo, pr_number, sender, "hold-released", f"Reason: {reason}")
            reply = f"✅ DiffShield quarantine released by @{sender}. Reason: {reason or 'Maintainer approval'}"
            await self.client.post_or_update_comment(repo, pr_number, reply, installation_id)
            return "released"

        elif cmd == "override":
            # Acceptance Criterion 9: override without a reason is REFUSED!
            if not reason:
                msg = f"⚠️ @{sender} `/diffshield override` requires an explicit justification reason. Command refused."
                await self.client.post_or_update_comment(repo, pr_number, msg, installation_id)
                self.store.record_audit(repo, pr_number, sender, "override-refused", "Missing mandatory reason")
                return "override-refused"

            if open_hold:
                self.store.release_hold(open_hold.id, actor=sender, kind="override")
                await self.client.remove_label(repo, pr_number, "diffshield:quarantine", installation_id)
                # Flip status to success with documented risk acceptance
                await self.client.create_commit_status(
                    repo=repo,
                    sha=open_hold.head_sha,
                    state="success",
                    description=f"Risk accepted by @{sender}: {reason}"[:140],
                    context="diffshield/security",
                    installation_id=installation_id
                )
            self.store.record_audit(repo, pr_number, sender, "override-accepted", f"Reason: {reason}")
            reply = f"🛡️ DiffShield risk override recorded by @{sender}. Reason: {reason}"
            await self.client.post_or_update_comment(repo, pr_number, reply, installation_id)
            return "overridden"

        elif cmd == "recheck":
            # Trigger analysis on demand
            self.store.record_audit(repo, pr_number, sender, "recheck-triggered", "On-demand re-analysis requested")
            # Construct synthetic PR event
            pr_synth = {
                "action": "synchronize",
                "pull_request": {"number": pr_number, "head": {"sha": open_hold.head_sha if open_hold else "HEAD"}},
                "repository": {"full_name": repo},
                "installation": {"id": installation_id}
            }
            await self.handle_pull_request_event(pr_synth)
            return "rechecked"

        return None

    async def release_due_holds(self) -> int:
        """
        Scheduled maintenance tick: checks all expired holds.
        Re-analyses at current head SHA:
          - Still quarantined -> extends hold by 12h (auto-extended)
          - Clean -> releases hold (auto)
        """
        due_holds = self.store.get_due_holds()
        count = 0

        for hold in due_holds:
            count += 1
            # Re-fetch PR diff to re-analyse
            try:
                raw_diff = await self.client.get_pull_request_diff(hold.repo, hold.pr_number, hold.installation)
                report = analyse_pr(
                    raw_diff=raw_diff,
                    repo=hold.repo,
                    pr_number=hold.pr_number,
                    head_sha=hold.head_sha
                )

                if report.decision == "quarantine":
                    # Still bad: restart / extend the hold
                    self.store.extend_hold(hold.id, additional_hours=12)
                    self.store.record_audit(
                        hold.repo, hold.pr_number, "diffshield", "hold-extended",
                        f"Hold extended +12h: PR still quarantined (score {report.score})"
                    )
                else:
                    # Clean: release the hold
                    self.store.release_hold(hold.id, actor="diffshield", kind="auto")
                    await self.client.remove_label(hold.repo, hold.pr_number, "diffshield:quarantine", hold.installation)
                    await self.client.create_commit_status(
                        repo=hold.repo,
                        sha=hold.head_sha,
                        state="success",
                        description=f"DiffShield: Quarantine expired and PR is now clean ({report.score}/100)",
                        context="diffshield/security",
                        installation_id=hold.installation
                    )
                    self.store.record_audit(
                        hold.repo, hold.pr_number, "diffshield", "hold-released",
                        f"Expired hold released: PR is clean (score {report.score})"
                    )
            except Exception as err:
                logger.error(f"Error checking due hold #{hold.id} for {hold.repo}#{hold.pr_number}: {err}")
                # Errors in GitHub calls must never lose a hold! Keep the row.

        return count

