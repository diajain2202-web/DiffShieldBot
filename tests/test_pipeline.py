from __future__ import annotations

import asyncio
import pytest
from app.config import Settings
from app.github_client import FakeGitHubClient
from app.pipeline import Pipeline
from app.store import Store
from engine.render import MARKER


PR482_DIFF = """--- a/merge.js
+++ b/merge.js
@@ -2,3 +2,2 @@
   for (const key in source) {
-    if (key === '__proto__') continue;
     target[key] = source[key];
"""

CLEAN_DIFF = """--- a/readme.txt
+++ b/readme.txt
@@ -1,1 +1,2 @@
+Documentation update
"""


@pytest.fixture
def test_setup(tmp_path):
    db_file = str(tmp_path / "pipeline_test.db")
    store = Store(db_path=db_file)
    client = FakeGitHubClient()
    pipeline = Pipeline(store=store, github_client=client, settings=Settings(dry_run=False))
    return store, client, pipeline


def test_criterion_7_webhook_idempotency(test_setup):
    """
    Acceptance criterion 7:
    Re-delivering the same webhook produces one comment, one check, one open hold.
    """
    async def _test():
        store, client, pipeline = test_setup
        repo = "lodash/lodash"
        client.diffs[f"{repo}:482"] = PR482_DIFF

        event_payload = {
            "action": "opened",
            "pull_request": {
                "number": 482,
                "title": "Simplify merge for performance",
                "head": {"sha": "sha_482_v1"},
                "base": {"sha": "main_base"}
            },
            "repository": {"full_name": repo},
            "installation": {"id": 999}
        }

        # 1. First webhook delivery
        await pipeline.handle_pull_request_event(event_payload)
        assert len(client.comments) == 1
        assert len(client.check_runs) == 1
        assert store.get_open_hold(repo, 482) is not None

        # 2. Duplicate webhook re-delivery (same head_sha)
        await pipeline.handle_pull_request_event(event_payload)
        # Still only 1 comment (updated in place) and 1 open hold!
        assert len(client.comments) == 1
        open_hold = store.get_open_hold(repo, 482)
        assert open_hold is not None

    asyncio.run(_test())


def test_criterion_8_expired_hold_extends_or_releases(test_setup):
    """
    Acceptance criterion 8:
    An expired hold on a still-malicious PR extends rather than releases;
    a clean re-analysis releases it.
    """
    async def _test():
        store, client, pipeline = test_setup
        repo = "test/still-bad"
        client.diffs[f"{repo}:1"] = PR482_DIFF

        # Setup expired hold
        store.upsert_hold(
            repo=repo,
            pr_number=1,
            installation=1,
            head_sha="sha_bad",
            decision="quarantine",
            score=94,
            band="critical",
            reason="Vulnerable",
            hold_hours=-1
        )

        # 1. Still malicious -> must EXTEND
        await pipeline.release_due_holds()
        hold = store.get_open_hold(repo, 1)
        assert hold is not None
        assert hold.release_kind == "auto-extended"
        audits = store.get_audits(repo, 1)
        assert any(a["action"] == "hold-extended" for a in audits)

        # 2. PR updated with clean diff -> must RELEASE
        repo_clean = "test/now-clean"
        client.diffs[f"{repo_clean}:2"] = CLEAN_DIFF
        store.upsert_hold(
            repo=repo_clean,
            pr_number=2,
            installation=1,
            head_sha="sha_clean",
            decision="quarantine",
            score=94,
            band="critical",
            reason="Was vulnerable",
            hold_hours=-1
        )
        await pipeline.release_due_holds()
        assert store.get_open_hold(repo_clean, 2) is None
        audits_clean = store.get_audits(repo_clean, 2)
        assert any(a["action"] == "hold-released" for a in audits_clean)

    asyncio.run(_test())


def test_criterion_9_override_requires_reason(test_setup):
    """
    Acceptance criterion 9:
    override without a reason is refused; with a reason it releases,
    flips status to success, and writes an audit row naming the actor.
    """
    async def _test():
        store, client, pipeline = test_setup
        repo = "org/repo"
        pr_num = 50
        store.upsert_hold(repo, pr_num, 1, "sha_ovr", "quarantine", 90, "critical", "Hold", 12)

        # 1. Override WITHOUT reason -> REFUSED
        cmd_no_reason = {
            "comment": {"body": "/diffshield override", "author_association": "MEMBER"},
            "repository": {"full_name": repo},
            "issue": {"number": pr_num},
            "sender": {"login": "sec_lead"},
            "installation": {"id": 1}
        }
        result = await pipeline.handle_comment_command(cmd_no_reason)
        assert result == "override-refused"
        # Hold remains open
        assert store.get_open_hold(repo, pr_num) is not None

        # 2. Override WITH reason -> RELEASES & FLIPS STATUS
        cmd_with_reason = {
            "comment": {"body": "/diffshield override Performance benchmark verified safe", "author_association": "OWNER"},
            "repository": {"full_name": repo},
            "issue": {"number": pr_num},
            "sender": {"login": "alice_owner"},
            "installation": {"id": 1}
        }
        result2 = await pipeline.handle_comment_command(cmd_with_reason)
        assert result2 == "overridden"
        # Hold is released
        assert store.get_open_hold(repo, pr_num) is None
        # Audit recorded with actor
        audits = store.get_audits(repo, pr_num)
        assert any(a["actor"] == "alice_owner" and a["action"] == "override-accepted" for a in audits)
        # Commit status flipped to success
        assert any(s["state"] == "success" and "alice_owner" in s["description"] for s in client.statuses)

    asyncio.run(_test())


def test_criterion_10_base_policy_enforcement(test_setup):
    """
    Acceptance criterion 10:
    A .diffshield.yml on the base branch with enforcement: comment produces flag and no hold;
    a broken YAML falls back to safe defaults (hold, 12h).
    """
    async def _test():
        store, client, pipeline = test_setup
        repo = "test/policy-repo"
        client.diffs[f"{repo}:100"] = PR482_DIFF

        # 1. Base policy: enforcement: comment
        client.files[f"{repo}:.diffshield.yml:base_ref_1"] = "enforcement: comment\nhold_hours: 12\n"

        res = await pipeline.handle_pull_request_event({
            "action": "opened",
            "pull_request": {"number": 100, "title": "PR", "head": {"sha": "sha_100"}, "base": {"sha": "base_ref_1"}},
            "repository": {"full_name": repo},
            "installation": {"id": 1}
        })
        assert res.decision == "flag"
        # NO quarantine hold created under comment enforcement
        assert store.get_open_hold(repo, 100) is None

        # 2. Broken YAML -> Fallback to safe defaults (hold, 12h)
        client.diffs[f"{repo}:101"] = PR482_DIFF
        client.files[f"{repo}:.diffshield.yml:base_ref_broken"] = ": [ broken yaml ::: \n"
        res_broken = await pipeline.handle_pull_request_event({
            "action": "opened",
            "pull_request": {"number": 101, "title": "PR", "head": {"sha": "sha_101"}, "base": {"sha": "base_ref_broken"}},
            "repository": {"full_name": repo},
            "installation": {"id": 1}
        })
        assert res_broken.decision == "quarantine"
        assert store.get_open_hold(repo, 101) is not None

    asyncio.run(_test())


def test_criterion_11_dry_run_no_github_writes(tmp_path):
    """
    Acceptance criterion 11:
    DIFFSHIELD_DRY_RUN=1 performs no GitHub writes at all.
    """
    async def _test():
        db_file = str(tmp_path / "dry_run.db")
        store = Store(db_path=db_file)
        client = FakeGitHubClient(dry_run=True)
        pipeline = Pipeline(store=store, github_client=client, settings=Settings(dry_run=True))

        repo = "test/dry-run"
        client.diffs[f"{repo}:1"] = PR482_DIFF

        await pipeline.handle_pull_request_event({
            "action": "opened",
            "pull_request": {"number": 1, "title": "PR", "head": {"sha": "sha1"}, "base": {"sha": "base1"}},
            "repository": {"full_name": repo},
            "installation": {"id": 1}
        })

        assert len(client.comments) == 0
        assert len(client.check_runs) == 0
        assert len(client.statuses) == 0
        assert len(client.labels) == 0

    asyncio.run(_test())


def test_unauthorized_user_command_denied(test_setup):
    async def _test():
        store, client, pipeline = test_setup
        repo = "test/auth"
        cmd = {
            "comment": {"body": "/diffshield release test", "author_association": "NONE"},
            "repository": {"full_name": repo},
            "issue": {"number": 1},
            "sender": {"login": "attacker"},
            "installation": {"id": 1}
        }
        res = await pipeline.handle_comment_command(cmd)
        assert res == "denied"
        audits = store.get_audits(repo, 1)
        assert any(a["action"] == "command-denied" for a in audits)

    asyncio.run(_test())


def test_pr_closed_releases_hold(test_setup):
    async def _test():
        store, client, pipeline = test_setup
        repo = "test/close-hold"
        store.upsert_hold(repo, 5, 1, "sha5", "quarantine", 90, "critical", "Hold", 12)
        assert store.get_open_hold(repo, 5) is not None

        await pipeline.handle_pull_request_event({
            "action": "closed",
            "pull_request": {"number": 5},
            "repository": {"full_name": repo},
            "installation": {"id": 1}
        })

        assert store.get_open_hold(repo, 5) is None

    asyncio.run(_test())
