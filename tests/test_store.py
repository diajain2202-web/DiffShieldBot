from __future__ import annotations

import datetime
import pytest
from app.store import Store


@pytest.fixture
def store(tmp_path):
    db_file = str(tmp_path / "test_diffshield.db")
    return Store(db_path=db_file)


def test_upsert_and_get_open_hold(store):
    hold = store.upsert_hold(
        repo="test/repo",
        pr_number=482,
        installation=123,
        head_sha="sha123",
        decision="quarantine",
        score=94,
        band="critical",
        reason="Prototype pollution guard removed",
        hold_hours=12
    )
    assert hold.id is not None
    assert hold.repo == "test/repo"
    assert hold.head_sha == "sha123"

    open_hold = store.get_open_hold("test/repo", 482)
    assert open_hold is not None
    assert open_hold.id == hold.id
    assert open_hold.released_at is None


def test_hold_idempotency_on_head_sha(store):
    h1 = store.upsert_hold(
        repo="test/repo",
        pr_number=482,
        installation=123,
        head_sha="sha_repeat",
        decision="quarantine",
        score=90,
        band="critical",
        reason="First delivery"
    )
    # Re-delivery of same head_sha
    h2 = store.upsert_hold(
        repo="test/repo",
        pr_number=482,
        installation=123,
        head_sha="sha_repeat",
        decision="quarantine",
        score=94,
        band="critical",
        reason="Second delivery"
    )
    assert h1.id == h2.id
    assert h2.score == 94


def test_release_hold(store):
    hold = store.upsert_hold(
        repo="test/repo",
        pr_number=10,
        installation=1,
        head_sha="sha1",
        decision="quarantine",
        score=80,
        band="high",
        reason="test"
    )
    store.release_hold(hold.id, actor="octocat", kind="override")
    open_hold = store.get_open_hold("test/repo", 10)
    assert open_hold is None  # No longer open


def test_extend_hold(store):
    hold = store.upsert_hold(
        repo="test/repo",
        pr_number=20,
        installation=1,
        head_sha="sha2",
        decision="quarantine",
        score=85,
        band="high",
        reason="test",
        hold_hours=1
    )
    old_release_at = hold.release_at
    store.extend_hold(hold.id, additional_hours=12)
    updated = store.get_open_hold("test/repo", 20)
    assert updated.release_kind == "auto-extended"
    assert updated.release_at > old_release_at


def test_due_holds_detection(store):
    # Past hold
    past_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)
    store.upsert_hold(
        repo="test/repo",
        pr_number=30,
        installation=1,
        head_sha="sha_due",
        decision="quarantine",
        score=75,
        band="high",
        reason="expired",
        hold_hours=-1  # In the past
    )
    due = store.get_due_holds()
    assert len(due) >= 1
    assert any(h.head_sha == "sha_due" for h in due)


def test_audit_logging_and_retrieval(store):
    store.record_audit("test/repo", 99, "maintainer1", "override", "Approved by security team")
    audits = store.get_audits("test/repo", 99)
    assert len(audits) == 1
    assert audits[0]["actor"] == "maintainer1"
    assert audits[0]["action"] == "override"


def test_report_upsert_and_get(store):
    payload = {"decision": "quarantine", "score": 92}
    store.upsert_report("test/repo", 482, "sha_rep", "quarantine", 92, payload)
    retrieved = store.get_report("test/repo", 482)
    assert retrieved is not None
    assert retrieved["decision"] == "quarantine"
    assert retrieved["score"] == 92

