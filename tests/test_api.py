from __future__ import annotations

import hashlib
import hmac
import json
import pytest
from starlette.testclient import TestClient

import app.main as main_mod
from app.main import app, verify_signature


client = TestClient(app)


def test_healthz_endpoint():
    resp = client.get("/healthz")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "diffshield"


def test_stats_endpoint():
    resp = client.get("/api/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_holds" in data
    assert "active_holds" in data


def test_dashboard_endpoint():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "DiffShield • Live Quarantine Ledger" in resp.text

    resp2 = client.get("/dashboard")
    assert resp2.status_code == 200
    assert "Quarantine Holds Registry" in resp2.text


def test_tasks_tick_endpoint():
    resp = client.post("/tasks/tick")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_webhook_hmac_signature_verification():
    secret = "secret_123"
    body = b'{"action": "ping"}'
    valid_sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    invalid_sig = "sha256=invalid"

    assert verify_signature(body, valid_sig, secret) is True
    assert verify_signature(body, invalid_sig, secret) is False


def test_webhook_invalid_signature_returns_401():
    # Temporarily set webhook secret in settings
    orig_secret = main_mod.settings.github_webhook_secret
    try:
        main_mod.settings.github_webhook_secret = "super_secret"
        resp = client.post(
            "/webhook",
            json={"action": "opened"},
            headers={
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "deliv-12345",
                "X-Hub-Signature-256": "sha256=bad_hex"
            }
        )
        assert resp.status_code == 401
    finally:
        main_mod.settings.github_webhook_secret = orig_secret


def test_webhook_valid_signature_accepted():
    orig_secret = main_mod.settings.github_webhook_secret
    secret = "test_key"
    payload = json.dumps({"action": "ping"}).encode()
    sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

    try:
        main_mod.settings.github_webhook_secret = secret
        resp = client.post(
            "/webhook",
            content=payload,
            headers={
                "Content-Type": "application/json",
                "X-GitHub-Event": "ping",
                "X-GitHub-Delivery": "delivery-unique-1",
                "X-Hub-Signature-256": sig
            }
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "received"
    finally:
        main_mod.settings.github_webhook_secret = orig_secret


def test_get_report_and_audit_api():
    # Insert report and audit directly into store
    main_mod.store.upsert_report("api-test/repo", 77, "head77", "quarantine", 91, {"score": 91})
    main_mod.store.record_audit("api-test/repo", 77, "admin", "test-audit", "detail")

    resp_rep = client.get("/api/report/api-test/repo/77")
    assert resp_rep.status_code == 200
    assert resp_rep.json()["score"] == 91

    resp_aud = client.get("/api/audit/api-test/repo/77")
    assert resp_aud.status_code == 200
    assert len(resp_aud.json()) >= 1

