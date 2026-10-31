"""
main.py - DiffShield FastAPI application and GitHub Webhook receiver.

Endpoints:
  POST /webhook     - HMAC-SHA256 verified GitHub webhook receiver (asynchronous)
  POST /tasks/tick  - Cron maintenance endpoint: re-analyses due holds
  GET  /healthz     - Service health check
  GET  /api/*       - Reports, audits, and quarantine metrics
  GET  /            - Interactive quarantine ledger HTML dashboard
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Dict, Any, Set

from fastapi import FastAPI, Request, Header, HTTPException, BackgroundTasks, Response
from fastapi.responses import HTMLResponse, JSONResponse

from app.config import Settings
from app.github_client import GitHubClient
from app.pipeline import Pipeline
from app.store import Store

logger = logging.getLogger("diffshield.app")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

app = FastAPI(title="DiffShield GitHub App", version="1.0.0")

settings = Settings.from_env()
store = Store(db_path=settings.db_path)
client = GitHubClient(
    app_id=settings.github_app_id,
    private_key=settings.github_private_key,
    dry_run=settings.dry_run
)
pipeline = Pipeline(store=store, github_client=client, settings=settings)

# In-memory deduplication set for X-GitHub-Delivery
_processed_deliveries: Set[str] = set()


def verify_signature(raw_body: bytes, signature_header: str, secret: str) -> bool:
    """Verify GitHub webhook HMAC-SHA256 signature against raw body."""
    if not secret:
        # Dev / local warning
        logger.warning("No GITHUB_WEBHOOK_SECRET configured; skipping signature verification.")
        return True

    if not signature_header or not signature_header.startswith("sha256="):
        return False

    expected_sig = signature_header.split("sha256=")[1].strip()
    mac = hmac.new(secret.encode("utf-8"), msg=raw_body, digestmod=hashlib.sha256)
    return hmac.compare_digest(mac.hexdigest(), expected_sig)


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "diffshield", "version": "1.0.0"}


@app.post("/webhook")
async def webhook_endpoint(
    request: Request,
    background_tasks: BackgroundTasks,
    x_github_event: str = Header(None),
    x_github_delivery: str = Header(None),
    x_hub_signature_256: str = Header(None)
):
    """
    Receives GitHub webhook events.
    Verifies HMAC-SHA256 over raw request body.
    Deduplicates on X-GitHub-Delivery.
    Dispatches to background task to guarantee <10s response.
    """
    raw_body = await request.body()

    # 1. HMAC Verification
    if settings.github_webhook_secret:
        if not verify_signature(raw_body, x_hub_signature_256, settings.github_webhook_secret):
            raise HTTPException(status_code=401, detail="Invalid X-Hub-Signature-256 signature")

    # 2. Delivery deduplication
    if x_github_delivery:
        if x_github_delivery in _processed_deliveries:
            return {"status": "ignored", "reason": "duplicate delivery", "delivery": x_github_delivery}
        _processed_deliveries.add(x_github_delivery)
        if len(_processed_deliveries) > 10000:
            _processed_deliveries.clear()

    payload = await request.json()

    # 3. Handle events
    if x_github_event == "pull_request":
        background_tasks.add_task(pipeline.handle_pull_request_event, payload)
    elif x_github_event in ("issue_comment", "pull_request_review_comment"):
        background_tasks.add_task(pipeline.handle_comment_command, payload)

    return {"status": "received", "event": x_github_event, "delivery": x_github_delivery}


@app.post("/tasks/tick")
async def tasks_tick():
    """Maintenance endpoint called periodically by cron to check due holds."""
    released_count = await pipeline.release_due_holds()
    return {"status": "ok", "checked_due_holds": released_count}


@app.get("/api/report/{owner}/{repo}/{pr_number}")
def get_report(owner: str, repo: str, pr_number: int):
    full_repo = f"{owner}/{repo}"
    report_data = store.get_report(full_repo, pr_number)
    if not report_data:
        raise HTTPException(status_code=404, detail="No report found for this PR")
    return report_data


@app.get("/api/audit/{owner}/{repo}/{pr_number}")
def get_audits(owner: str, repo: str, pr_number: int):
    full_repo = f"{owner}/{repo}"
    return store.get_audits(full_repo, pr_number)


@app.get("/api/stats")
def get_stats():
    return store.get_stats()


@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    stats = store.get_stats()
    holds = store.list_holds(limit=30)

    holds_rows = ""
    for h in holds:
        rel = h.get("released_at")
        badge = '<span style="color:#ef4444; font-weight:700;">ACTIVE HOLD</span>' if not rel else f'<span style="color:#10b981;">RELEASED ({h.get("release_kind")})</span>'
        holds_rows += f"""
        <tr>
          <td><b>{h['repo']} #{h['pr_number']}</b></td>
          <td><code>{h['head_sha'][:8]}</code></td>
          <td>{badge}</td>
          <td><b>{h['score']}/100</b> ({h['band'].upper()})</td>
          <td>{h['release_at'][:19]}</td>
          <td>{h.get('released_by') or '-'}</td>
          <td>{h['reason']}</td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>DiffShield • Quarantine Ledger</title>
  <style>
    body {{ background: #0b0f19; color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 24px; }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    .card {{ background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 20px; margin-bottom: 24px; }}
    .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }}
    .stat-card {{ background: #1f2937; padding: 16px; border-radius: 6px; text-align: center; }}
    .stat-val {{ font-size: 2rem; font-weight: 700; color: #10b981; }}
    .stat-lbl {{ font-size: 0.8rem; color: #9ca3af; text-transform: uppercase; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
    th, td {{ border: 1px solid #1f2937; padding: 10px 14px; text-align: left; }}
    th {{ background: #1f2937; color: #fff; }}
    h1 {{ font-size: 1.6rem; margin-bottom: 16px; display: flex; align-items: center; gap: 10px; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ DiffShield • Live Quarantine Ledger</h1>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-val" style="color: #ef4444;">{stats['active_holds']}</div>
        <div class="stat-lbl">Active Holds</div>
      </div>
      <div class="stat-card">
        <div class="stat-val">{stats['total_holds']}</div>
        <div class="stat-lbl">Total Holds Managed</div>
      </div>
      <div class="stat-card">
        <div class="stat-val">{stats['released_holds']}</div>
        <div class="stat-lbl">Released / Overridden</div>
      </div>
      <div class="stat-card">
        <div class="stat-val">{stats['total_audits']}</div>
        <div class="stat-lbl">Audit Entries</div>
      </div>
    </div>

    <div class="card">
      <h2 style="font-size: 1.2rem; margin-bottom: 14px;">Quarantine Holds Registry</h2>
      <table>
        <thead>
          <tr>
            <th>PR</th><th>Head SHA</th><th>Status</th><th>Risk Score</th><th>Release Due</th><th>Released By</th><th>Reason</th>
          </tr>
        </thead>
        <tbody>
          {holds_rows or "<tr><td colspan='7' style='text-align:center; color:#9ca3af;'>No holds registered. System clean.</td></tr>"}
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>"""
    return HTMLResponse(content=html)

