"""
demo_local.py - Interactive zero-credential scenario browser and server at :8000.

The primary demo path for judges and maintainers. Provides:
- Interactive web UI at http://localhost:8000 with the 6 canonical scenarios
- Instant 1-click deterministic execution
- Live inspection of evidence tables, AST block findings, and surgical restore_guard.patch
- Simulation of maintainer override/release workflows
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Ensure repository root is in sys.path
REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from typing import Dict, Any

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from engine.analyse import analyse_pr
from scripts.scenarios import SCENARIOS, get_scenario_by_id


app = FastAPI(title="DiffShield Interactive Scenario Lab", version="1.0.0")


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DiffShield • Scenario Evaluation Lab</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111827;
      --border: #1f2937;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --accent: #10b981;
      --danger: #ef4444;
      --warning: #f59e0b;
      --info: #3b82f6;
      --code-bg: #030712;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 24px;
    }
    .header {
      max-width: 1200px;
      margin: 0 auto 24px auto;
      border-bottom: 1px solid var(--border);
      padding-bottom: 16px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .header h1 { font-size: 1.6rem; color: #fff; display: flex; align-items: center; gap: 10px; }
    .badge {
      font-size: 0.75rem;
      padding: 4px 10px;
      border-radius: 9999px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .badge-quarantine { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
    .badge-pass { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }
    .container {
      max-width: 1200px;
      margin: 0 auto;
      display: grid;
      grid-template-columns: 340px 1fr;
      gap: 24px;
    }
    .sidebar {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      height: fit-content;
    }
    .scenario-btn {
      width: 100%;
      text-align: left;
      background: transparent;
      border: 1px solid var(--border);
      color: var(--text);
      padding: 12px;
      margin-bottom: 8px;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .scenario-btn:hover { background: #1f2937; border-color: #374151; }
    .scenario-btn.active { background: #1e293b; border-color: var(--accent); }
    .scenario-title { font-weight: 600; font-size: 0.95rem; margin-bottom: 4px; }
    .scenario-meta { font-size: 0.8rem; color: var(--text-muted); display: flex; justify-content: space-between; }
    .main-panel {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 24px;
    }
    .section-title { font-size: 1.1rem; font-weight: 600; margin-bottom: 12px; color: #fff; }
    pre {
      background: var(--code-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 14px;
      overflow-x: auto;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.85rem;
      color: #e5e7eb;
      margin-bottom: 16px;
    }
    .diff-del { color: #f87171; background: rgba(239,68,68,0.1); }
    .diff-add { color: #34d399; background: rgba(16,185,129,0.1); }
    .table-evidence {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 20px;
      font-size: 0.88rem;
    }
    .table-evidence th, .table-evidence td {
      border: 1px solid var(--border);
      padding: 8px 12px;
      text-align: left;
    }
    .table-evidence th { background: #1f2937; color: #fff; }
    .verdict-box {
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .verdict-box.quarantine { background: rgba(239, 68, 68, 0.08); border-color: var(--danger); }
    .verdict-box.pass { background: rgba(16, 185, 129, 0.08); border-color: var(--accent); }
    .verdict-stat { text-align: center; }
    .verdict-stat .val { font-size: 1.5rem; font-weight: 700; }
    .verdict-stat .lbl { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; }
  </style>
</head>
<body>
  <div class="header">
    <h1>🛡️ DiffShield • Verification & Demo Lab</h1>
    <div>
      <span class="badge" style="background: rgba(59,130,246,0.2); color:#60a5fa; border:1px solid #3b82f6;">Offline Mode • No LLM</span>
    </div>
  </div>

  <div class="container">
    <div class="sidebar">
      <h3 style="font-size: 0.9rem; text-transform: uppercase; color: var(--text-muted); margin-bottom: 12px;">Test Scenarios</h3>
      <div id="scenario-list"></div>
    </div>

    <div class="main-panel">
      <div id="scenario-details">
        <h2 id="view-title" style="margin-bottom: 8px;">Select a scenario to evaluate</h2>
        <p id="view-desc" style="color: var(--text-muted); margin-bottom: 20px;"></p>
        
        <div id="verdict-banner"></div>

        <div class="section-title">Unified Diff Inspected</div>
        <pre id="view-diff"></pre>

        <div class="section-title">Evidence & Multi-Layer Signals</div>
        <div id="view-evidence"></div>

        <div class="section-title">Generated Surgical Remediation (restore_guard.patch)</div>
        <pre id="view-patch"></pre>
      </div>
    </div>
  </div>

  <script>
    let activeScenario = null;

    async function loadScenarios() {
      const res = await fetch("/api/scenarios");
      const list = await res.json();
      const container = document.getElementById("scenario-list");
      container.innerHTML = "";

      list.forEach((sc, idx) => {
        const btn = document.createElement("button");
        btn.className = "scenario-btn" + (idx === 0 ? " active" : "");
        btn.onclick = () => selectScenario(sc.id, btn);
        btn.innerHTML = `
          <div class="scenario-title">${sc.name}</div>
          <div class="scenario-meta">
            <span>${sc.pr_title}</span>
            <span class="badge ${sc.is_attack ? 'badge-quarantine' : 'badge-pass'}">${sc.is_attack ? 'ATTACK' : 'BENIGN'}</span>
          </div>
        `;
        container.appendChild(btn);
      });

      if (list.length > 0) {
        selectScenario(list[0].id, container.firstChild);
      }
    }

    async function selectScenario(id, btnElement) {
      document.querySelectorAll(".scenario-btn").forEach(b => b.classList.remove("active"));
      if (btnElement) btnElement.classList.add("active");

      const res = await fetch(`/api/evaluate/${id}`);
      const data = await res.json();

      document.getElementById("view-title").innerText = data.scenario.name;
      document.getElementById("view-desc").innerText = data.scenario.description;
      document.getElementById("view-diff").innerText = data.scenario.raw_diff;

      const isQuarantine = data.report.decision === "quarantine";
      const bannerClass = isQuarantine ? "quarantine" : "pass";
      const badgeText = isQuarantine ? "QUARANTINE ACTIVE" : "PASSED";

      document.getElementById("verdict-banner").innerHTML = `
        <div class="verdict-box ${bannerClass}">
          <div>
            <div style="font-size: 1.2rem; font-weight: 700; color: ${isQuarantine ? '#f87171' : '#34d399'};">
              ${isQuarantine ? '🛑' : '✅'} Verdict: ${badgeText}
            </div>
            <div style="font-size: 0.85rem; color: var(--text-muted); margin-top: 4px;">
              ${data.report.title} (${data.report.repo} #${data.report.pr_number})
            </div>
          </div>
          <div style="display: flex; gap: 24px;">
            <div class="verdict-stat">
              <div class="val">${data.report.score}/100</div>
              <div class="lbl">Risk Score</div>
            </div>
            <div class="verdict-stat">
              <div class="val" style="text-transform: uppercase;">${data.report.band}</div>
              <div class="lbl">Band</div>
            </div>
            <div class="verdict-stat">
              <div class="val">${data.report.hold_hours}h</div>
              <div class="lbl">Quarantine Hold</div>
            </div>
          </div>
        </div>
      `;

      // Evidence table
      const evTable = data.report.evidence_table || [];
      if (evTable.length > 0) {
        let rows = evTable.map(r => `
          <tr>
            <td><b>${r.signal}</b></td>
            <td><code>+${r.points}</code></td>
            <td><span style="color:var(--text-muted);">${r.category}</span></td>
            <td>${r.detail}</td>
          </tr>
        `).join("");
        document.getElementById("view-evidence").innerHTML = `
          <table class="table-evidence">
            <thead>
              <tr><th>Signal</th><th>Points</th><th>Category</th><th>Details</th></tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>
        `;
      } else {
        document.getElementById("view-evidence").innerHTML = "<p style='color:var(--text-muted); margin-bottom:16px;'>No risk points assigned. PR passed clean.</p>";
      }

      // Restore patch
      const patch = data.report.patches.restore_guard_patch || "(No security guards stripped; no patch needed)";
      document.getElementById("view-patch").innerText = patch;
    }

    loadScenarios();
  </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def index_page():
    return HTML_TEMPLATE


@app.get("/api/scenarios")
def list_scenarios():
    return [
        {
            "id": s.id,
            "name": s.name,
            "description": s.description,
            "is_attack": s.is_attack,
            "repo": s.repo,
            "pr_number": s.pr_number,
            "pr_title": s.pr_title
        }
        for s in SCENARIOS
    ]


@app.get("/api/evaluate/{scenario_id}")
def evaluate_scenario(scenario_id: str):
    sc = get_scenario_by_id(scenario_id)
    contents = {}
    if sc.base_source:
        contents[f"base:merge.js"] = sc.base_source
        contents[f"base:validate.js"] = sc.base_source
    if sc.head_source:
        contents[f"head:merge.js"] = sc.head_source
        contents[f"head:validate.js"] = sc.head_source
        contents[f"head:telemetry.js"] = sc.head_source

    report = analyse_pr(
        raw_diff=sc.raw_diff,
        repo=sc.repo,
        pr_number=sc.pr_number,
        title=sc.pr_title,
        file_contents=contents
    )

    return {
        "scenario": {
            "id": sc.id,
            "name": sc.name,
            "description": sc.description,
            "is_attack": sc.is_attack,
            "raw_diff": sc.raw_diff
        },
        "report": report.to_dict()
    }


def main():
    port = int(os.getenv("PORT", 8000))
    print(f"Starting DiffShield Demo Lab on http://localhost:{port}")
    uvicorn.run("scripts.demo_local:app", host="0.0.0.0", port=port, reload=False)


if __name__ == "__main__":
    main()

