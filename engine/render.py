"""
render.py - PR Markdown comments, check run summaries, and annotations.

Formats deterministic security reports for GitHub comments (with <!-- diffshield:report -->
marker for in-place idempotency), check runs, and PR review comments under 65,000 char limit.
"""

from __future__ import annotations

from typing import List, Dict, Any, Optional

MARKER = "<!-- diffshield:report -->"
GITHUB_COMMENT_LIMIT = 65000


def render_comment(report_data: Dict[str, Any]) -> str:
    """
    Render GitHub PR comment markdown strictly following required section order:
    1. Verdict headline + score/band/hold
    2. What happens now bullets with exact commands
    3. Evidence table (signal / points / detail)
    4. Per-file findings (advisory links, similarity, removed guards, lines)
    5. Code moved rather than written (camouflage)
    6. Collapsible revert.patch and restore_guard.patch
    7. Local deterministic footer (no third-party LLM)
    """
    decision = report_data.get("decision", "pass").upper()
    score = report_data.get("score", 0)
    band = report_data.get("band", "info").upper()
    hold_hours = report_data.get("hold_hours", 0)
    hard_block = report_data.get("hard_block", False)

    # 1. Verdict Headline
    if decision == "QUARANTINE":
        badge = "🛑 **DIFFSHIELD QUARANTINE ACTIVE**"
        status_line = f"**Verdict:** {decision} | **Risk Score:** {score}/100 ({band}) | **Hold:** {hold_hours} hours"
    elif decision == "FLAG":
        badge = "⚠️ **DIFFSHIELD SECURITY WARNING**"
        status_line = f"**Verdict:** {decision} | **Risk Score:** {score}/100 ({band}) | **Hold:** None"
    else:
        badge = "✅ **DIFFSHIELD SECURITY CHECK PASSED**"
        status_line = f"**Verdict:** {decision} | **Risk Score:** {score}/100 ({band})"

    lines: List[str] = [
        MARKER,
        f"## {badge}",
        "",
        status_line,
        ""
    ]

    # 2. What happens now
    if decision == "QUARANTINE":
        lines.extend([
            "### ⏳ What happens now",
            f"- **Merge is blocked** under a **{hold_hours}-hour quarantine** hold to prevent silent security regression.",
            "- When the hold expires, the PR is **automatically re-analysed** (if clean, released; if still vulnerable, hold extends).",
            "- Authorized maintainers (`OWNER`, `MEMBER`, `COLLABORATOR`) can intervene at any time:",
            "  - `/diffshield release <reason>` — release the quarantine immediately.",
            "  - `/diffshield override <reason>` — accept risk with documented reason.",
            "  - `/diffshield recheck` — re-run deterministic analysis on demand.",
            ""
        ])
    elif decision == "FLAG":
        lines.extend([
            "### 🔍 What happens now",
            "- Security signals were flagged for manual reviewer attention. Merge is not hard-blocked.",
            "- Use `/diffshield recheck` after addressing findings to update this report.",
            ""
        ])

    # 3. Evidence Table
    evidence = report_data.get("evidence_table", [])
    if evidence:
        lines.extend([
            "### 📊 Evidence Table",
            "| Signal | Points | Category | Details |",
            "| :--- | :---: | :--- | :--- |"
        ])
        for row in evidence:
            sig = row.get("signal", "").replace("|", "\\|")
            pts = f"+{row.get('points', 0)}"
            cat = row.get("category", "")
            det = row.get("detail", "").replace("|", "\\|")
            lines.append(f"| {sig} | `{pts}` | {cat} | {det} |")
        lines.append("")

    # 4. Per-File Findings
    findings = report_data.get("findings", [])
    if findings:
        lines.extend([
            "### 🔬 Security Findings",
            ""
        ])
        for f in findings:
            adv_id = f.get("advisory_id") or f.get("rule_id", "Finding")
            title = f.get("title") or f.get("name", "")
            adv_url = f.get("advisory_url", "")
            adv_link = f"[{adv_id}]({adv_url})" if adv_url else f"**{adv_id}**"
            verdict = f.get("verdict", "")
            sim = f.get("similarity")
            sim_str = f" | Similarity: `{int(sim * 100)}%`" if sim is not None else ""

            lines.append(f"#### {adv_link}: {title} ({verdict.upper()}{sim_str})")
            lines.append(f"- **File:** `{f.get('file_path')}:{f.get('line_number', 1)}`")
            if f.get("evidence"):
                lines.append(f"- **Evidence:** {f.get('evidence')}")
            if f.get("removed_guards"):
                lines.append("- **Removed Defensive Guard(s):**")
                for rg in f.get("removed_guards"):
                    lines.append(f"  ```javascript\n  {rg}\n  ```")
            lines.append("")

    # 5. Code Moved Rather Than Written (Camouflage)
    camouflage = report_data.get("camouflage", [])
    if camouflage:
        lines.extend([
            "### 🎭 Camouflage / Relocation Analysis",
            "Near-duplicate structural rewrites detected across diff boundaries:",
            ""
        ])
        for cm in camouflage:
            lines.append(f"- `{cm.get('old_name')}` ➔ `{cm.get('new_name')}`: {cm.get('evidence')}")
        lines.append("")

    # 6. Collapsible Patches
    patches = report_data.get("patches", {})
    revert_patch = patches.get("revert_patch", "")
    restore_patch = patches.get("restore_guard_patch", "")
    restore_rationale = patches.get("restore_rationale", "")

    if restore_patch:
        lines.extend([
            "### 🩹 Recommended Remediation",
            f"> {restore_rationale}",
            "",
            "<details><summary><b>View Surgical restore_guard.patch (Recommended)</b></summary>",
            "",
            "```diff",
            restore_patch.strip(),
            "```",
            "",
            "</details>",
            ""
        ])

    if revert_patch:
        lines.extend([
            "<details><summary><b>View Full revert.patch (Undo PR)</b></summary>",
            "",
            "```diff",
            revert_patch.strip(),
            "```",
            "",
            "</details>",
            ""
        ])

    # 7. Local Deterministic Footer
    lines.extend([
        "---",
        "*DiffShield Engine v1.0 • 100% Deterministic Local Analysis • No source code was sent to any third-party LLM.*"
    ])

    full_comment = "\n".join(lines)
    if len(full_comment) > GITHUB_COMMENT_LIMIT:
        full_comment = full_comment[:GITHUB_COMMENT_LIMIT - 500] + "\n\n*(Report truncated to stay within GitHub length limits)*\n"

    return full_comment


def render_check_run(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format output dictionary for GitHub Check Run API.
    """
    decision = report_data.get("decision", "pass").upper()
    score = report_data.get("score", 0)
    band = report_data.get("band", "info").upper()

    conclusion = "success"
    if decision == "QUARANTINE":
        conclusion = "failure"
    elif decision == "FLAG":
        conclusion = "neutral"

    title = f"DiffShield: {decision} ({score}/100 {band})"
    summary = f"DiffShield evaluated this pull request with deterministic multi-layer analysis.\nRisk Score: {score}/100. Decision: {decision}."

    annotations = []
    for f in report_data.get("findings", []):
        level = "failure" if decision == "QUARANTINE" else "warning"
        annotations.append({
            "path": f.get("file_path", "unknown"),
            "start_line": f.get("line_number", 1),
            "end_line": f.get("line_number", 1),
            "annotation_level": level,
            "title": f.get("advisory_id") or f.get("rule_id", "DiffShield"),
            "message": f.get("evidence") or f.get("detail", "Security finding detected.")
        })

    return {
        "name": "diffshield/security",
        "conclusion": conclusion,
        "output": {
            "title": title,
            "summary": summary,
            "text": render_comment(report_data),
            "annotations": annotations[:50]  # GitHub limit is 50 annotations per request
        }
    }

