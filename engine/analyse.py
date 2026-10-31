"""
analyse.py - DiffShield core offline analysis pipeline.

Single source of truth for PR analysis and JSON report schema.
Orchestrates unified diff parsing, AST block extraction, historical fix matching,
rule evaluation, vector similarity / camouflage detection, risk scoring, and
remediation patch synthesis.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import List, Dict, Any, Optional

from engine.astnorm import (
    extract_blocks_from_source,
    map_blocks_to_diff,
    Block
)
from engine.diffparse import (
    parse_unified_diff,
    touched_ranges,
    forward_patch,
    apply_reverse_patch,
    FileDiff
)
from engine.fixdb import FixDatabase, FixMatch
from engine.render import render_comment
from engine.reverse import generate_revert_patch, generate_restore_guard_patch
from engine.risk import evaluate_risk, RiskAssessment
from engine.rules_engine import RulesEngine, RuleFinding
from engine.similarity import detect_camouflage, CamouflageMatch


DEFAULT_IGNORE_PATTERNS = [
    "dist/**",
    "*/dist/**",
    "*.min.js",
    "*.min.css",
    "node_modules/**",
    "*/node_modules/**",
    ".git/**"
]

JS_TS_EXTENSIONS = {
    ".js", ".mjs", ".cjs", ".jsx",
    ".ts", ".mts", ".cts", ".tsx"
}


@dataclass
class Report:
    """Canonical DiffShield analysis report."""
    repo: str
    pr_number: int
    head_sha: str
    title: str
    decision: str
    score: int
    band: str
    hard_block: bool
    hold_hours: int
    files_analyzed: int
    findings: List[Dict[str, Any]] = field(default_factory=list)
    camouflage: List[Dict[str, Any]] = field(default_factory=list)
    evidence_table: List[Dict[str, Any]] = field(default_factory=list)
    patches: Dict[str, Any] = field(default_factory=dict)
    markdown_comment: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def should_ignore_file(path: str, ignore_patterns: Optional[List[str]] = None) -> bool:
    """Check if file path matches any ignore patterns."""
    patterns = ignore_patterns if ignore_patterns is not None else DEFAULT_IGNORE_PATTERNS
    p = path.replace("\\", "/")
    name = Path(p).name
    for pat in patterns:
        if fnmatch.fnmatch(p, pat) or fnmatch.fnmatch(name, pat):
            return True
    return False


def analyse_pr(
    raw_diff: str,
    repo: str = "repo/test",
    pr_number: int = 1,
    head_sha: str = "HEAD",
    title: str = "Pull Request",
    file_contents: Optional[Dict[str, str]] = None,
    enforcement: str = "hold",
    hold_hours: int = 12,
    ignore_patterns: Optional[List[str]] = None,
    fix_db: Optional[FixDatabase] = None,
    rules_engine: Optional[RulesEngine] = None
) -> Report:
    """
    Run complete deterministic multi-layer DiffShield analysis on a PR diff.
    """
    if fix_db is None:
        fix_db = FixDatabase()
    if rules_engine is None:
        rules_engine = RulesEngine()

    file_diffs = parse_unified_diff(raw_diff)

    total_added_lines = 0
    total_removed_lines = 0
    files_analyzed = 0

    all_fix_matches: List[FixMatch] = []
    all_rule_findings: List[RuleFinding] = []
    all_camouflage: List[CamouflageMatch] = []
    revert_patches: List[str] = []
    restore_patches: List[str] = []
    restore_rationales: List[str] = []

    for fd in file_diffs:
        path = fd.path
        if should_ignore_file(path, ignore_patterns):
            continue

        files_analyzed += 1
        total_added_lines += fd.added_count
        total_removed_lines += fd.removed_count

        ext = Path(path).suffix.lower()
        is_js_ts = ext in JS_TS_EXTENSIONS

        base_blocks: List[Block] = []
        head_blocks: List[Block] = []
        removed_blocks: List[Block] = []
        added_blocks: List[Block] = []

        # Retrieve or synthesize base and head content
        contents = file_contents or {}
        base_source = contents.get(f"base:{path}", "")
        head_source = contents.get(f"head:{path}", "")

        # If full head source is provided, use it; otherwise synthesize from diff
        if not head_source:
            # Build head lines from added and context lines
            head_lines = []
            for h in fd.hunks:
                for dl in h.lines:
                    if dl.kind in ("+", " "):
                        head_lines.append(dl.text)
            head_source = "\n".join(head_lines)

        if not base_source:
            # Build base lines from removed and context lines
            base_lines = []
            for h in fd.hunks:
                for dl in h.lines:
                    if dl.kind in ("-", " "):
                        base_lines.append(dl.text)
            base_source = "\n".join(base_lines)

        if is_js_ts:
            base_blocks = extract_blocks_from_source(base_source, file_path=path)
            head_blocks = extract_blocks_from_source(head_source, file_path=path)

            old_ranges, new_ranges = touched_ranges(fd.hunks)
            removed_blocks = map_blocks_to_diff(base_blocks, old_ranges)
            added_blocks = map_blocks_to_diff(head_blocks, new_ranges)

            # Layer 1 & 2: Fix database matching
            block_matches = fix_db.match_blocks(removed_blocks, added_blocks, file_path=path)
            line_matches = fix_db.analyse_removed_guard_lines(fd, base_blocks, head_blocks, file_path=path)
            all_fix_matches.extend(block_matches)
            all_fix_matches.extend(line_matches)

            # Layer 3: Camouflage detection
            camo = detect_camouflage(removed_blocks, added_blocks)
            all_camouflage.extend(camo)

        # Layer 4: Pattern rules
        findings = rules_engine.evaluate_file(
            file_diff=fd,
            added_blocks=added_blocks,
            removed_blocks=removed_blocks,
            raw_diff=raw_diff
        )
        all_rule_findings.extend(findings)

        # Generate patches if this file had findings or fix matches
        file_has_signals = (
            any(fm.file_path == path for fm in all_fix_matches) or
            any(rf.file_path == path for rf in all_rule_findings)
        )
        if file_has_signals or is_js_ts:
            rev_patch = generate_revert_patch(fd)
            if rev_patch:
                revert_patches.append(rev_patch)

            # Gather all deleted guards for surgical restore
            file_removed_guards = [
                g for fm in all_fix_matches if fm.file_path == path
                for g in fm.removed_guards
            ]
            if file_removed_guards:
                rest_patch, rationale = generate_restore_guard_patch(
                    file_diff=fd,
                    removed_guards=file_removed_guards,
                    head_source=head_source,
                    path=path
                )
                if rest_patch:
                    restore_patches.append(rest_patch)
                    restore_rationales.append(rationale)

    # Risk evaluation
    risk: RiskAssessment = evaluate_risk(
        fix_matches=all_fix_matches,
        rule_findings=all_rule_findings,
        camouflage_matches=all_camouflage,
        files_count=files_analyzed,
        added_lines_count=total_added_lines,
        removed_lines_count=total_removed_lines,
        enforcement=enforcement,
        hold_hours=hold_hours
    )

    # Format findings payload
    formatted_findings: List[Dict[str, Any]] = []
    for fm in all_fix_matches:
        formatted_findings.append({
            "advisory_id": fm.advisory_id,
            "package": fm.package,
            "title": fm.title,
            "vuln_class": fm.vuln_class,
            "verdict": fm.verdict,
            "similarity": fm.similarity,
            "evidence": fm.evidence,
            "removed_guards": fm.removed_guards,
            "file_path": fm.file_path,
            "line_number": fm.line_number,
            "related_advisories": fm.related_advisories
        })

    for rf in all_rule_findings:
        formatted_findings.append({
            "rule_id": rf.rule_id,
            "name": rf.name,
            "category": rf.category,
            "severity": rf.severity,
            "weight": rf.weight,
            "file_path": rf.file_path,
            "line_number": rf.line_number,
            "matched_text": rf.matched_text,
            "detail": rf.detail,
            "verdict": "rule-violation"
        })

    formatted_camo: List[Dict[str, Any]] = [
        {
            "old_name": cm.old_name,
            "new_name": cm.new_name,
            "similarity": cm.similarity,
            "guard_delta": cm.guard_delta,
            "control_delta": cm.control_delta,
            "risk_points": cm.risk_points,
            "evidence": cm.evidence
        }
        for cm in all_camouflage
    ]

    patches_dict: Dict[str, Any] = {
        "revert_patch": "\n".join(revert_patches),
        "restore_guard_patch": "\n".join(restore_patches),
        "restore_rationale": " ".join(restore_rationales)
    }

    report_data = {
        "repo": repo,
        "pr_number": pr_number,
        "head_sha": head_sha,
        "title": title,
        "decision": risk.decision,
        "score": risk.score,
        "band": risk.band,
        "hard_block": risk.hard_block,
        "hold_hours": risk.hold_hours,
        "files_analyzed": files_analyzed,
        "findings": formatted_findings,
        "camouflage": formatted_camo,
        "evidence_table": risk.evidence_table,
        "patches": patches_dict
    }

    markdown_comment = render_comment(report_data)

    return Report(
        repo=repo,
        pr_number=pr_number,
        head_sha=head_sha,
        title=title,
        decision=risk.decision,
        score=risk.score,
        band=risk.band,
        hard_block=risk.hard_block,
        hold_hours=risk.hold_hours,
        files_analyzed=files_analyzed,
        findings=formatted_findings,
        camouflage=formatted_camo,
        evidence_table=risk.evidence_table,
        patches=patches_dict,
        markdown_comment=markdown_comment
    )

