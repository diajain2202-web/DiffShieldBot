from __future__ import annotations

import pytest
from engine.fixdb import FixMatch
from engine.risk import evaluate_risk, RiskSignal
from engine.rules_engine import RuleFinding
from engine.similarity import CamouflageMatch


def test_hard_block_critical_rule():
    critical_finding = RuleFinding(
        rule_id="DS001",
        name="Dynamic Eval",
        category="code-execution",
        severity="critical",
        weight=34,
        file_path="eval.js",
        line_number=1,
        matched_text="eval(code)",
        detail="Dynamic eval"
    )
    assessment = evaluate_risk(
        fix_matches=[],
        rule_findings=[critical_finding],
        camouflage_matches=[],
        files_count=1
    )
    assert assessment.hard_block is True
    assert assessment.decision == "quarantine"
    assert assessment.band in ("critical", "high")


def test_diminishing_returns_beyond_4_signals():
    findings = [
        RuleFinding(f"R{i}", f"Rule {i}", "cat", "medium", 12, "f.js", 1, "m", "d")
        for i in range(6)
    ]
    # First 4 = 12 * 4 = 48
    # 5th and 6th = (12 * 0.5) * 2 = 12
    # Total = 60
    assessment = evaluate_risk([], findings, [])
    assert assessment.score == 60


def test_band_never_contradicts_quarantine_decision():
    # Signal with exactly 34 points (hard block), but single signal so raw score is 34
    critical_finding = RuleFinding(
        rule_id="CRIT",
        name="Critical Signal",
        category="cat",
        severity="critical",
        weight=34,
        file_path="f.js",
        line_number=1,
        matched_text="crit",
        detail="crit"
    )
    assessment = evaluate_risk([], [critical_finding], [])
    assert assessment.decision == "quarantine"
    # Even though score is 34 (which would normally be 'medium'), band MUST NOT contradict decision!
    assert assessment.band in ("high", "critical")
    assert assessment.band != "medium"
    assert assessment.band != "low"


def test_churn_nudges():
    # > 8 files
    a_files = evaluate_risk([], [], [], files_count=10)
    assert any("High File Churn" in s.name for s in a_files.signals)
    assert a_files.score >= 8

    # > 1500 lines added
    a_lines = evaluate_risk([], [], [], added_lines_count=1600)
    assert any("High Line Churn" in s.name for s in a_lines.signals)
    assert a_lines.score >= 6

    # Deletion only
    a_del = evaluate_risk([], [], [], added_lines_count=0, removed_lines_count=50)
    assert any("Deletion-Only PR" in s.name for s in a_del.signals)
    assert a_del.score >= 4


def test_enforcement_comment_downgrades_to_flag():
    critical_finding = RuleFinding(
        rule_id="DS001",
        name="Dynamic Eval",
        category="code-execution",
        severity="critical",
        weight=34,
        file_path="eval.js",
        line_number=1,
        matched_text="eval(code)",
        detail="Dynamic eval"
    )
    assessment = evaluate_risk(
        fix_matches=[],
        rule_findings=[critical_finding],
        camouflage_matches=[],
        enforcement="comment"
    )
    assert assessment.decision == "flag"
    assert assessment.hold_hours == 0

