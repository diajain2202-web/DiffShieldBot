"""
risk.py - Transparent additive risk scoring, bands, and quarantine decisions.

Deterministic, transparent scoring model without opaque weights.
Features hard-block short-circuiting, diminishing returns on multiple signals,
and strict consistency between band and quarantine decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from engine.fixdb import FixMatch
from engine.rules_engine import RuleFinding
from engine.similarity import CamouflageMatch


CRITICAL_THRESHOLD = 34


@dataclass
class RiskSignal:
    """A scored detection signal contributing to the total risk score."""
    name: str
    category: str
    points: int
    detail: str


@dataclass
class RiskAssessment:
    """The complete risk verdict, score, band, and itemized signals."""
    score: int
    band: str  # 'critical', 'high', 'medium', 'low', 'info'
    decision: str  # 'quarantine', 'flag', 'pass'
    hard_block: bool
    hold_hours: int
    signals: List[RiskSignal] = field(default_factory=list)
    evidence_table: List[dict] = field(default_factory=list)


def evaluate_risk(
    fix_matches: List[FixMatch],
    rule_findings: List[RuleFinding],
    camouflage_matches: List[CamouflageMatch],
    files_count: int = 1,
    added_lines_count: int = 0,
    removed_lines_count: int = 0,
    enforcement: str = "hold",
    hold_hours: int = 12
) -> RiskAssessment:
    """
    Compute total risk score, assign risk band, and decide whether to quarantine.
    """
    signals: List[RiskSignal] = []

    # 1. Historical CVE fix matches
    for fm in fix_matches:
        if fm.verdict == "reintroduced":
            pts = 40
        elif fm.verdict == "weakened":
            pts = 25
        elif fm.verdict == "touched":
            pts = 12
        else:
            pts = 0

        if pts > 0:
            signals.append(RiskSignal(
                name=f"Historical Fix Reversal ({fm.advisory_id})",
                category="historical-fix",
                points=pts,
                detail=fm.evidence
            ))

    # 2. Pattern rules
    for rf in rule_findings:
        signals.append(RiskSignal(
            name=f"Rule {rf.rule_id}: {rf.name}",
            category=rf.category,
            points=rf.weight,
            detail=f"{rf.file_path}:{rf.line_number} - {rf.matched_text}"
        ))

    # 3. Camouflage detection
    for cm in camouflage_matches:
        if cm.risk_points > 0:
            signals.append(RiskSignal(
                name=f"Camouflage / Defense Stripped ({cm.old_name} -> {cm.new_name})",
                category="camouflage",
                points=cm.risk_points,
                detail=cm.evidence
            ))

    # 4. Churn nudges
    if files_count > 8:
        signals.append(RiskSignal(
            name="High File Churn",
            category="churn",
            points=8,
            detail=f"PR modifies {files_count} files (>8 threshold)"
        ))
    if added_lines_count > 1500:
        signals.append(RiskSignal(
            name="High Line Churn",
            category="churn",
            points=6,
            detail=f"PR adds {added_lines_count} lines (>1500 threshold)"
        ))
    if added_lines_count == 0 and removed_lines_count > 0:
        signals.append(RiskSignal(
            name="Deletion-Only PR",
            category="churn",
            points=4,
            detail=f"PR only deletes code ({removed_lines_count} lines removed)"
        ))

    # Check for hard block: any signal >= CRITICAL_THRESHOLD (34)
    hard_block = any(s.points >= CRITICAL_THRESHOLD for s in signals)

    # Sort signals descending by points for diminishing returns
    sorted_signals = sorted(signals, key=lambda s: s.points, reverse=True)

    raw_score = 0.0
    for idx, s in enumerate(sorted_signals):
        if idx < 4:
            raw_score += s.points
        else:
            # Diminishing returns beyond 4 signals (half credit)
            raw_score += s.points * 0.5

    final_score = min(100, max(0, int(round(raw_score))))

    # Determine band based on raw score
    if final_score >= 80:
        band = "critical"
    elif final_score >= 60:
        band = "high"
    elif final_score >= 40:
        band = "medium"
    elif final_score >= 20:
        band = "low"
    else:
        band = "info"

    # Decision logic
    if final_score >= 60 or hard_block:
        decision = "quarantine"
    elif final_score >= 40:
        decision = "flag"
    else:
        decision = "pass"

    # Downgrade if enforcement is comment-only (dry run / notify only)
    effective_hold_hours = hold_hours
    if enforcement == "comment":
        if decision == "quarantine":
            decision = "flag"
        effective_hold_hours = 0
    elif enforcement == "block":
        # Block without timer
        effective_hold_hours = 0
    elif decision != "quarantine":
        effective_hold_hours = 0

    # Never let the band contradict the decision:
    # A quarantined PR is never labelled info/low/medium
    if decision == "quarantine":
        if band in ("info", "low", "medium"):
            band = "high"

    evidence_table = [
        {
            "signal": s.name,
            "category": s.category,
            "points": s.points,
            "detail": s.detail
        }
        for s in sorted_signals
    ]

    return RiskAssessment(
        score=final_score,
        band=band,
        decision=decision,
        hard_block=hard_block,
        hold_hours=effective_hold_hours,
        signals=sorted_signals,
        evidence_table=evidence_table
    )

