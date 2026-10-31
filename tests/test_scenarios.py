from __future__ import annotations

import pytest
from engine.analyse import analyse_pr
from scripts.scenarios import SCENARIOS, get_scenario_by_id


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.id)
def test_all_scenarios(scenario):
    contents = {}
    if scenario.base_source:
        contents[f"base:merge.js"] = scenario.base_source
        contents[f"base:validate.js"] = scenario.base_source
    if scenario.head_source:
        contents[f"head:merge.js"] = scenario.head_source
        contents[f"head:validate.js"] = scenario.head_source
        contents[f"head:telemetry.js"] = scenario.head_source

    report = analyse_pr(
        raw_diff=scenario.raw_diff,
        repo=scenario.repo,
        pr_number=scenario.pr_number,
        title=scenario.pr_title,
        file_contents=contents
    )

    # 1. Decision verification
    assert report.decision == scenario.expected_decision, (
        f"Scenario {scenario.id} failed: expected {scenario.expected_decision}, got {report.decision} (score {report.score})"
    )

    if scenario.is_attack:
        assert report.score >= 60 or report.hard_block
        if scenario.expected_cve_or_rule.startswith("CVE"):
            assert any(f.get("advisory_id") == scenario.expected_cve_or_rule for f in report.findings), (
                f"Expected advisory {scenario.expected_cve_or_rule} not found in findings"
            )
        elif scenario.expected_cve_or_rule.startswith("DS"):
            assert any(f.get("rule_id") == scenario.expected_cve_or_rule for f in report.findings), (
                f"Expected rule {scenario.expected_cve_or_rule} not found in findings"
            )
    else:
        # Benign control must pass with score < 40
        assert report.score < 40
        # Similarity must produce 0 points
        camo_points = sum(c.get("risk_points", 0) for c in report.camouflage)
        assert camo_points == 0

    # Scenario 1 specific checks: restore_guard.patch and revert.patch must be present
    if scenario.id == "scenario-1":
        assert report.patches.get("revert_patch")
        assert report.patches.get("restore_guard_patch")
        assert "if (key === '__proto__') continue;" in report.patches["restore_guard_patch"]

    # Scenario 6 specific check: DS011 must NOT fire when guard is intact
    if scenario.id == "scenario-6":
        assert not any(f.get("rule_id") == "DS011" for f in report.findings)

