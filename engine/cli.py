"""
cli.py - DiffShield command-line interface.

Provides standalone offline CLI operations:
  scan    - Scan unified diff from file or stdin, output report/markdown, exit non-zero on quarantine.
  reverse - Generate revert.patch and surgical restore_guard.patch.
  demo    - Interactive terminal walkthrough of PR #482 scenario.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from engine.analyse import analyse_pr


DEMO_PR482_DIFF = """--- a/merge.js
+++ b/merge.js
@@ -2,3 +2,2 @@
   for (const key in source) {
-    if (key === '__proto__') continue;
     target[key] = source[key];
"""


def cmd_scan(args: argparse.Namespace) -> int:
    if args.patch_file:
        raw_diff = Path(args.patch_file).read_text(encoding="utf-8")
    else:
        raw_diff = sys.stdin.read()

    report = analyse_pr(
        raw_diff=raw_diff,
        repo=args.repo,
        pr_number=args.pr_number,
        title=args.title,
        enforcement=args.enforcement,
        hold_hours=args.hold_hours
    )

    if args.out:
        Path(args.out).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        print(f"Report written to {args.out}")

    if args.markdown:
        Path(args.markdown).write_text(report.markdown_comment, encoding="utf-8")
        print(f"Markdown comment written to {args.markdown}")

    if args.patches_dir:
        p_dir = Path(args.patches_dir)
        p_dir.mkdir(parents=True, exist_ok=True)
        if report.patches.get("revert_patch"):
            (p_dir / "revert.patch").write_text(report.patches["revert_patch"], encoding="utf-8")
        if report.patches.get("restore_guard_patch"):
            (p_dir / "restore_guard.patch").write_text(report.patches["restore_guard_patch"], encoding="utf-8")
        print(f"Patches saved in {args.patches_dir}/")

    print(f"\nDiffShield Scan Complete: Verdict = {report.decision.upper()} (Score: {report.score}/100, Band: {report.band.upper()})")
    for row in report.evidence_table:
        print(f"  [{row['points']:>2} pts] {row['signal']} - {row['detail']}")

    # Exit non-zero on quarantine
    if report.decision == "quarantine":
        return 1
    return 0


def cmd_scenarios(args: argparse.Namespace) -> int:
    from scripts.scenarios import SCENARIOS

    print("=" * 76)
    print("  DIFFSHIELD LIVE MULTI-SCENARIO VERIFICATION MATRIX")
    print("=" * 76)

    for sc in SCENARIOS:
        contents = {}
        if sc.base_source:
            contents["base:merge.js"] = sc.base_source
            contents["base:validate.js"] = sc.base_source
        if sc.head_source:
            contents["head:merge.js"] = sc.head_source
            contents["head:validate.js"] = sc.head_source
            contents["head:telemetry.js"] = sc.head_source

        report = analyse_pr(
            raw_diff=sc.raw_diff,
            repo=sc.repo,
            pr_number=sc.pr_number,
            title=sc.pr_title,
            file_contents=contents
        )

        icon = "[QUARANTINE]" if report.decision == "quarantine" else "[PASS]"
        print(f"\n{icon} [{report.decision.upper():<10}] {sc.name}")
        print(f"   Target: {sc.repo} #{sc.pr_number} | Score: {report.score}/100 ({report.band.upper()}) | Hold: {report.hold_hours}h")
        for row in report.evidence_table[:2]:
            det = row['detail'][:65]
            print(f"   - [+{row['points']:>2} pts] {row['signal']}: {det}...")
        if report.patches.get("restore_guard_patch"):
            rest_lines = [l for l in report.patches["restore_guard_patch"].splitlines() if l.startswith("+") and not l.startswith("+++")]
            print(f"   - Surgical Restoration: {rest_lines}")

    print("\n" + "=" * 76)
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    print("=" * 68)
    print("  DIFFSHIELD DEMO: SCENARIO PR #482 (CVE-2019-10744)")
    print("=" * 68)
    print("\nPR Diff:")
    print(DEMO_PR482_DIFF)

    report = analyse_pr(
        raw_diff=DEMO_PR482_DIFF,
        repo="lodash/lodash",
        pr_number=482,
        title="Simplify merge for performance"
    )

    print("-" * 68)
    print(f"VERDICT:     {report.decision.upper()}")
    print(f"SCORE:       {report.score}/100 ({report.band.upper()})")
    print(f"HOLD:        {report.hold_hours} hours")
    print(f"HARD BLOCK:  {report.hard_block}")
    print("-" * 68)

    print("\nEVIDENCE TABLE:")
    for row in report.evidence_table:
        print(f"  + {row['points']:>2} pts | {row['signal']:<35} | {row['detail']}")

    print("\nFINDINGS:")
    for f in report.findings:
        adv = f.get("advisory_id") or f.get("rule_id")
        title = f.get("title") or f.get("name")
        print(f"  - {adv}: {title}")
        print(f"    Evidence: {f.get('evidence')}")
        if f.get("removed_guards"):
            print(f"    Removed Guard: {f['removed_guards']}")

    print("\nSURGICAL RESTORATION PATCH (restore_guard.patch):")
    print(report.patches.get("restore_guard_patch", "None"))

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="diffshield", description="DiffShield AppSec PR Guardian")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a PR diff")
    scan_parser.add_argument("--patch-file", help="Path to unified diff file")
    scan_parser.add_argument("--title", default="Pull Request Scan", help="PR title")
    scan_parser.add_argument("--repo", default="org/repo", help="Repository full name")
    scan_parser.add_argument("--pr-number", type=int, default=1, help="PR number")
    scan_parser.add_argument("--enforcement", default="hold", choices=["hold", "block", "close", "comment"])
    scan_parser.add_argument("--hold-hours", type=int, default=12)
    scan_parser.add_argument("--out", help="Output path for JSON report")
    scan_parser.add_argument("--markdown", help="Output path for Markdown comment")
    scan_parser.add_argument("--patches-dir", help="Output directory for generated patches")

    # Demo command
    demo_parser = subparsers.add_parser("demo", help="Run PR #482 demo scenario")

    # Scenarios command
    scenarios_parser = subparsers.add_parser("scenarios", help="Run all 6 verification scenarios")

    args = parser.parse_args()

    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "demo":
        return cmd_demo(args)
    elif args.command == "scenarios":
        return cmd_scenarios(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())

