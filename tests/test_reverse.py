from __future__ import annotations

import pytest
from engine.diffparse import parse_unified_diff
from engine.reverse import generate_revert_patch, generate_restore_guard_patch


DIFF_MERGE = """--- a/merge.js
+++ b/merge.js
@@ -2,3 +2,2 @@
   for (const key in source) {
-    if (key === '__proto__') continue;
     target[key] = source[key];
"""

HEAD_MERGE = """function merge(target, source) {
  for (const key in source) {
    target[key] = source[key];
  }
}
"""

DIFF_GUARD_RE_ADDED = """--- a/merge.js
+++ b/merge.js
@@ -2,3 +2,3 @@
   for (const key in source) {
-    if (key === '__proto__') continue;
+    if (key === '__proto__') continue;
     target[key] = source[key];
"""


def test_revert_patch_generation():
    diffs = parse_unified_diff(DIFF_MERGE)
    revert = generate_revert_patch(diffs[0])
    assert "diff --git a/merge.js b/merge.js" in revert
    assert "--- a/merge.js" in revert
    assert "+++ b/merge.js" in revert
    # In revert, the removed line is restored with a '+'
    assert "+    if (key === '__proto__') continue;" in revert


def test_surgical_restore_guard_patch():
    diffs = parse_unified_diff(DIFF_MERGE)
    patch, rationale = generate_restore_guard_patch(
        file_diff=diffs[0],
        removed_guards=["if (key === '__proto__') continue;"],
        head_source=HEAD_MERGE,
        path="merge.js"
    )
    assert "diff --git a/merge.js b/merge.js" in patch
    assert "+    if (key === '__proto__') continue;" in patch
    assert "Surgically restores defensive guard" in rationale


def test_surgical_restore_skipped_if_already_readded():
    diffs = parse_unified_diff(DIFF_GUARD_RE_ADDED)
    patch, rationale = generate_restore_guard_patch(
        file_diff=diffs[0],
        removed_guards=["if (key === '__proto__') continue;"],
        head_source=HEAD_MERGE,
        path="merge.js"
    )
    assert patch == ""
    assert "All security guards were re-implemented" in rationale

