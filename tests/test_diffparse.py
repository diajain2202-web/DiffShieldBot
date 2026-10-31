from __future__ import annotations

import pytest
from engine.diffparse import (
    parse_unified_diff,
    forward_patch,
    apply_reverse_patch,
    reverse_patch,
    touched_ranges,
)


BASE_CODE = """function merge(target, source) {
  for (const key in source) {
    if (key === '__proto__') continue;
    target[key] = source[key];
  }
}
module.exports = merge;
"""

PATCH_PR482 = """--- a/merge.js
+++ b/merge.js
@@ -2,3 +2,2 @@
   for (const key in source) {
-    if (key === '__proto__') continue;
     target[key] = source[key];
"""

HEAD_CODE = """function merge(target, source) {
  for (const key in source) {
    target[key] = source[key];
  }
}
module.exports = merge;
"""


def test_parse_unified_diff_single_file():
    diffs = parse_unified_diff(PATCH_PR482)
    assert len(diffs) == 1
    fd = diffs[0]
    assert fd.old_path == "merge.js"
    assert fd.new_path == "merge.js"
    assert len(fd.hunks) == 1
    hunk = fd.hunks[0]
    assert hunk.old_start == 2
    assert hunk.new_start == 2
    assert len(hunk.removed_lines) == 1
    assert "if (key === '__proto__') continue;" in hunk.removed_lines[0].text
    assert len(hunk.added_lines) == 0


def test_forward_patch_roundtrip():
    diffs = parse_unified_diff(PATCH_PR482)
    hunks = diffs[0].hunks
    head = forward_patch(BASE_CODE, hunks)
    assert head.strip() == HEAD_CODE.strip()


def test_apply_reverse_patch_roundtrip():
    diffs = parse_unified_diff(PATCH_PR482)
    hunks = diffs[0].hunks
    restored = apply_reverse_patch(HEAD_CODE, hunks)
    assert restored.strip() == BASE_CODE.strip()


def test_roundtrip_composition():
    diffs = parse_unified_diff(PATCH_PR482)
    hunks = diffs[0].hunks
    head = forward_patch(BASE_CODE, hunks)
    roundtripped = apply_reverse_patch(head, hunks)
    assert roundtripped == BASE_CODE.strip()


def test_reverse_patch_format():
    diffs = parse_unified_diff(PATCH_PR482)
    rev = reverse_patch(diffs[0])
    assert "diff --git a/merge.js b/merge.js" in rev
    assert "--- a/merge.js" in rev
    assert "+++ b/merge.js" in rev
    assert "+    if (key === '__proto__') continue;" in rev


def test_touched_ranges():
    diffs = parse_unified_diff(PATCH_PR482)
    old_r, new_r = touched_ranges(diffs[0].hunks)
    assert old_r == [(3, 3)]
    assert new_r == []
