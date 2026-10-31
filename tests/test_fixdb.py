from __future__ import annotations

import pytest
from engine.astnorm import extract_blocks_from_source
from engine.diffparse import parse_unified_diff
from engine.fixdb import FixDatabase, FixMatch


BASE_MERGE = """function merge(target, source) {
  for (const key in source) {
    if (key === '__proto__') continue;
    target[key] = source[key];
  }
}
"""

HEAD_MERGE_UNGUARDED = """function merge(target, source) {
  for (const key in source) {
    target[key] = source[key];
  }
}
"""

DIFF_PR482 = """--- a/merge.js
+++ b/merge.js
@@ -2,3 +2,2 @@
   for (const key in source) {
-    if (key === '__proto__') continue;
     target[key] = source[key];
"""

# Two guards in base
BASE_TWO_GUARDS = """function parseOptions(k, v) {
  if (k === '__proto__') return;
  if (k === 'constructor') return;
  this[k] = v;
}
"""

HEAD_ONE_GUARD = """function parseOptions(k, v) {
  if (k === '__proto__') return;
  this[k] = v;
}
"""

DIFF_PARTIAL_REVERT = """--- a/options.js
+++ b/options.js
@@ -2,3 +2,2 @@
   if (k === '__proto__') return;
-  if (k === 'constructor') return;
   this[k] = v;
"""

# Surviving guard in DIFFERENT function
BASE_DIFFERENT_FN = """function merge(target, source) {
  for (const key in source) {
    if (key === '__proto__') continue;
    target[key] = source[key];
  }
}
function sanitize(k) {
  if (k === '__proto__') return false;
  return true;
}
"""

HEAD_DIFFERENT_FN = """function merge(target, source) {
  for (const key in source) {
    target[key] = source[key];
  }
}
function sanitize(k) {
  if (k === '__proto__') return false;
  return true;
}
"""

DIFF_DIFF_FN = """--- a/merge.js
+++ b/merge.js
@@ -2,3 +2,2 @@
   for (const key in source) {
-    if (key === '__proto__') continue;
     target[key] = source[key];
"""


def test_fix_seed_loaded():
    db = FixDatabase()
    assert len(db.advisories) >= 15
    ids = {a.id for a in db.advisories}
    assert "CVE-2019-10744" in ids
    assert "CVE-2021-3807" in ids
    assert "CVE-2024-21538" in ids


def test_pr482_line_level_match():
    db = FixDatabase()
    diffs = parse_unified_diff(DIFF_PR482)
    base_blocks = extract_blocks_from_source(BASE_MERGE)
    head_blocks = extract_blocks_from_source(HEAD_MERGE_UNGUARDED)

    matches = db.analyse_removed_guard_lines(diffs[0], base_blocks, head_blocks, file_path="merge.js")
    assert len(matches) > 0
    m = matches[0]
    assert m.advisory_id == "CVE-2019-10744"
    assert m.verdict == "reintroduced"
    assert "if (key === '__proto__') continue;" in m.removed_guards[0]


def test_partial_revert_detected():
    db = FixDatabase()
    diffs = parse_unified_diff(DIFF_PARTIAL_REVERT)
    base_blocks = extract_blocks_from_source(BASE_TWO_GUARDS)
    head_blocks = extract_blocks_from_source(HEAD_ONE_GUARD)

    matches = db.analyse_removed_guard_lines(diffs[0], base_blocks, head_blocks, file_path="options.js")
    assert len(matches) > 0
    assert any("constructor" in g for m in matches for g in m.removed_guards)


def test_guard_surviving_in_different_function_does_not_suppress():
    """
    Acceptance criterion 15:
    A guard surviving in a DIFFERENT function does not suppress a deleted guard.
    """
    db = FixDatabase()
    diffs = parse_unified_diff(DIFF_DIFF_FN)
    base_blocks = extract_blocks_from_source(BASE_DIFFERENT_FN)
    head_blocks = extract_blocks_from_source(HEAD_DIFFERENT_FN)

    matches = db.analyse_removed_guard_lines(diffs[0], base_blocks, head_blocks, file_path="merge.js")
    assert len(matches) > 0
    assert matches[0].advisory_id == "CVE-2019-10744"
    assert matches[0].verdict == "reintroduced"


def test_semantics_gate_prevents_false_positive():
    db = FixDatabase()
    unrelated_loop = """function copyArray(dest, src) {
  for (let i = 0; i < src.length; i++) {
    dest[i] = src[i];
  }
}
"""
    blocks = extract_blocks_from_source(unrelated_loop)
    adv = next(a for a in db.advisories if a.id == "CVE-2019-10744")
    assert not db._shares_semantics(blocks[0], adv)

