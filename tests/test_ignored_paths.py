from __future__ import annotations

import pytest
from engine.analyse import should_ignore_file, analyse_pr


DIFF_DIST_FILE = """--- a/dist/bundle.js
+++ b/dist/bundle.js
@@ -1,2 +1,3 @@
 function merge(target, source) {
-  if (key === '__proto__') continue;
   target[key] = source[key];
 }
"""

DIFF_MIN_FILE = """--- a/vendor.min.js
+++ b/vendor.min.js
@@ -1,2 +1,3 @@
 function merge(target, source) {
-  if (key === '__proto__') continue;
   target[key] = source[key];
 }
"""


def test_should_ignore_file():
    assert should_ignore_file("dist/bundle.js") is True
    assert should_ignore_file("build/dist/app.js") is True
    assert should_ignore_file("static/jquery.min.js") is True
    assert should_ignore_file("node_modules/pkg/index.js") is True
    assert should_ignore_file("src/merge.js") is False
    assert should_ignore_file("package.json") is False


def test_analysis_skips_ignored_files():
    report = analyse_pr(
        raw_diff=DIFF_DIST_FILE,
        repo="test/repo",
        pr_number=1
    )
    # Ignored files are not analyzed and produce no quarantine findings
    assert report.files_analyzed == 0
    assert report.decision == "pass"
    assert report.score == 0

    report_min = analyse_pr(
        raw_diff=DIFF_MIN_FILE,
        repo="test/repo",
        pr_number=2
    )
    assert report_min.files_analyzed == 0
    assert report_min.decision == "pass"
    assert report_min.score == 0

