"""
diffparse.py - Unified diff parser, patch application, and reverse patch generator.

Pure offline analysis. Parses unified diffs into structured hunks and lines,
provides forward and reverse patch application primitives, and computes
touched line ranges for AST block mapping.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Tuple, Optional


HUNK_HEADER_RE = re.compile(
    r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@(.*)$"
)
DIFF_GIT_RE = re.compile(r"^diff --git a/(.*?) b/(.*)$")
OLD_FILE_RE = re.compile(r"^---\s+(?:a/)?(.*)$")
NEW_FILE_RE = re.compile(r"^\+\+\+\s+(?:b/)?(.*)$")


@dataclass
class DiffLine:
    """Represents a single line within a diff hunk."""
    kind: str  # '+', '-', ' '
    text: str  # Line content without the leading +/-/' '
    old_no: Optional[int] = None
    new_no: Optional[int] = None


@dataclass
class Hunk:
    """Represents a diff hunk with coordinate ranges and lines."""
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    header: str
    lines: List[DiffLine] = field(default_factory=list)

    @property
    def removed_lines(self) -> List[DiffLine]:
        return [l for l in self.lines if l.kind == "-"]

    @property
    def added_lines(self) -> List[DiffLine]:
        return [l for l in self.lines if l.kind == "+"]

    @property
    def context_lines(self) -> List[DiffLine]:
        return [l for l in self.lines if l.kind == " "]


@dataclass
class FileDiff:
    """Represents a single file's modifications in a diff."""
    old_path: str
    new_path: str
    hunks: List[Hunk] = field(default_factory=list)
    is_new: bool = False
    is_deleted: bool = False
    is_rename: bool = False

    @property
    def path(self) -> str:
        return self.new_path or self.old_path

    @property
    def added_count(self) -> int:
        return sum(len(h.added_lines) for h in self.hunks)

    @property
    def removed_count(self) -> int:
        return sum(len(h.removed_lines) for h in self.hunks)


def parse_unified_diff(raw_diff: str) -> List[FileDiff]:
    """
    Parse a unified diff string (git diff or GitHub API patch) into FileDiff objects.
    Handles multiple files, missing headers, and standard GitHub patch chunks.
    """
    if not raw_diff or not raw_diff.strip():
        return []

    lines = raw_diff.splitlines()
    file_diffs: List[FileDiff] = []
    
    current_file: Optional[FileDiff] = None
    current_hunk: Optional[Hunk] = None
    old_no = 0
    new_no = 0

    i = 0
    while i < len(lines):
        line = lines[i]

        # Check for git diff header: diff --git a/file b/file
        git_match = DIFF_GIT_RE.match(line)
        if git_match:
            old_p, new_p = git_match.groups()
            current_file = FileDiff(old_path=old_p, new_path=new_p)
            file_diffs.append(current_file)
            current_hunk = None
            i += 1
            continue

        # Check for new file mode / deleted file mode
        if line.startswith("new file mode") and current_file:
            current_file.is_new = True
            i += 1
            continue
        if line.startswith("deleted file mode") and current_file:
            current_file.is_deleted = True
            i += 1
            continue
        if line.startswith("similarity index") and current_file:
            current_file.is_rename = True
            i += 1
            continue

        # Check for --- a/file
        old_match = OLD_FILE_RE.match(line)
        if old_match and not line.startswith("--- /dev/null"):
            old_p = old_match.group(1).strip()
            if current_file is None:
                current_file = FileDiff(old_path=old_p, new_path=old_p)
                file_diffs.append(current_file)
            else:
                current_file.old_path = old_p
            i += 1
            continue
        elif line.startswith("--- /dev/null"):
            if current_file is None:
                current_file = FileDiff(old_path="/dev/null", new_path="", is_new=True)
                file_diffs.append(current_file)
            else:
                current_file.old_path = "/dev/null"
                current_file.is_new = True
            i += 1
            continue

        # Check for +++ b/file
        new_match = NEW_FILE_RE.match(line)
        if new_match and not line.startswith("+++ /dev/null"):
            new_p = new_match.group(1).strip()
            if current_file is None:
                current_file = FileDiff(old_path=new_p, new_path=new_p)
                file_diffs.append(current_file)
            else:
                current_file.new_path = new_p
            i += 1
            continue
        elif line.startswith("+++ /dev/null"):
            if current_file is not None:
                current_file.new_path = "/dev/null"
                current_file.is_deleted = True
            i += 1
            continue

        # Check for hunk header: @@ -old_start,old_count +new_start,new_count @@
        hunk_match = HUNK_HEADER_RE.match(line)
        if hunk_match:
            if current_file is None:
                current_file = FileDiff(old_path="unknown", new_path="unknown")
                file_diffs.append(current_file)

            old_start = int(hunk_match.group(1))
            old_count = int(hunk_match.group(2)) if hunk_match.group(2) is not None else 1
            new_start = int(hunk_match.group(3))
            new_count = int(hunk_match.group(4)) if hunk_match.group(4) is not None else 1
            header_suffix = hunk_match.group(5)

            current_hunk = Hunk(
                old_start=old_start,
                old_count=old_count,
                new_start=new_start,
                new_count=new_count,
                header=header_suffix.strip()
            )
            current_file.hunks.append(current_hunk)
            old_no = old_start
            new_no = new_start
            i += 1
            continue

        # Diff content lines
        if current_hunk is not None:
            if line.startswith("+"):
                current_hunk.lines.append(DiffLine(kind="+", text=line[1:], old_no=None, new_no=new_no))
                new_no += 1
            elif line.startswith("-"):
                current_hunk.lines.append(DiffLine(kind="-", text=line[1:], old_no=old_no, new_no=None))
                old_no += 1
            elif line.startswith(" ") or line == "":
                # Context line: empty string or space prefix
                txt = line[1:] if line.startswith(" ") else ""
                current_hunk.lines.append(DiffLine(kind=" ", text=txt, old_no=old_no, new_no=new_no))
                old_no += 1
                new_no += 1
            elif line.startswith("\\ No newline at end of file"):
                pass  # Ignore newline marker
            else:
                # Unexpected line outside hunk; could be commentary or new file
                pass
        i += 1

    return file_diffs


def touched_ranges(hunks: List[Hunk]) -> Tuple[List[Tuple[int, int]], List[Tuple[int, int]]]:
    """
    Returns (old_touched_ranges, new_touched_ranges) as 1-indexed (start_line, end_line) tuples.
    Used for mapping tree-sitter AST blocks to modified diff regions.
    """
    old_ranges: List[Tuple[int, int]] = []
    new_ranges: List[Tuple[int, int]] = []

    for hunk in hunks:
        # Group contiguous '-' lines
        cur_old_start: Optional[int] = None
        last_old: Optional[int] = None
        for dl in hunk.lines:
            if dl.kind == "-":
                if cur_old_start is None:
                    cur_old_start = dl.old_no
                last_old = dl.old_no
            else:
                if cur_old_start is not None and last_old is not None:
                    old_ranges.append((cur_old_start, last_old))
                    cur_old_start = None
                    last_old = None
        if cur_old_start is not None and last_old is not None:
            old_ranges.append((cur_old_start, last_old))

        # Group contiguous '+' lines
        cur_new_start: Optional[int] = None
        last_new: Optional[int] = None
        for dl in hunk.lines:
            if dl.kind == "+":
                if cur_new_start is None:
                    cur_new_start = dl.new_no
                last_new = dl.new_no
            else:
                if cur_new_start is not None and last_new is not None:
                    new_ranges.append((cur_new_start, last_new))
                    cur_new_start = None
                    last_new = None
        if cur_new_start is not None and last_new is not None:
            new_ranges.append((cur_new_start, last_new))

    return old_ranges, new_ranges


def forward_patch(base: str, hunks: List[Hunk]) -> str:
    """
    Apply diff hunks forward to the base text to produce the head text.
    Round-trip primitive: forward_patch(base, hunks) -> head.
    """
    base_lines = base.splitlines()
    result_lines: List[str] = []
    base_idx = 0  # 0-indexed cursor in base_lines

    for hunk in hunks:
        target_base_idx = hunk.old_start - 1 if hunk.old_start > 0 else 0
        # Copy base lines up to the start of this hunk
        while base_idx < target_base_idx and base_idx < len(base_lines):
            result_lines.append(base_lines[base_idx])
            base_idx += 1

        # Process lines within the hunk
        for dl in hunk.lines:
            if dl.kind == " ":
                if base_idx < len(base_lines):
                    result_lines.append(base_lines[base_idx])
                    base_idx += 1
                else:
                    result_lines.append(dl.text)
            elif dl.kind == "-":
                # Removed from base
                base_idx += 1
            elif dl.kind == "+":
                # Added to head
                result_lines.append(dl.text)

    # Copy remaining base lines
    while base_idx < len(base_lines):
        result_lines.append(base_lines[base_idx])
        base_idx += 1

    return "\n".join(result_lines)


def apply_reverse_patch(head: str, hunks: List[Hunk]) -> str:
    """
    Apply the inverse of diff hunks to head text to restore the base text.
    Round-trip primitive: apply_reverse_patch(head, hunks) -> base.
    """
    head_lines = head.splitlines()
    result_lines: List[str] = []
    head_idx = 0  # 0-indexed cursor in head_lines

    for hunk in hunks:
        target_head_idx = hunk.new_start - 1 if hunk.new_start > 0 else 0
        while head_idx < target_head_idx and head_idx < len(head_lines):
            result_lines.append(head_lines[head_idx])
            head_idx += 1

        # Process lines in reverse logic
        for dl in hunk.lines:
            if dl.kind == " ":
                if head_idx < len(head_lines):
                    result_lines.append(head_lines[head_idx])
                    head_idx += 1
                else:
                    result_lines.append(dl.text)
            elif dl.kind == "+":
                # Skip added lines (undo addition)
                head_idx += 1
            elif dl.kind == "-":
                # Restore removed lines
                result_lines.append(dl.text)

    while head_idx < len(head_lines):
        result_lines.append(head_lines[head_idx])
        head_idx += 1

    return "\n".join(result_lines)


def reverse_patch(file_diff: FileDiff) -> str:
    """
    Generate unified diff text shaped as:
    diff --git a/{path} b/{path}
    --- a/{path}
    +++ b/{path}
    @@ -old,+new @@
    which, when applied with git apply or patch -p1, restores the original code.
    """
    path = file_diff.new_path or file_diff.old_path
    lines: List[str] = [
        f"diff --git a/{path} b/{path}",
        f"--- a/{path}",
        f"+++ b/{path}",
    ]

    for hunk in file_diff.hunks:
        # Inverted coordinates:
        # old side becomes hunk.new_start, hunk.new_count
        # new side becomes hunk.old_start, hunk.old_count
        hdr = f"@@ -{hunk.new_start},{hunk.new_count} +{hunk.old_start},{hunk.old_count} @@"
        lines.append(hdr)
        for dl in hunk.lines:
            if dl.kind == " ":
                lines.append(f" {dl.text}")
            elif dl.kind == "+":
                # In reverse patch, newly added line is removed
                lines.append(f"-{dl.text}")
            elif dl.kind == "-":
                # In reverse patch, previously removed line is restored
                lines.append(f"+{dl.text}")

    return "\n".join(lines) + "\n"

