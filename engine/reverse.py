"""
reverse.py - Surgical restore_guard.patch and git revert.patch generation.

Generates two remediation artifacts per flagged file:
1. revert.patch: clean git-applicable unified diff undoing the PR.
2. restore_guard.patch: surgical patch that re-inserts only the deleted defensive
   guards into the post-PR code without throwing away valid performance or feature changes.
"""

from __future__ import annotations

from typing import List, Tuple, Optional
from engine.diffparse import FileDiff, reverse_patch, Hunk, DiffLine


def generate_revert_patch(file_diff: FileDiff) -> str:
    """Generate git-applicable unified diff undoing all PR changes in this file."""
    return reverse_patch(file_diff)


def generate_restore_guard_patch(
    file_diff: FileDiff,
    removed_guards: List[str],
    head_source: str,
    path: Optional[str] = None
) -> Tuple[str, str]:
    """
    Generate surgical patch re-inserting deleted security guards into the post-PR code.
    Returns (patch_content, rationale).
    """
    file_path = path or file_diff.path
    if not removed_guards:
        return "", "No deleted security guards identified for surgical restoration."

    # Verify guards are not already re-added elsewhere in added lines
    added_texts = [
        dl.text.strip()
        for h in file_diff.hunks
        for dl in h.added_lines
    ]
    guards_to_restore = []
    seen = set()
    for g in removed_guards:
        clean_g = g.strip()
        if not clean_g or clean_g in seen:
            continue
        # If clean_g is just an expression like "(key === '__proto__')" but a full statement "if (key === '__proto__') continue;" exists, skip the expression
        if clean_g.startswith("(") and any(other.startswith("if") and clean_g in other for other in removed_guards):
            continue
        # Check if already present in added code
        if not any(clean_g in at for at in added_texts):
            guards_to_restore.append(clean_g)
            seen.add(clean_g)

    if not guards_to_restore:
        return "", "All security guards were re-implemented in the modified code."

    head_lines = head_source.splitlines()
    if not head_lines:
        return "", "Post-PR file is empty; cannot generate surgical restore patch."

    # Identify best insertion location in head_lines
    # Look for the context line immediately following or preceding the deletion in hunks
    target_idx = -1
    matched_guard = guards_to_restore[0]
    indent = "    "

    # Search hunks for context lines around the removed guard
    for hunk in file_diff.hunks:
        for idx, dl in enumerate(hunk.lines):
            if dl.kind == "-" and any(g in dl.text for g in guards_to_restore):
                # Check indentation of original guard
                match_indent = dl.text[:len(dl.text) - len(dl.text.lstrip())]
                if match_indent:
                    indent = match_indent

                # Look at subsequent context or added line
                for after_dl in hunk.lines[idx + 1:]:
                    after_txt = after_dl.text.strip()
                    if after_txt:
                        # Find after_txt in head_lines
                        for h_idx, hl in enumerate(head_lines):
                            if after_txt in hl:
                                target_idx = h_idx
                                break
                    if target_idx != -1:
                        break
            if target_idx != -1:
                break
        if target_idx != -1:
            break

    # Fallback: if context line not matched, search for loop or sink in head_lines
    if target_idx == -1:
        for h_idx, hl in enumerate(head_lines):
            if any(k in hl for k in ("for (", "while (", "forEach", "Object.keys")):
                target_idx = h_idx + 1
                break

    if target_idx == -1:
        target_idx = max(0, len(head_lines) // 2)

    # Build surgical patch around target_idx
    ctx_start = max(0, target_idx - 1)
    ctx_end = min(len(head_lines), target_idx + 2)

    old_start = ctx_start + 1
    old_count = ctx_end - ctx_start
    new_start = old_start
    new_count = old_count + len(guards_to_restore)

    patch_lines = [
        f"diff --git a/{file_path} b/{file_path}",
        f"--- a/{file_path}",
        f"+++ b/{file_path}",
        f"@@ -{old_start},{old_count} +{new_start},{new_count} @@"
    ]

    for i in range(ctx_start, target_idx):
        patch_lines.append(f" {head_lines[i]}")

    for g in guards_to_restore:
        patch_lines.append(f"+{indent}{g}")

    for i in range(target_idx, ctx_end):
        patch_lines.append(f" {head_lines[i]}")

    patch_text = "\n".join(patch_lines) + "\n"
    rationale = (
        f"Surgically restores defensive guard(s): {', '.join(repr(g) for g in guards_to_restore)} "
        f"at line {target_idx + 1} to close security vulnerability while retaining PR feature changes."
    )

    return patch_text, rationale
