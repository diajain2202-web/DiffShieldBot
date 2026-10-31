"""
fixdb.py - Historical fix index and multi-layer reverse-fix matching.

Pure offline analysis. Loads curated CVE fix entries, matches both at
AST-block level and line level against diffs to detect reintroduced or
weakened historical vulnerabilities.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple

from engine.astnorm import (
    Block,
    extract_blocks_from_source,
    normalize_node,
    sequence_ratio,
    token_shingle_jaccard,
    GUARD_TOKENS,
    SECURITY_SENSITIVE_IDENTS,
    SECURITY_SENSITIVE_STRINGS,
)
from engine.diffparse import FileDiff, DiffLine

logger = logging.getLogger("diffshield.fixdb")


@dataclass
class FixAdvisory:
    """Historical security fix entry from seed database."""
    id: str
    package: str
    ecosystem: str
    language: str
    title: str
    advisory: str
    fix_commit: str
    fix_block: str
    trigger_strings: List[str]
    vuln_class: str
    fix_kind: str
    notes: str
    parsed_block: Optional[Block] = None


@dataclass
class FixMatch:
    """Result of matching code modifications against a known fix."""
    advisory_id: str
    package: str
    title: str
    vuln_class: str
    verdict: str  # 'reintroduced', 'weakened', 'touched', 'unrelated'
    similarity: float
    evidence: str
    removed_guards: List[str]
    file_path: str
    line_number: int
    related_advisories: List[str] = field(default_factory=list)


class FixDatabase:
    """Index of historical CVE fixes with block-level and line-level matching."""

    def __init__(self, seed_path: Optional[str] = None):
        self.advisories: List[FixAdvisory] = []
        if seed_path is None:
            # Default to data/fix_seed.json relative to repo root
            seed_path = str(Path(__file__).parent.parent / "data" / "fix_seed.json")
        self.load_seed(seed_path)

    def load_seed(self, path: str) -> None:
        p = Path(path)
        if not p.exists():
            logger.warning(f"Fix seed database not found at {path}")
            return

        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)

        for item in data:
            advisory = FixAdvisory(
                id=item["id"],
                package=item.get("package", ""),
                ecosystem=item.get("ecosystem", "npm"),
                language=item.get("language", "javascript"),
                title=item.get("title", ""),
                advisory=item.get("advisory", ""),
                fix_commit=item.get("fix_commit", ""),
                fix_block=item.get("fix_block", ""),
                trigger_strings=item.get("trigger_strings", []),
                vuln_class=item.get("vuln_class", ""),
                fix_kind=item.get("fix_kind", "guard-check"),
                notes=item.get("notes", "")
            )
            # Pre-parse fix block
            blocks = extract_blocks_from_source(advisory.fix_block, file_path="fix.js")
            if blocks:
                advisory.parsed_block = blocks[0]
            self.advisories.append(advisory)

        logger.info(f"Loaded {len(self.advisories)} historical CVE fix entries from {path}")

    def _shares_semantics(self, block: Block, advisory: FixAdvisory) -> bool:
        """
        Precision gate: must mention trigger strings or security-sensitive identifiers
        from the fix block. Without this gate, structural normalisation produces
        false positives on unrelated loops/functions.
        """
        # 1. Check advisory trigger strings against block content
        block_text = f"{block.source} {' '.join(block.strings)} {' '.join(block.idents)} {block.structural}"
        for trigger in advisory.trigger_strings:
            if trigger in block_text or trigger in block.source:
                return True

        # 2. Check security sensitive identifiers present in the advisory's fix block
        if advisory.parsed_block:
            advisory_security_idents = set(advisory.parsed_block.idents).intersection(SECURITY_SENSITIVE_IDENTS)
            block_security_idents = set(block.idents).intersection(SECURITY_SENSITIVE_IDENTS)
            if advisory_security_idents and advisory_security_idents.intersection(block_security_idents):
                return True

            advisory_security_strings = set(advisory.parsed_block.strings).intersection(SECURITY_SENSITIVE_STRINGS)
            block_security_strings = set(block.strings).intersection(SECURITY_SENSITIVE_STRINGS)
            if advisory_security_strings and advisory_security_strings.intersection(block_security_strings):
                return True

        return False

    def _guard_fingerprint(self, block: Block) -> Set[str]:
        """
        Extract defensive constructs visible in source and structural AST representations.
        """
        fingerprints: Set[str] = set()
        # Look for guard tokens in guards and source
        for g in block.guards:
            for token in GUARD_TOKENS:
                if token in g:
                    fingerprints.add(f"guard:{token}")
            if "__proto__" in g:
                fingerprints.add("guard:proto")
            if "prototype" in g:
                fingerprints.add("guard:prototype")
            if "constructor" in g:
                fingerprints.add("guard:constructor")

        for line in block.source.splitlines():
            s = line.strip()
            if s.startswith("if") or "continue" in s or "throw" in s or "return" in s:
                for token in GUARD_TOKENS:
                    if token in s:
                        fingerprints.add(f"guard:{token}")
                if "__proto__" in s:
                    fingerprints.add("guard:proto")
                if "prototype" in s:
                    fingerprints.add("guard:prototype")
                if "constructor" in s:
                    fingerprints.add("guard:constructor")

        return fingerprints

    def match_blocks(
        self,
        removed_blocks: List[Block],
        added_blocks: List[Block],
        file_path: str = "index.js"
    ) -> List[FixMatch]:
        """
        Layer 1 & 2: Match removed blocks and added blocks against the fix database.
        Detects full reintroductions and weakened replacements.
        Folds secondary advisories into related_advisories to avoid score inflation.
        """
        matches: List[FixMatch] = []

        for rem_b in removed_blocks:
            block_candidates: List[Tuple[float, FixAdvisory, str, List[str]]] = []

            for advisory in self.advisories:
                if not advisory.parsed_block:
                    continue

                adv_block = advisory.parsed_block
                if not self._shares_semantics(rem_b, advisory):
                    continue

                adv_guards = self._guard_fingerprint(adv_block)
                rem_guards = self._guard_fingerprint(rem_b)
                shared_guards = rem_guards.intersection(adv_guards)
                if not shared_guards and not any(t in rem_b.source for t in advisory.trigger_strings):
                    continue

                seq_sim = sequence_ratio(rem_b.structural, adv_block.structural)
                jacc_sim = token_shingle_jaccard(rem_b.structural, adv_block.structural)
                similarity = max(seq_sim, jacc_sim)

                reintroduced = True
                weakened = False
                replacement_b: Optional[Block] = None

                for add_b in added_blocks:
                    if add_b.name == rem_b.name or sequence_ratio(rem_b.structural, add_b.structural) >= 0.65:
                        replacement_b = add_b
                        add_guards = self._guard_fingerprint(add_b)
                        if shared_guards.issubset(add_guards) or any(t in add_b.source for t in advisory.trigger_strings):
                            reintroduced = False
                        else:
                            weakened = True
                        break

                if reintroduced or weakened:
                    verdict = "reintroduced" if (reintroduced and not replacement_b) or (replacement_b and weakened) else "weakened"
                    dropped_guard_texts = [
                        line.strip() for line in rem_b.source.splitlines()
                        if any(t in line for t in advisory.trigger_strings) and any(gt in line for gt in GUARD_TOKENS)
                    ]
                    if not dropped_guard_texts:
                        dropped_guard_texts = [g for g in rem_b.guards if any(t in g for t in advisory.trigger_strings)]

                    block_candidates.append((similarity, advisory, verdict, dropped_guard_texts))

            if block_candidates:
                # Sort by similarity descending
                block_candidates.sort(key=lambda c: c[0], reverse=True)
                best_sim, best_adv, best_verdict, best_dropped = block_candidates[0]
                related = [c[1].id for c in block_candidates[1:]]

                ev = (
                    f"Structural similarity {int(best_sim * 100)}% to fix for {best_adv.id} "
                    f"({best_adv.title}), which added defensive guards stripped here."
                )
                matches.append(FixMatch(
                    advisory_id=best_adv.id,
                    package=best_adv.package,
                    title=best_adv.title,
                    vuln_class=best_adv.vuln_class,
                    verdict=best_verdict,
                    similarity=round(best_sim, 3),
                    evidence=ev,
                    removed_guards=best_dropped,
                    file_path=file_path,
                    line_number=rem_b.start_line,
                    related_advisories=related
                ))

        return matches

    def analyse_removed_guard_lines(
        self,
        file_diff: FileDiff,
        base_blocks: List[Block],
        head_blocks: List[Block],
        file_path: str = "index.js"
    ) -> List[FixMatch]:
        """
        Layer 2 (line-level): Detects partial reverts where a single defensive guard line
        was removed from a function, even if the surrounding block was otherwise retained.
        Scope is the function: a guard surviving in another function does NOT defend this one.
        """
        matches: List[FixMatch] = []
        seen_advisories: Set[str] = set()

        for hunk in file_diff.hunks:
            for dl in hunk.removed_lines:
                text = dl.text.strip()
                if not text:
                    continue

                # A removed line counts as a deleted defense if:
                # 1. mentions an advisory trigger string
                # 2. reads as a comparison or early exit
                has_guard_construct = any(gt in text for gt in GUARD_TOKENS)
                if not has_guard_construct:
                    continue

                matched_advisories = [
                    adv for adv in self.advisories
                    if any(trig in text for trig in adv.trigger_strings)
                ]
                if not matched_advisories:
                    continue

                # Find which function/block in base contained this line
                old_line_no = dl.old_no or hunk.old_start
                parent_base_fn: Optional[Block] = None
                for b in base_blocks:
                    if b.start_line <= old_line_no <= b.end_line:
                        parent_base_fn = b
                        break

                # Find triggers that were specifically present in the removed line
                removed_line_triggers = [
                    trig for adv in matched_advisories
                    for trig in adv.trigger_strings
                    if trig in text
                ]

                # Scope check: Look for corresponding function in head_blocks
                still_defended = False
                if parent_base_fn:
                    for hb in head_blocks:
                        # Match replacement function by name or high structural similarity
                        if hb.name == parent_base_fn.name or sequence_ratio(parent_base_fn.structural, hb.structural) >= 0.75:
                            # Check if hb still checks ALL triggers that were removed
                            hb_text = f"{hb.source} {' '.join(hb.guards)}"
                            if all(r_trig in hb_text for r_trig in removed_line_triggers):
                                still_defended = True
                                break

                if not still_defended:
                    primary_adv = matched_advisories[0]
                    if primary_adv.id in seen_advisories:
                        continue
                    seen_advisories.add(primary_adv.id)

                    related = [a.id for a in matched_advisories[1:]]
                    ev = (
                        f"Line-level deleted defense: '{text}' matched trigger for {primary_adv.id} "
                        f"({primary_adv.title}). Guard was not preserved in replacement function."
                    )
                    matches.append(FixMatch(
                        advisory_id=primary_adv.id,
                        package=primary_adv.package,
                        title=primary_adv.title,
                        vuln_class=primary_adv.vuln_class,
                        verdict="reintroduced",
                        similarity=0.95,
                        evidence=ev,
                        removed_guards=[text],
                        file_path=file_path,
                        line_number=old_line_no,
                        related_advisories=related
                    ))

        return matches
