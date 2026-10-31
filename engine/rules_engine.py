"""
rules_engine.py - YAML-driven deterministic pattern rules engine.

Pure offline analysis. Hot-reloadable rules evaluating AST calls, tokens,
source strings, regular expressions, and heuristics with guard exclusion
and all_of gating. Non-code files (package.json, CI workflows) are evaluated
as raw text.
"""

from __future__ import annotations

import fnmatch
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Optional, Set

import yaml

from engine.astnorm import Block
from engine.diffparse import FileDiff, DiffLine

logger = logging.getLogger("diffshield.rules")


@dataclass
class RuleFinding:
    """Represents a rule violation detected in a PR diff."""
    rule_id: str
    name: str
    category: str
    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    weight: int
    file_path: str
    line_number: int
    matched_text: str
    detail: str


@dataclass
class Rule:
    """Parsed pattern rule definition."""
    id: str
    name: str
    category: str
    severity: str
    weight: int
    scope: str  # 'added', 'removed', 'any'
    files: List[str]
    ast_calls: List[str] = field(default_factory=list)
    ast_strings: List[str] = field(default_factory=list)
    ast_tokens: List[str] = field(default_factory=list)
    source_any: List[str] = field(default_factory=list)
    regex_any: List[str] = field(default_factory=list)
    compiled_regex: List[re.Pattern] = field(default_factory=list)
    heuristics: Dict[str, Any] = field(default_factory=dict)
    all_of: bool = False
    exclude_if_guard: bool = False


class RulesEngine:
    """Loads and evaluates deterministic security rules."""

    def __init__(self, rules_path: Optional[str] = None):
        if rules_path is None:
            rules_path = str(Path(__file__).parent.parent / "rules" / "default.yml")
        self.rules_path = rules_path
        self.rules: List[Rule] = []
        self.load_rules(rules_path)

    def load_rules(self, path: str) -> None:
        """Load and compile rules from YAML file."""
        p = Path(path)
        if not p.exists():
            logger.warning(f"Rules configuration file not found at {path}")
            return

        with open(p, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        raw_rules = data.get("rules", [])
        loaded: List[Rule] = []

        for r in raw_rules:
            ast_spec = r.get("ast", {}) or {}
            regexes = r.get("regex_any", []) or []
            compiled = []
            for rx in regexes:
                try:
                    compiled.append(re.compile(rx, re.IGNORECASE | re.MULTILINE))
                except re.error as err:
                    logger.error(f"Failed to compile regex '{rx}' for rule {r.get('id')}: {err}")

            rule = Rule(
                id=r.get("id", "UNKNOWN"),
                name=r.get("name", ""),
                category=r.get("category", "general"),
                severity=r.get("severity", "medium").lower(),
                weight=int(r.get("weight", 12)),
                scope=r.get("scope", "added").lower(),
                files=r.get("files", ["*"]),
                ast_calls=ast_spec.get("calls_any", []),
                ast_strings=ast_spec.get("strings_any", []),
                ast_tokens=ast_spec.get("tokens_any", []),
                source_any=r.get("source_any", []),
                regex_any=regexes,
                compiled_regex=compiled,
                heuristics=r.get("heuristics", {}) or {},
                all_of=bool(r.get("all_of", False)),
                exclude_if_guard=bool(r.get("exclude_if_guard", False))
            )
            loaded.append(rule)

        self.rules = loaded
        logger.info(f"Loaded {len(self.rules)} pattern rules from {path}")

    def _matches_file(self, rule: Rule, file_path: str) -> bool:
        """Check if file matches any glob in rule.files."""
        p = file_path.replace("\\", "/")
        name = Path(p).name
        for pattern in rule.files:
            if fnmatch.fnmatch(p, pattern) or fnmatch.fnmatch(name, pattern):
                return True
        return False

    def evaluate_file(
        self,
        file_diff: FileDiff,
        added_blocks: List[Block],
        removed_blocks: List[Block],
        raw_diff: str = ""
    ) -> List[RuleFinding]:
        """
        Evaluate all matching rules against a file's diff and blocks.
        """
        findings: List[RuleFinding] = []
        path = file_diff.path

        # Determine added lines and removed lines from diff
        added_lines: List[DiffLine] = []
        removed_lines: List[DiffLine] = []
        for h in file_diff.hunks:
            added_lines.extend(h.added_lines)
            removed_lines.extend(h.removed_lines)

        added_text = "\n".join(l.text for l in added_lines)
        removed_text = "\n".join(l.text for l in removed_lines)
        full_patch_text = raw_diff if raw_diff else (added_text + "\n" + removed_text)

        # Check guard delta across blocks
        added_guards_count = sum(len(b.guards) for b in added_blocks)
        removed_guards_count = sum(len(b.guards) for b in removed_blocks)
        guard_delta = added_guards_count - removed_guards_count

        for rule in self.rules:
            if not self._matches_file(rule, path):
                continue

            # Select target text and lines based on rule scope
            if rule.scope == "added":
                target_text = added_text
                target_lines = added_lines
                target_blocks = added_blocks
            elif rule.scope == "removed":
                target_text = removed_text
                target_lines = removed_lines
                target_blocks = removed_blocks
            else:
                target_text = full_patch_text
                target_lines = added_lines + removed_lines
                target_blocks = added_blocks + removed_blocks

            if not target_text.strip() and not rule.heuristics:
                continue

            # 1. Heuristics check
            heuristic_hit = False
            heuristic_required = bool(rule.heuristics)
            if "min_line_length" in rule.heuristics:
                limit = int(rule.heuristics["min_line_length"])
                for dl in target_lines:
                    if len(dl.text) >= limit:
                        heuristic_hit = True
                        findings.append(RuleFinding(
                            rule_id=rule.id,
                            name=rule.name,
                            category=rule.category,
                            severity=rule.severity,
                            weight=rule.weight,
                            file_path=path,
                            line_number=dl.new_no or dl.old_no or 1,
                            matched_text=dl.text[:80] + "...",
                            detail=f"Line length {len(dl.text)} exceeds minified threshold {limit}"
                        ))
                        break
            if "net_guard_delta_negative" in rule.heuristics:
                if guard_delta < 0:
                    heuristic_hit = True
                    findings.append(RuleFinding(
                        rule_id=rule.id,
                        name=rule.name,
                        category=rule.category,
                        severity=rule.severity,
                        weight=rule.weight,
                        file_path=path,
                        line_number=removed_lines[0].old_no if removed_lines else 1,
                        matched_text=f"net guard delta: {guard_delta}",
                        detail=f"Security guard deletion: {abs(guard_delta)} guard condition(s) removed without equivalent replacement."
                    ))

            if heuristic_required and not heuristic_hit:
                continue
            if heuristic_required and heuristic_hit and not (rule.ast_calls or rule.source_any or rule.compiled_regex):
                continue

            # 2. Guard exclusion check (e.g. for DS011)
            # If exclude_if_guard is True and target blocks or target lines contain an active guard condition, skip!
            if rule.exclude_if_guard:
                # Check if the surrounding blocks or patch has an intact guard check for __proto__ / prototype
                has_active_guard = False
                for b in added_blocks:
                    for g in b.guards:
                        if any(k in g for k in ("__proto__", "prototype", "constructor", "hasOwnProperty")):
                            has_active_guard = True
                            break
                    if has_active_guard:
                        break
                if not has_active_guard:
                    for dl in added_lines:
                        txt = dl.text.strip()
                        if (txt.startswith("if") or "continue" in txt or "return" in txt) and any(k in txt for k in ("__proto__", "prototype", "constructor")):
                            has_active_guard = True
                            break
                if has_active_guard:
                    # Guard is present and intact! Exclude this finding.
                    continue

            # 3. AST checks, source substring checks, and regex checks
            call_match = False
            token_match = False
            source_match = False
            regex_matches: List[str] = []

            # Check AST calls
            if rule.ast_calls:
                for b in target_blocks:
                    for c in b.calls:
                        if any(ac in c for ac in rule.ast_calls):
                            call_match = True
                            break
                    if call_match:
                        break

            # Check AST tokens
            if rule.ast_tokens:
                for b in target_blocks:
                    for tok in rule.ast_tokens:
                        if tok in b.source or tok in b.structural or tok in b.idents or tok in b.strings:
                            token_match = True
                            break
                    if token_match:
                        break

            # Check source substrings
            if rule.source_any:
                for s in rule.source_any:
                    if s in target_text:
                        source_match = True
                        break

            # Check regular expressions
            if rule.compiled_regex:
                for crx in rule.compiled_regex:
                    m = crx.search(target_text)
                    if m:
                        regex_matches.append(m.group(0))

            # Combine matches according to all_of
            matched = False
            first_match_text = ""

            if rule.all_of:
                # All configured dimensions must be satisfied
                conditions: List[bool] = []
                if rule.compiled_regex:
                    conditions.append(len(regex_matches) == len(rule.compiled_regex))
                if rule.source_any:
                    conditions.append(source_match)
                if rule.ast_calls:
                    conditions.append(call_match)
                if rule.ast_tokens:
                    conditions.append(token_match)

                matched = len(conditions) > 0 and all(conditions)
                if matched:
                    first_match_text = regex_matches[0] if regex_matches else (rule.source_any[0] if rule.source_any else "pattern match")
            else:
                # Any configured dimension matches
                if regex_matches:
                    matched = True
                    first_match_text = regex_matches[0]
                elif source_match:
                    matched = True
                    first_match_text = rule.source_any[0]
                elif call_match:
                    matched = True
                    first_match_text = rule.ast_calls[0]
                elif token_match:
                    matched = True
                    first_match_text = rule.ast_tokens[0]

            if matched:
                # Find line number of the match
                line_no = 1
                for dl in target_lines:
                    if first_match_text and first_match_text in dl.text:
                        line_no = dl.new_no or dl.old_no or 1
                        break
                    elif any(rx in dl.text for rx in regex_matches):
                        line_no = dl.new_no or dl.old_no or 1
                        break

                findings.append(RuleFinding(
                    rule_id=rule.id,
                    name=rule.name,
                    category=rule.category,
                    severity=rule.severity,
                    weight=rule.weight,
                    file_path=path,
                    line_number=line_no,
                    matched_text=first_match_text[:120],
                    detail=f"Pattern rule {rule.id} fired: {rule.name}"
                ))

        return findings

