"""
astnorm.py - Tree-sitter JS/TS block extraction and disguise-proof structural normalisation.

Pure offline analysis. Cuts files into semantic blocks (functions, methods, classes,
statements), extracts calls/idents/strings/guards/control metrics, and computes
canonical structural normalisations that defeat obfuscation, renaming, quote switching,
escape sequences, and string concatenation.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Set, Tuple, Optional, Dict, Any

import tree_sitter
import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts


# Security-sensitive identifiers kept verbatim in structural normalization
SECURITY_SENSITIVE_IDENTS: Set[str] = {
    "eval", "Function", "child_process", "exec", "execSync", "spawn", "spawnSync",
    "require", "process", "env", "fetch", "__proto__", "prototype", "constructor",
    "Object", "assign", "encodeURIComponent", "hasOwnProperty", "writeFile",
    "writeFileSync", "chmod", "chmodSync", "innerHTML", "outerHTML", "document",
    "write", "setTimeout", "setInterval", "vm", "runInThisContext", "runInNewContext",
    "fs", "net", "http", "https", "url", "crypto"
}

# Security-sensitive string keywords decoded and retained as S[value]
SECURITY_SENSITIVE_STRINGS: Set[str] = {
    "__proto__", "prototype", "constructor", "child_process", "eval", "Function",
    "exec", "spawn", "fs", "net", "http", "https", "postinstall", "preinstall",
    "install", "/bin/sh", "/bin/bash", "cmd.exe", "powershell", "SELECT", "INSERT",
    "UPDATE", "DELETE", "DROP", "UNION", "id_rsa", ".env", "GITHUB_TOKEN"
}

# Guard-identifying tokens and patterns
GUARD_TOKENS: Set[str] = {
    "===", "!==", "==", "!=", "continue", "throw", "return", "break",
    "includes", "indexOf", "hasOwnProperty", "typeof", "instanceof", "startsWith", "endsWith"
}


@dataclass
class Block:
    """Represents a code block (function, method, class, statement)."""
    name: str
    kind: str  # 'function', 'method', 'arrow', 'class', 'statement'
    start_line: int  # 1-indexed
    end_line: int    # 1-indexed
    source: str
    structural: str
    calls: List[str] = field(default_factory=list)
    idents: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    guards: List[str] = field(default_factory=list)
    control: int = 0


# Initialize tree-sitter parsers lazily
_JS_LANG: Optional[tree_sitter.Language] = None
_TS_LANG: Optional[tree_sitter.Language] = None
_TSX_LANG: Optional[tree_sitter.Language] = None


def get_language_for_path(path: str) -> tree_sitter.Language:
    """Return the tree-sitter Language for the given file extension."""
    global _JS_LANG, _TS_LANG, _TSX_LANG
    ext = Path(path).suffix.lower()

    if ext in (".tsx",):
        if _TSX_LANG is None:
            _TSX_LANG = tree_sitter.Language(tsts.language_tsx())
        return _TSX_LANG
    elif ext in (".ts", ".mts", ".cts"):
        if _TS_LANG is None:
            _TS_LANG = tree_sitter.Language(tsts.language_typescript())
        return _TS_LANG
    else:
        # Default to JS (.js, .mjs, .cjs, .jsx, etc.)
        if _JS_LANG is None:
            _JS_LANG = tree_sitter.Language(tsjs.language())
        return _JS_LANG


def unescape_js_string(s: str) -> str:
    """
    Decode JavaScript string escape sequences:
    \\xHH (hex), \\uHHHH (unicode), \\n, \\r, \\t, quotes, backslashes.
    """
    s = s.strip()
    if len(s) >= 2 and s[0] in ('"', "'", '`') and s[-1] == s[0]:
        s = s[1:-1]

    def _replace_esc(m: re.Match) -> str:
        if m.group(1):  # \\xHH
            return chr(int(m.group(1), 16))
        if m.group(2):  # \\uHHHH
            return chr(int(m.group(2), 16))
        if m.group(3):
            c = m.group(3)
            return {
                'n': '\n', 'r': '\r', 't': '\t', '0': '\0',
                '\\': '\\', "'": "'", '"': '"', '`': '`'
            }.get(c, c)
        return m.group(0)

    return re.sub(r'\\x([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})|\\(.)', _replace_esc, s)


def is_security_relevant_string(val: str) -> bool:
    """Check if decoded string matches security keywords or patterns."""
    if val in SECURITY_SENSITIVE_STRINGS:
        return True
    if any(k in val for k in ("__proto__", "prototype", "constructor")):
        return True
    return False


def _try_eval_string_concat(node: tree_sitter.Node, src: bytes) -> Optional[str]:
    """
    Evaluate string concatenation (e.g. '__' + 'proto__') at AST level
    so concatenated disguises are resolved.
    """
    if node.type == "binary_expression":
        has_plus = False
        for child in node.children:
            if child.type == "+":
                has_plus = True
                break
        if has_plus:
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left and right and left.type in ("string", "template_string") and right.type in ("string", "template_string"):
                s1 = unescape_js_string(src[left.start_byte:left.end_byte].decode("utf8", errors="ignore"))
                s2 = unescape_js_string(src[right.start_byte:right.end_byte].decode("utf8", errors="ignore"))
                joined = s1 + s2
                if is_security_relevant_string(joined):
                    return f"S[{joined}]"
                return "S"
    return None


def normalize_node(node: tree_sitter.Node, src: bytes) -> str:
    """
    Produce canonical disguise-proof structural string from AST node.
    - Preserves node types, operators, keywords
    - Drops comments and formatting
    - Replaces ordinary identifiers with 'ID'
    - Retains security-sensitive identifiers verbatim
    - Normalizes string literals to S or S[decoded-value]
    - Folds string concatenations
    - Normalizes var/let/const declarations
    """
    # Drop comments entirely
    if "comment" in node.type:
        return ""

    # Check for string concatenation fold
    concat_result = _try_eval_string_concat(node, src)
    if concat_result is not None:
        return concat_result

    # Atomic string / template literal handling
    if node.type in ("string", "template_string"):
        raw_text = src[node.start_byte:node.end_byte].decode("utf8", errors="ignore").strip()
        decoded = unescape_js_string(raw_text)
        if is_security_relevant_string(decoded):
            return f"S[{decoded}]"
        return "S"

    # Leaf token handling
    if not node.children:
        text = src[node.start_byte:node.end_byte].decode("utf8", errors="ignore").strip()
        if not text:
            return ""

        if node.type in ("identifier", "property_identifier"):
            return text if text in SECURITY_SENSITIVE_IDENTS else "ID"
        if node.type in ("number", "decimal"):
            return "NUM"
        if node.type in ("var", "let", "const"):
            return "DECL"
        return text

    # Recursive traversal
    parts: List[str] = []
    for child in node.children:
        part = normalize_node(child, src)
        if part:
            parts.append(part)
    return " ".join(parts)


def extract_block_metadata(node: tree_sitter.Node, src: bytes) -> Tuple[List[str], List[str], List[str], List[str], int]:
    """
    Extract calls, idents, strings, guards, and control count from an AST node subtree.
    """
    calls: List[str] = []
    idents: List[str] = []
    strings: List[str] = []
    guards: List[str] = []
    control_count = 0

    control_types = {
        "if_statement", "switch_statement", "for_statement", "for_in_statement",
        "for_of_statement", "while_statement", "do_statement", "try_statement",
        "throw_statement", "return_statement", "continue_statement", "break_statement"
    }

    def walk(n: tree_sitter.Node) -> None:
        nonlocal control_count
        if "comment" in n.type:
            return

        if n.type in control_types:
            control_count += 1

        if n.type == "call_expression":
            fn_node = n.child_by_field_name("function")
            if fn_node:
                fn_name = src[fn_node.start_byte:fn_node.end_byte].decode("utf8", errors="ignore").strip()
                calls.append(fn_name)

        elif n.type in ("identifier", "property_identifier"):
            ident = src[n.start_byte:n.end_byte].decode("utf8", errors="ignore").strip()
            if ident:
                idents.append(ident)

        elif n.type in ("string", "template_string"):
            raw = src[n.start_byte:n.end_byte].decode("utf8", errors="ignore").strip()
            dec = unescape_js_string(raw)
            if dec:
                strings.append(dec)

        # Detect guards in conditions
        if n.type in ("if_statement", "while_statement", "for_statement"):
            cond = n.child_by_field_name("condition")
            if cond:
                cond_text = src[cond.start_byte:cond.end_byte].decode("utf8", errors="ignore").strip()
                guards.append(cond_text)

        for child in n.children:
            walk(child)

    walk(node)
    return calls, idents, strings, guards, control_count


def extract_blocks_from_source(source: str, file_path: str = "index.js") -> List[Block]:
    """
    Parse source code with tree-sitter and cut into semantic blocks:
    functions, methods, arrow functions, classes, and top-level statements.
    """
    if not source or not source.strip():
        return []

    src_bytes = source.encode("utf8")
    lang = get_language_for_path(file_path)
    parser = tree_sitter.Parser(lang)
    tree = parser.parse(src_bytes)

    blocks: List[Block] = []

    block_types = {
        "function_declaration": ("function", True),
        "function_expression": ("function", True),
        "arrow_function": ("arrow", False),
        "method_definition": ("method", True),
        "class_declaration": ("class", True),
        "class_expression": ("class", True),
    }

    def get_node_name(node: tree_sitter.Node) -> str:
        name_node = node.child_by_field_name("name")
        if name_node:
            return src_bytes[name_node.start_byte:name_node.end_byte].decode("utf8", errors="ignore").strip()
        # Look for parent assignment if arrow function
        parent = node.parent
        if parent and parent.type == "variable_declarator":
            var_name = parent.child_by_field_name("name")
            if var_name:
                return src_bytes[var_name.start_byte:var_name.end_byte].decode("utf8", errors="ignore").strip()
        return "anonymous"

    # Walk top-level statements and find functions / classes / expressions
    for top_node in tree.root_node.children:
        if "comment" in top_node.type:
            continue

        if top_node.type in block_types:
            kind, _ = block_types[top_node.type]
            name = get_node_name(top_node)
            s_line = top_node.start_point.row + 1
            e_line = top_node.end_point.row + 1
            source_slice = src_bytes[top_node.start_byte:top_node.end_byte].decode("utf8", errors="ignore")
            structural = normalize_node(top_node, src_bytes)
            calls, idents, strings, guards, control = extract_block_metadata(top_node, src_bytes)
            blocks.append(Block(
                name=name,
                kind=kind,
                start_line=s_line,
                end_line=e_line,
                source=source_slice,
                structural=structural,
                calls=calls,
                idents=idents,
                strings=strings,
                guards=guards,
                control=control
            ))
        elif top_node.type == "variable_declaration" or top_node.type == "lexical_declaration":
            # Check if variable declaration contains arrow or function
            found_inner_fn = False
            for decl in top_node.children:
                if decl.type == "variable_declarator":
                    init = decl.child_by_field_name("value")
                    if init and init.type in block_types:
                        kind, _ = block_types[init.type]
                        name = get_node_name(init)
                        s_line = top_node.start_point.row + 1
                        e_line = top_node.end_point.row + 1
                        source_slice = src_bytes[top_node.start_byte:top_node.end_byte].decode("utf8", errors="ignore")
                        structural = normalize_node(top_node, src_bytes)
                        calls, idents, strings, guards, control = extract_block_metadata(top_node, src_bytes)
                        blocks.append(Block(
                            name=name,
                            kind=kind,
                            start_line=s_line,
                            end_line=e_line,
                            source=source_slice,
                            structural=structural,
                            calls=calls,
                            idents=idents,
                            strings=strings,
                            guards=guards,
                            control=control
                        ))
                        found_inner_fn = True
            if not found_inner_fn:
                # Top-level statement block
                s_line = top_node.start_point.row + 1
                e_line = top_node.end_point.row + 1
                source_slice = src_bytes[top_node.start_byte:top_node.end_byte].decode("utf8", errors="ignore")
                structural = normalize_node(top_node, src_bytes)
                calls, idents, strings, guards, control = extract_block_metadata(top_node, src_bytes)
                blocks.append(Block(
                    name="top-level",
                    kind="statement",
                    start_line=s_line,
                    end_line=e_line,
                    source=source_slice,
                    structural=structural,
                    calls=calls,
                    idents=idents,
                    strings=strings,
                    guards=guards,
                    control=control
                ))
        else:
            # Top-level statement block
            s_line = top_node.start_point.row + 1
            e_line = top_node.end_point.row + 1
            source_slice = src_bytes[top_node.start_byte:top_node.end_byte].decode("utf8", errors="ignore")
            structural = normalize_node(top_node, src_bytes)
            calls, idents, strings, guards, control = extract_block_metadata(top_node, src_bytes)
            blocks.append(Block(
                name="top-level",
                kind="statement",
                start_line=s_line,
                end_line=e_line,
                source=source_slice,
                structural=structural,
                calls=calls,
                idents=idents,
                strings=strings,
                guards=guards,
                control=control
            ))

    return blocks


def map_blocks_to_diff(blocks: List[Block], touched_line_ranges: List[Tuple[int, int]]) -> List[Block]:
    """
    Returns blocks that overlap with any touched (added or removed) line range in the diff.
    Overlap condition: max(block.start_line, r_start) <= min(block.end_line, r_end).
    """
    touched_blocks: List[Block] = []
    for block in blocks:
        overlaps = False
        for r_start, r_end in touched_line_ranges:
            if max(block.start_line, r_start) <= min(block.end_line, r_end):
                overlaps = True
                break
        if overlaps:
            touched_blocks.append(block)
    return touched_blocks


def sequence_ratio(s1: str, s2: str) -> float:
    """Standard difflib SequenceMatcher ratio between two strings."""
    if not s1 and not s2:
        return 1.0
    if not s1 or not s2:
        return 0.0
    return difflib.SequenceMatcher(None, s1, s2).ratio()


def token_shingle_jaccard(s1: str, s2: str, n: int = 3) -> float:
    """
    Token-shingle Jaccard similarity.
    Breaks strings into whitespace-separated tokens, builds n-grams, computes |A ∩ B| / |A ∪ B|.
    """
    tokens1 = s1.split()
    tokens2 = s2.split()

    if len(tokens1) < n or len(tokens2) < n:
        set1 = set(tokens1)
        set2 = set(tokens2)
    else:
        set1 = set(" ".join(tokens1[i:i + n]) for i in range(len(tokens1) - n + 1))
        set2 = set(" ".join(tokens2[i:i + n]) for i in range(len(tokens2) - n + 1))

    if not set1 and not set2:
        return 1.0
    if not set1 or not set2:
        return 0.0

    intersection = len(set1.intersection(set2))
    union = len(set1.union(set2))
    return float(intersection) / float(union) if union > 0 else 0.0

