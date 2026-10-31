from __future__ import annotations

import pytest
from engine.astnorm import (
    extract_blocks_from_source,
    map_blocks_to_diff,
    normalize_node,
    unescape_js_string,
    sequence_ratio,
    token_shingle_jaccard,
    get_language_for_path,
)
import tree_sitter


CODE_BASE = """function merge(target, source) {
  for (const key in source) {
    if (key === '__proto__') continue;
    target[key] = source[key];
  }
}
"""

CODE_RENAMED = """function merge(t, s) {
  for (let k in s) {
    if (k === "__proto__") continue;
    t[k] = s[k];
  }
}
"""

CODE_HEX_ESCAPED = """function merge(t, s) {
  for (let k in s) {
    if (k === '\\x5f\\x5fproto__') continue;
    t[k] = s[k];
  }
}
"""

CODE_CONCATENATED = """function merge(t, s) {
  for (let k in s) {
    if (k === "__" + "proto__") continue;
    t[k] = s[k];
  }
}
"""

CODE_NO_GUARD = """function merge(target, source) {
  for (const key in source) {
    target[key] = source[key];
  }
}
"""


def test_unescape_js_string():
    assert unescape_js_string(r"'\x5f\x5fproto__'") == "__proto__"
    assert unescape_js_string(r'"\u005f\u005fproto__"') == "__proto__"
    assert unescape_js_string(r"'hello\nworld'") == "hello\nworld"
    assert unescape_js_string(r'`simple`') == "simple"


def test_structural_normalisation_equality():
    blocks_base = extract_blocks_from_source(CODE_BASE)
    blocks_renamed = extract_blocks_from_source(CODE_RENAMED)
    blocks_escaped = extract_blocks_from_source(CODE_HEX_ESCAPED)
    blocks_concat = extract_blocks_from_source(CODE_CONCATENATED)

    assert len(blocks_base) == 1
    assert len(blocks_renamed) == 1
    assert len(blocks_escaped) == 1
    assert len(blocks_concat) == 1

    s_base = blocks_base[0].structural
    s_renamed = blocks_renamed[0].structural
    s_escaped = blocks_escaped[0].structural
    s_concat = blocks_concat[0].structural

    # All variations of PR #482 guarded merge must have identical structural strings!
    assert s_base == s_renamed
    assert s_base == s_escaped
    assert s_base == s_concat


def test_structural_normalisation_differs_without_guard():
    blocks_base = extract_blocks_from_source(CODE_BASE)
    blocks_no_guard = extract_blocks_from_source(CODE_NO_GUARD)

    assert blocks_base[0].structural != blocks_no_guard[0].structural
    assert "S[__proto__]" in blocks_base[0].structural
    assert "S[__proto__]" not in blocks_no_guard[0].structural


def test_extract_block_metadata():
    blocks = extract_blocks_from_source(CODE_BASE)
    b = blocks[0]
    assert b.name == "merge"
    assert b.kind == "function"
    assert b.control >= 2  # for-in and if
    assert "__proto__" in b.strings
    assert any("__proto__" in g for g in b.guards)


def test_map_blocks_to_diff():
    blocks = extract_blocks_from_source(CODE_BASE)
    # Block is at lines 1-6
    touched = map_blocks_to_diff(blocks, [(3, 3)])
    assert len(touched) == 1
    assert touched[0].name == "merge"

    # Non-overlapping range
    not_touched = map_blocks_to_diff(blocks, [(20, 25)])
    assert len(not_touched) == 0


def test_similarity_primitives():
    s1 = "function ID ( ID ) { if ( ID === S ) return ; }"
    s2 = "function ID ( ID ) { if ( ID === S ) return ; }"
    s3 = "class ID { method ( ) { return ; } }"

    assert sequence_ratio(s1, s2) == 1.0
    assert token_shingle_jaccard(s1, s2) == 1.0

    assert sequence_ratio(s1, s3) < 0.6
    assert token_shingle_jaccard(s1, s3) < 0.3

