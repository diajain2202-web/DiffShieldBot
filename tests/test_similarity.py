from __future__ import annotations

import pytest
from engine.astnorm import extract_blocks_from_source
from engine.similarity import HashedEmbedder, detect_camouflage


CODE_BASE = """function merge(target, source) {
  for (const key in source) {
    if (key === '__proto__') continue;
    target[key] = source[key];
  }
}
"""

CODE_RENAMED_SAFE = """function safeMerge(t, s) {
  for (const k in s) {
    if (k === '__proto__') continue;
    t[k] = s[k];
  }
}
"""

CODE_STRIPPED = """function merge(target, source) {
  for (const key in source) {
    target[key] = source[key];
  }
}
"""


def test_hashed_embedder_deterministic():
    emb = HashedEmbedder()
    v1 = emb.embed(CODE_BASE)
    v2 = emb.embed(CODE_BASE)
    assert len(v1) == 512
    assert v1 == v2
    assert emb.cosine_similarity(v1, v2) == pytest.approx(1.0, 1e-4)


def test_pure_rename_produces_zero_risk_points():
    """Acceptance criterion 5: honest refactor produces zero points from similarity."""
    rem_blocks = extract_blocks_from_source(CODE_BASE)
    add_blocks = extract_blocks_from_source(CODE_RENAMED_SAFE)
    matches = detect_camouflage(rem_blocks, add_blocks, threshold=0.80)
    assert len(matches) > 0
    m = matches[0]
    assert m.risk_points == 0
    assert m.guard_delta >= 0


def test_camouflage_with_guard_loss_emits_points():
    rem_blocks = extract_blocks_from_source(CODE_BASE)
    add_blocks = extract_blocks_from_source(CODE_STRIPPED)
    matches = detect_camouflage(rem_blocks, add_blocks, threshold=0.80)
    assert len(matches) > 0
    m = matches[0]
    assert m.risk_points >= 10
    assert m.guard_delta < 0

