"""
similarity.py - Local deterministic vector embeddings and camouflage detection.

No LLM. Computes 512-dimensional signed hash embeddings (unigrams + trigrams)
using blake2b and L2 normalisation. Detects camouflaged code movement or rewrites
where defensive guards or control flow structures were silently stripped.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from engine.astnorm import Block


@dataclass
class CamouflageMatch:
    """Represents a near-duplicate block rewritten or moved with reduced defenses."""
    old_name: str
    new_name: str
    similarity: float
    guard_delta: int  # added_guards - removed_guards
    control_delta: int  # added_control - removed_control
    risk_points: int
    old_line: int
    new_line: int
    evidence: str


class HashedEmbedder:
    """
    Deterministic, zero-dependency 512-dimensional signed feature hasher.
    Hashes unigrams and token-trigrams using blake2b, normalised with L2.
    """

    DIM = 512

    def __init__(self, dim: int = DIM):
        self.dim = dim

    def embed(self, text: str) -> List[float]:
        """Convert input code/text to an L2-normalised float vector."""
        if not text or not text.strip():
            return [0.0] * self.dim

        tokens = [t for t in re.split(r"\W+", text) if t]
        if not tokens:
            return [0.0] * self.dim

        vec = [0.0] * self.dim

        # 1. Unigrams
        for tok in tokens:
            self._hash_and_accumulate(tok, vec, weight=1.0)

        # 2. Token trigrams
        for i in range(len(tokens) - 2):
            trigram = f"{tokens[i]}_{tokens[i+1]}_{tokens[i+2]}"
            self._hash_and_accumulate(trigram, vec, weight=1.5)

        # L2-normalisation
        norm_sq = sum(x * x for x in vec)
        if norm_sq > 0.0:
            inv_norm = 1.0 / math.sqrt(norm_sq)
            return [x * inv_norm for x in vec]
        return vec

    def _hash_and_accumulate(self, feature: str, vec: List[float], weight: float = 1.0) -> None:
        digest = hashlib.blake2b(feature.encode("utf8"), digest_size=8).digest()
        val = int.from_bytes(digest, "little", signed=True)
        bucket = abs(val) % self.dim
        sign = 1.0 if val > 0 else -1.0
        vec[bucket] += sign * weight

    def cosine_similarity(self, v1: List[float], v2: List[float]) -> float:
        """Compute cosine similarity between two unit vectors."""
        if len(v1) != self.dim or len(v2) != self.dim:
            return 0.0
        # For unit vectors, dot product equals cosine similarity
        dot = sum(a * b for a, b in zip(v1, v2))
        return max(-1.0, min(1.0, dot))


# Optional sentence-transformers support behind env flag
_ST_MODEL = None


def get_embedder() -> HashedEmbedder:
    """Return embedder implementation based on environment configuration."""
    backend = os.getenv("DIFFSHIELD_EMBEDDER", "hashed").lower()
    if backend == "st":
        global _ST_MODEL
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore
            if _ST_MODEL is None:
                _ST_MODEL = SentenceTransformer("all-MiniLM-L6-v2")
            return _ST_MODEL
        except Exception:
            pass
    return HashedEmbedder()


def compute_similarity(b1: Block, b2: Block) -> float:
    """Compute semantic similarity between two blocks using local embedder."""
    embedder = get_embedder()
    v1 = embedder.embed(b1.structural or b1.source)
    v2 = embedder.embed(b2.structural or b2.source)
    return embedder.cosine_similarity(v1, v2)


def detect_camouflage(
    removed_blocks: List[Block],
    added_blocks: List[Block],
    threshold: float = 0.82
) -> List[CamouflageMatch]:
    """
    Detect camouflaged code movement or rewriting.
    Only emits risk points when guard_delta < 0 or control_delta < 0.
    A pure rename produces zero points.
    """
    embedder = HashedEmbedder()
    matches: List[CamouflageMatch] = []

    for rem_b in removed_blocks:
        rem_vec = embedder.embed(rem_b.structural or rem_b.source)
        for add_b in added_blocks:
            add_vec = embedder.embed(add_b.structural or add_b.source)
            sim = embedder.cosine_similarity(rem_vec, add_vec)

            if sim >= threshold:
                guard_delta = len(add_b.guards) - len(rem_b.guards)
                control_delta = add_b.control - rem_b.control

                risk_points = 0
                if guard_delta < 0:
                    # Guard lost: min(30, 10 + 6 * |guard_delta|)
                    risk_points = min(30, 10 + 6 * abs(guard_delta))
                    ev = (
                        f"Code moved/rewritten with guards removed ({sim*100:.1f}% similarity, "
                        f"{abs(guard_delta)} guard(s) deleted, -{risk_points} pts risk)"
                    )
                elif control_delta < 0:
                    # Control flow reduced
                    risk_points = 4
                    ev = (
                        f"Relocation with less control flow ({sim*100:.1f}% similarity, "
                        f"control delta {control_delta})"
                    )
                else:
                    # Pure rename or safe refactor: ZERO points
                    risk_points = 0
                    ev = f"Honest refactor / rename ({sim*100:.1f}% similarity, intact defenses)"

                matches.append(CamouflageMatch(
                    old_name=rem_b.name,
                    new_name=add_b.name,
                    similarity=round(sim, 3),
                    guard_delta=guard_delta,
                    control_delta=control_delta,
                    risk_points=risk_points,
                    old_line=rem_b.start_line,
                    new_line=add_b.start_line,
                    evidence=ev
                ))

    return matches

