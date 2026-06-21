"""Embedding providers with an offline, deterministic fallback.

When ``OPENAI_API_KEY`` is available we use OpenAI embeddings. Otherwise we use
:class:`HashingEmbeddings` — a dependency-free, deterministic bag-of-words hash
embedding. It is obviously weaker than a neural embedding, but it is stable,
fast and good enough for keyword-style RAG over the bundled knowledge base,
which keeps the FAISS pipeline fully functional offline.
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import List, Sequence

import numpy as np

from config import get_logger, get_settings

logger = get_logger(__name__)

_TOKEN_RE = re.compile(r"[a-z0-9]+")


class HashingEmbeddings:
    """Deterministic hashing embedding compatible with the LangChain API."""

    def __init__(self, dim: int = 384) -> None:
        self.dim = dim
        self.model_name = f"hashing-{dim}"

    def _embed(self, text: str) -> List[float]:
        vec = np.zeros(self.dim, dtype=np.float32)
        tokens = _TOKEN_RE.findall((text or "").lower())
        for tok in tokens:
            h = int(hashlib.md5(tok.encode("utf-8")).hexdigest(), 16)
            idx = h % self.dim
            sign = 1.0 if (h >> 8) % 2 == 0 else -1.0
            vec[idx] += sign
        norm = float(np.linalg.norm(vec))
        if norm > 0:
            vec /= norm
        return vec.tolist()

    def embed_documents(self, texts: Sequence[str]) -> List[List[float]]:
        return [self._embed(t) for t in texts]

    def embed_query(self, text: str) -> List[float]:
        return self._embed(text)


def get_embeddings():
    """Return an embeddings object exposing ``embed_documents`` / ``embed_query``.

    When OpenAI is configured we construct OpenAI embeddings *and run a tiny
    health probe*. If the probe fails (e.g. an invalid/misconfigured API key or
    network error) we transparently fall back to the deterministic hashing
    embeddings. Probing up-front guarantees a single, consistent backend for
    both indexing and querying (avoiding embedding-dimension mismatches).
    """
    settings = get_settings()
    if settings.has_openai:
        try:
            from langchain_openai import OpenAIEmbeddings

            emb = OpenAIEmbeddings(
                model=settings.csai_embedding_model,
                api_key=settings.openai_api_key,
            )
            # Health probe: confirm the key actually works before committing.
            emb.embed_query("ping")
            logger.info("Embeddings: using OpenAI '%s'.", settings.csai_embedding_model)
            return emb
        except Exception as exc:
            logger.warning(
                "OpenAI embeddings unusable (%s); falling back to hashing.", exc
            )
    logger.info("Embeddings: using deterministic hashing fallback.")
    return HashingEmbeddings()


def cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
    """Plain cosine similarity used by the numpy vector-store fallback."""
    va, vb = np.asarray(a, dtype=np.float32), np.asarray(b, dtype=np.float32)
    na, nb = float(np.linalg.norm(va)), float(np.linalg.norm(vb))
    if na == 0 or nb == 0:
        return 0.0
    return float(np.dot(va, vb) / (na * nb))
