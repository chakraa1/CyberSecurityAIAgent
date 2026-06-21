"""RAG vector store built on FAISS with a pure-numpy fallback.

The store ingests the bundled cybersecurity knowledge base (CVE notes, hardening
guides, policy controls) and exposes a simple ``search`` API used by the Threat
Intelligence and Policy agents to ground their answers (Retrieval-Augmented
Generation).

If ``faiss`` is importable we use it for fast similarity search; otherwise we
fall back to brute-force cosine similarity over numpy arrays, so RAG keeps
working in any environment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

from config import get_logger
from tools.embeddings import cosine_similarity, get_embeddings

logger = get_logger(__name__)

try:
    import faiss  # type: ignore

    _HAS_FAISS = True
except Exception:  # pragma: no cover
    _HAS_FAISS = False


@dataclass
class Document:
    text: str
    metadata: Dict = field(default_factory=dict)


class KnowledgeBase:
    """A small RAG index over :class:`Document` objects."""

    def __init__(self, embeddings=None) -> None:
        self._embeddings = embeddings or get_embeddings()
        self._docs: List[Document] = []
        self._matrix: Optional[np.ndarray] = None
        self._faiss_index = None

    # ---- ingestion -------------------------------------------------------
    def add_documents(self, docs: Sequence[Document]) -> None:
        if not docs:
            return
        self._docs.extend(docs)
        vectors = np.asarray(
            self._embeddings.embed_documents([d.text for d in docs]),
            dtype=np.float32,
        )
        self._matrix = (
            vectors if self._matrix is None else np.vstack([self._matrix, vectors])
        )
        self._rebuild_faiss()
        logger.info("KnowledgeBase: indexed %d documents (total %d).",
                    len(docs), len(self._docs))

    def _rebuild_faiss(self) -> None:
        if not _HAS_FAISS or self._matrix is None:
            return
        dim = self._matrix.shape[1]
        index = faiss.IndexFlatIP(dim)
        normed = _l2_normalize(self._matrix)
        index.add(normed)
        self._faiss_index = index

    # ---- query -----------------------------------------------------------
    def search(self, query: str, k: int = 3) -> List[Tuple[Document, float]]:
        if not self._docs or self._matrix is None:
            return []
        q = np.asarray(self._embeddings.embed_query(query), dtype=np.float32)
        k = min(k, len(self._docs))

        if _HAS_FAISS and self._faiss_index is not None:
            qn = _l2_normalize(q.reshape(1, -1))
            scores, idxs = self._faiss_index.search(qn, k)
            return [
                (self._docs[i], float(scores[0][rank]))
                for rank, i in enumerate(idxs[0])
                if i != -1
            ]

        scored = [
            (doc, cosine_similarity(q, self._matrix[i]))
            for i, doc in enumerate(self._docs)
        ]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:k]

    @property
    def size(self) -> int:
        return len(self._docs)

    @property
    def backend(self) -> str:
        return "faiss" if (_HAS_FAISS and self._faiss_index is not None) else "numpy"


def _l2_normalize(matrix: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return (matrix / norms).astype(np.float32)
