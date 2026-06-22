"""Web search via Tavily with an offline fallback.

When ``TAVILY_API_KEY`` is configured, queries hit the Tavily API for live
threat intelligence. Otherwise we search the bundled CVE/knowledge corpus so
the Threat Intelligence agent still returns grounded, useful results offline.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from config import get_logger, get_settings

logger = get_logger(__name__)


@dataclass
class SearchResult:
    title: str
    url: str
    content: str
    source: str = "tavily"


def tavily_search(query: str, max_results: int = 5) -> List[SearchResult]:
    """Live Tavily search. Raises on failure so callers can fall back."""
    from tavily import TavilyClient

    client = TavilyClient(api_key=get_settings().tavily_api_key)
    resp = client.search(query=query, max_results=max_results)
    results = []
    for item in resp.get("results", []):
        results.append(
            SearchResult(
                title=item.get("title", ""),
                url=item.get("url", ""),
                content=item.get("content", ""),
                source="tavily",
            )
        )
    return results


def _offline_search(query: str, max_results: int) -> List[SearchResult]:
    """Search the local RAG knowledge base as a Tavily substitute."""
    from tools.knowledge import get_knowledge_base

    kb = get_knowledge_base()
    hits = kb.search(query, k=max_results)
    results: List[SearchResult] = []
    for doc, score in hits:
        meta = doc.metadata or {}
        ref = meta.get("id") or meta.get("title") or meta.get("source", "kb")
        results.append(
            SearchResult(
                title=f"{ref} (local, score={score:.2f})",
                url=f"local://{meta.get('source', 'kb')}/{ref}",
                content=doc.text,
                source="offline-kb",
            )
        )
    return results


def web_search(query: str, max_results: int = 5) -> List[SearchResult]:
    """Public entry point. Uses Tavily if available, else local corpus."""
    settings = get_settings()
    if settings.has_tavily:
        try:
            logger.info("Web search via Tavily: %r", query)
            return tavily_search(query, max_results=max_results)
        except Exception as exc:  # pragma: no cover - network/credential errors
            logger.warning("Tavily search failed (%s); using offline corpus.", exc)
    logger.info("Web search via offline corpus: %r", query)
    return _offline_search(query, max_results)
