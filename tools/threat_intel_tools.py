"""Threat-intelligence tools: CVE lookup + RAG-grounded enrichment.

Uses authorized sources only:
* a bundled, offline snapshot of NVD-style CVE records (``data/cve``),
* the RAG knowledge base, and
* optional live web search (Tavily) for fresh intelligence.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

from config import get_logger
from tools.knowledge import load_cve_corpus
from tools.vectorstore import KnowledgeBase
from tools.websearch import SearchResult, web_search

logger = get_logger(__name__)


@dataclass
class CVEMatch:
    id: str
    alias: str
    product: str
    severity: str
    cvss: float
    summary: str
    remediation: str
    matched_on: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)


def lookup_cves_for_component(component: str, version: Optional[str] = None) -> List[CVEMatch]:
    """Match a software component (and optional version string) against the CVE corpus."""
    component_l = (component or "").lower()
    matches: List[CVEMatch] = []
    for cve in load_cve_corpus():
        haystack = " ".join(
            [
                cve.get("product", ""),
                cve.get("alias", ""),
                " ".join(cve.get("keywords", [])),
            ]
        ).lower()
        matched_on = [kw for kw in cve.get("keywords", []) if kw in component_l] or (
            [component_l] if component_l and component_l in haystack else []
        )
        if matched_on:
            matches.append(
                CVEMatch(
                    id=cve["id"],
                    alias=cve.get("alias", ""),
                    product=cve.get("product", ""),
                    severity=cve.get("severity", "unknown"),
                    cvss=float(cve.get("cvss", 0.0)),
                    summary=cve.get("summary", ""),
                    remediation=cve.get("remediation", ""),
                    matched_on=matched_on,
                )
            )
    matches.sort(key=lambda m: m.cvss, reverse=True)
    logger.info("CVE lookup for %r matched %d record(s).", component, len(matches))
    return matches


def search_cve_by_keyword(keyword: str) -> List[CVEMatch]:
    """Free-text keyword search across the CVE corpus."""
    kw = (keyword or "").lower()
    out: List[CVEMatch] = []
    for cve in load_cve_corpus():
        text = " ".join(
            [
                cve.get("id", ""),
                cve.get("alias", ""),
                cve.get("product", ""),
                cve.get("summary", ""),
                " ".join(cve.get("keywords", [])),
            ]
        ).lower()
        if kw and kw in text:
            out.append(
                CVEMatch(
                    id=cve["id"],
                    alias=cve.get("alias", ""),
                    product=cve.get("product", ""),
                    severity=cve.get("severity", "unknown"),
                    cvss=float(cve.get("cvss", 0.0)),
                    summary=cve.get("summary", ""),
                    remediation=cve.get("remediation", ""),
                    matched_on=[kw],
                )
            )
    out.sort(key=lambda m: m.cvss, reverse=True)
    return out


def enrich_with_web(query: str, max_results: int = 3) -> List[SearchResult]:
    """Fetch additional context from Tavily (or offline corpus)."""
    return web_search(query, max_results=max_results)
