"""Loads the bundled corpora and builds the RAG knowledge base."""

from __future__ import annotations

import json
from functools import lru_cache
from typing import List

from config import get_logger, get_settings
from tools.vectorstore import Document, KnowledgeBase

logger = get_logger(__name__)


def load_cve_corpus() -> List[dict]:
    """Load the local CVE corpus (authorized, offline snapshot of NVD data)."""
    path = get_settings().data_dir / "cve" / "cve_corpus.json"
    if not path.exists():
        logger.warning("CVE corpus missing at %s", path)
        return []
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _kb_markdown_sections() -> List[Document]:
    path = get_settings().data_dir / "knowledge_base" / "hardening_and_policies.md"
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    docs: List[Document] = []
    current_title = "intro"
    buffer: List[str] = []
    for line in text.splitlines():
        if line.startswith("## "):
            if buffer:
                docs.append(
                    Document(
                        text="\n".join(buffer).strip(),
                        metadata={"source": "knowledge_base", "title": current_title},
                    )
                )
            current_title = line[3:].strip()
            buffer = [line]
        else:
            buffer.append(line)
    if buffer:
        docs.append(
            Document(
                text="\n".join(buffer).strip(),
                metadata={"source": "knowledge_base", "title": current_title},
            )
        )
    return docs


def _cve_documents() -> List[Document]:
    docs: List[Document] = []
    for cve in load_cve_corpus():
        text = (
            f"{cve['id']} ({cve.get('alias', '')}) affecting {cve.get('product', '')} "
            f"{cve.get('affected_versions', '')}. Severity {cve.get('severity')} "
            f"CVSS {cve.get('cvss')}. {cve.get('summary', '')} "
            f"Remediation: {cve.get('remediation', '')} "
            f"Keywords: {', '.join(cve.get('keywords', []))}."
        )
        docs.append(Document(text=text, metadata={"source": "cve", "id": cve["id"]}))
    return docs


@lru_cache(maxsize=1)
def get_knowledge_base() -> KnowledgeBase:
    """Build (and cache) the RAG index from CVE + hardening corpora."""
    kb = KnowledgeBase()
    docs = _cve_documents() + _kb_markdown_sections()
    kb.add_documents(docs)
    logger.info("Knowledge base ready: %d docs (backend=%s).", kb.size, kb.backend)
    return kb
