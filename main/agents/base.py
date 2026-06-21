"""Base agent abstraction shared by all specialised agents.

Design goals:
* **Scalable**: each agent is stateless and side-effect free given its input,
  so they can run concurrently and be reused across requests (suitable for a
  financial-services workload).
* **Explainable**: agents return structured ``findings`` plus an LLM-narrated
  ``summary``. The structured part is deterministic; the narrative is the only
  LLM-dependent piece and degrades gracefully offline.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

from config import get_logger
from main.llm import complete

logger = get_logger(__name__)

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class AgentResult:
    agent: str
    summary: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    severity: str = "info"
    metadata: Dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def finding_count(self) -> int:
        return len(self.findings)


class BaseAgent:
    name: str = "base"
    description: str = "Base agent"

    def run(self, payload: Dict[str, Any]) -> AgentResult:
        start = time.perf_counter()
        try:
            result = self._run(payload or {})
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("Agent %s failed: %s", self.name, exc)
            result = AgentResult(
                agent=self.name,
                summary=f"Agent error: {exc}",
                severity="info",
                metadata={"error": str(exc)},
            )
        result.duration_ms = round((time.perf_counter() - start) * 1000, 2)
        logger.info("Agent %s finished: %d finding(s) in %.1f ms.",
                    self.name, result.finding_count, result.duration_ms)
        return result

    # Subclasses implement this.
    def _run(self, payload: Dict[str, Any]) -> AgentResult:  # pragma: no cover
        raise NotImplementedError

    # ---- helpers ---------------------------------------------------------
    @staticmethod
    def rollup_severity(findings: List[Dict[str, Any]]) -> str:
        worst = "info"
        for f in findings:
            sev = str(f.get("severity", "info")).lower()
            if _SEVERITY_ORDER.get(sev, 0) > _SEVERITY_ORDER.get(worst, 0):
                worst = sev
        return worst

    def narrate(self, instruction: str, findings: List[Dict[str, Any]]) -> str:
        """Produce a short narrative summary via the LLM (or fallback)."""
        import json

        prompt = (
            f"You are the {self.name} in a cybersecurity multi-agent system for a "
            f"financial-services platform. {instruction}\n"
            f"Findings (JSON): {json.dumps(findings, default=str)}\n"
            "Respond with a concise, actionable summary (max ~6 bullet points)."
        )
        return complete(prompt)
