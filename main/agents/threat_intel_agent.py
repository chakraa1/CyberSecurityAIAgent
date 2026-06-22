"""Threat Intelligence Agent — looks up known threats (CVE) via RAG + web search."""

from __future__ import annotations

from typing import Any, Dict, List

from main.agents.base import AgentResult, BaseAgent
from tools.threat_intel_tools import (
    enrich_with_web,
    lookup_cves_for_component,
    search_cve_by_keyword,
)


class ThreatIntelligenceAgent(BaseAgent):
    name = "Threat Intelligence Agent"
    description = "Looks up known security threats (CVE) and checks if the system is affected."

    def _run(self, payload: Dict[str, Any]) -> AgentResult:
        components: List[Dict[str, str]] = payload.get("components", [])
        keyword = payload.get("keyword", "")

        findings: List[Dict[str, Any]] = []
        for comp in components:
            name = comp.get("name", "")
            version = comp.get("version")
            for match in lookup_cves_for_component(name, version):
                d = match.to_dict()
                d["component"] = name
                d["version"] = version
                d["title"] = f"{d['id']} affects {name}"
                findings.append(d)

        if keyword:
            for match in search_cve_by_keyword(keyword):
                d = match.to_dict()
                d["title"] = f"{d['id']} ({d['alias']})"
                findings.append(d)

        # De-duplicate by CVE id (keep highest cvss / first occurrence).
        seen = set()
        deduped = []
        for f in sorted(findings, key=lambda x: x.get("cvss", 0), reverse=True):
            if f["id"] in seen:
                continue
            seen.add(f["id"])
            deduped.append(f)
        findings = deduped

        # RAG / web enrichment for additional context.
        query = keyword or (components[0]["name"] if components else "latest critical CVE")
        web_hits = enrich_with_web(f"{query} vulnerability advisory remediation", max_results=3)
        web_context = [
            {"title": h.title, "url": h.url, "source": h.source} for h in web_hits
        ]

        summary = self.narrate(
            "State which CVEs likely affect the system and the priority order to patch.",
            findings,
        )
        return AgentResult(
            agent=self.name,
            summary=summary,
            findings=findings,
            recommendations=[f["remediation"] for f in findings if f.get("remediation")][:6],
            severity=self.rollup_severity(findings),
            metadata={"web_context": web_context, "web_source": web_hits[0].source if web_hits else "none"},
        )
