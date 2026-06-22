"""Vulnerability Scanner Agent — scans code, DB config and Docker images."""

from __future__ import annotations

from typing import Any, Dict, List

from main.agents.base import AgentResult, BaseAgent
from tools.vuln_scanner_tools import scan_code, scan_database_config, scan_dockerfile


class VulnerabilityScannerAgent(BaseAgent):
    name = "Vulnerability Scanner Agent"
    description = "Scans code, APIs, database configs and Docker images for weaknesses."

    def _run(self, payload: Dict[str, Any]) -> AgentResult:
        findings: List[Dict[str, Any]] = []

        code = payload.get("code")
        if code:
            findings += [f.to_dict() for f in scan_code(code, payload.get("filename", "snippet"))]

        db_config = payload.get("database_config")
        if db_config:
            findings += [f.to_dict() for f in scan_database_config(db_config)]

        dockerfile = payload.get("dockerfile")
        if dockerfile:
            findings += [f.to_dict() for f in scan_dockerfile(dockerfile)]

        summary = self.narrate(
            "Rank the discovered weaknesses by exploitability and business risk.",
            findings,
        )
        return AgentResult(
            agent=self.name,
            summary=summary,
            findings=findings,
            recommendations=sorted({f["recommendation"] for f in findings if f.get("recommendation")}),
            severity=self.rollup_severity(findings),
            metadata={
                "scanned": [
                    k for k in ("code", "database_config", "dockerfile") if payload.get(k)
                ]
            },
        )
