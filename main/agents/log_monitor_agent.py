"""Log Monitor Agent — detects unusual activity / attacks in logs."""

from __future__ import annotations

from typing import Any, Dict

from main.agents.base import AgentResult, BaseAgent
from tools.log_tools import analyze_log_text, load_sample_logs


class LogMonitorAgent(BaseAgent):
    name = "Log Monitor Agent"
    description = "Reads system and network logs to detect unusual activity or attacks."

    def _run(self, payload: Dict[str, Any]) -> AgentResult:
        log_text = payload.get("log_text", "")
        if not log_text and payload.get("use_sample_logs", True):
            log_text = "\n".join(load_sample_logs().values())

        findings = [f.to_dict() for f in analyze_log_text(log_text)]
        recommendations = sorted(
            {self._recommend(f["detector"]) for f in findings}
        )
        summary = self.narrate(
            "Summarise the most urgent log anomalies and what they imply.",
            findings,
        )
        return AgentResult(
            agent=self.name,
            summary=summary,
            findings=findings,
            recommendations=recommendations,
            severity=self.rollup_severity(findings),
            metadata={"lines_analyzed": len(log_text.splitlines())},
        )

    @staticmethod
    def _recommend(detector: str) -> str:
        return {
            "brute_force": "Block offending IPs, enable fail2ban, disable SSH password auth.",
            "sql_injection": "Use parameterised queries and deploy a WAF.",
            "xss": "Apply output encoding and a strict Content-Security-Policy.",
            "path_traversal": "Canonicalise paths and deny traversal sequences.",
            "secret_exposure": "Stop serving dotfiles; rotate any exposed secrets.",
            "scanner_tooling": "Rate-limit and block known scanner user-agents.",
            "privilege_escalation": "Review sudoers and alert on unauthorized sudo.",
        }.get(detector, "Investigate and remediate the detected anomaly.")
