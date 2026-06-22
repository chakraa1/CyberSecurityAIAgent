"""Policy Checker Agent — checks setup against ISO 27001, NIST CSF, SOC 2."""

from __future__ import annotations

from typing import Any, Dict, List

from main.agents.base import AgentResult, BaseAgent
from tools.policy_tools import check_compliance, compliance_score


class PolicyCheckerAgent(BaseAgent):
    name = "Policy Checker Agent"
    description = "Checks the setup against ISO, NIST and SOC 2 and shows where fixes are needed."

    def _run(self, payload: Dict[str, Any]) -> AgentResult:
        setup: Dict[str, Any] = payload.get("setup", {})
        frameworks: List[str] = payload.get("frameworks") or []

        results = check_compliance(setup, frameworks or None)
        findings = [r.to_dict() for r in results if r.status != "pass"]
        score = compliance_score(results)

        summary = self.narrate(
            f"Overall compliance score is {score}%. Summarise the top gaps to fix first.",
            findings,
        )
        return AgentResult(
            agent=self.name,
            summary=summary,
            findings=findings,
            recommendations=[r["recommendation"] for r in findings if r.get("recommendation")][:6],
            severity=self.rollup_severity(findings),
            metadata={
                "compliance_score": score,
                "controls_evaluated": len(results),
                "controls_failing": len(findings),
            },
        )
