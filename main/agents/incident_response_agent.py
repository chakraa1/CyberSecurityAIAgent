"""Incident Response Agent — builds step-by-step action plans from findings."""

from __future__ import annotations

from typing import Any, Dict, List

from main.agents.base import AgentResult, BaseAgent

_PLAYBOOKS = {
    "brute_force": [
        "Contain: block the source IP(s) at the firewall / security group.",
        "Eradicate: disable affected accounts and rotate credentials.",
        "Harden: enforce key-based SSH auth and enable fail2ban.",
        "Monitor: add alerting on repeated failed logins (NIST AC-7).",
    ],
    "sql_injection": [
        "Contain: enable WAF blocking for injection signatures.",
        "Fix: replace string-built queries with parameterised statements.",
        "Verify: run a DAST scan against the affected endpoint.",
        "Audit: review DB logs for data exfiltration.",
    ],
    "secret_exposure": [
        "Contain: stop serving the exposed file immediately.",
        "Rotate: invalidate and re-issue all exposed secrets/keys.",
        "Audit: review access logs for who fetched the secret.",
        "Prevent: add deny rules for dotfiles and scan repos for secrets.",
    ],
    "critical_cve": [
        "Triage: confirm affected versions against the asset inventory.",
        "Patch: apply the vendor-recommended fixed version.",
        "Mitigate: apply documented workarounds until patched.",
        "Verify: re-scan to confirm remediation.",
    ],
}

_GENERIC_PLAN = [
    "Triage and confirm the finding against the affected asset.",
    "Contain the impact (isolate host, block source, disable account).",
    "Eradicate the root cause (patch, fix code, change config).",
    "Recover and validate normal operation.",
    "Document lessons learned and update detections.",
]


class IncidentResponseAgent(BaseAgent):
    name = "Incident Response Agent"
    description = "Creates step-by-step action plans when an issue is found."

    def _run(self, payload: Dict[str, Any]) -> AgentResult:
        # Accept findings from any upstream agent.
        upstream: List[Dict[str, Any]] = payload.get("findings", [])
        plans: List[Dict[str, Any]] = []
        for f in sorted(upstream, key=lambda x: _sev_rank(x.get("severity")), reverse=True)[:10]:
            key = self._playbook_key(f)
            steps = _PLAYBOOKS.get(key, _GENERIC_PLAN)
            plans.append(
                {
                    "title": f.get("title") or f.get("id") or "Security issue",
                    "severity": f.get("severity", "info"),
                    "playbook": key,
                    "steps": steps,
                }
            )

        if not plans:
            plans.append(
                {"title": "No active incidents", "severity": "info",
                 "playbook": "none",
                 "steps": ["Maintain monitoring and periodic scans."]}
            )

        summary = self.narrate(
            "Produce an incident-response action plan prioritised by severity.",
            plans,
        )
        return AgentResult(
            agent=self.name,
            summary=summary,
            findings=plans,
            recommendations=[f"{p['title']}: {p['steps'][0]}" for p in plans][:6],
            severity=self.rollup_severity(plans),
            metadata={"incidents": len(plans)},
        )

    @staticmethod
    def _playbook_key(finding: Dict[str, Any]) -> str:
        detector = str(finding.get("detector", "")).lower()
        if detector in _PLAYBOOKS:
            return detector
        if str(finding.get("id", "")).startswith("CVE") and _sev_rank(finding.get("severity")) >= 3:
            return "critical_cve"
        return "generic"


def _sev_rank(sev: Any) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
        str(sev).lower(), 0
    )
