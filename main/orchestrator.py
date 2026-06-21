"""LangGraph orchestrator coordinating the five cybersecurity agents.

Flow (a directed graph):

    log_monitor ─┐
    threat_intel ─┤
    vuln_scanner ─┼─▶ incident_response ─▶ policy_checker ─▶ END
                  │      (consumes all findings above)

The Incident Response agent consumes the aggregated findings from the detection
agents, then the Policy Checker evaluates the overall posture.

If ``langgraph`` is unavailable for any reason, the orchestrator transparently
falls back to an equivalent sequential pipeline, so the product always runs.
"""

from __future__ import annotations

from typing import Any, Dict, List, TypedDict

from config import get_logger
from main.agents import (
    IncidentResponseAgent,
    LogMonitorAgent,
    PolicyCheckerAgent,
    ThreatIntelligenceAgent,
    VulnerabilityScannerAgent,
)
from main.agents.base import AgentResult

logger = get_logger(__name__)


class PipelineState(TypedDict, total=False):
    payload: Dict[str, Any]
    results: Dict[str, Dict[str, Any]]
    all_findings: List[Dict[str, Any]]


class SecurityOrchestrator:
    """Builds and runs the multi-agent security pipeline."""

    def __init__(self) -> None:
        self.log_agent = LogMonitorAgent()
        self.threat_agent = ThreatIntelligenceAgent()
        self.vuln_agent = VulnerabilityScannerAgent()
        self.incident_agent = IncidentResponseAgent()
        self.policy_agent = PolicyCheckerAgent()
        self._graph = self._build_graph()

    # ---- graph construction ---------------------------------------------
    def _build_graph(self):
        try:
            from langgraph.graph import END, START, StateGraph
        except Exception as exc:  # pragma: no cover
            logger.warning("langgraph unavailable (%s); using sequential fallback.", exc)
            return None

        graph = StateGraph(PipelineState)
        graph.add_node("log_monitor", self._node_log)
        graph.add_node("threat_intel", self._node_threat)
        graph.add_node("vuln_scanner", self._node_vuln)
        graph.add_node("incident_response", self._node_incident)
        graph.add_node("policy_checker", self._node_policy)

        graph.add_edge(START, "log_monitor")
        graph.add_edge("log_monitor", "threat_intel")
        graph.add_edge("threat_intel", "vuln_scanner")
        graph.add_edge("vuln_scanner", "incident_response")
        graph.add_edge("incident_response", "policy_checker")
        graph.add_edge("policy_checker", END)
        return graph.compile()

    # ---- node implementations -------------------------------------------
    def _record(self, state: PipelineState, result: AgentResult) -> PipelineState:
        state.setdefault("results", {})
        state.setdefault("all_findings", [])
        state["results"][result.agent] = result.to_dict()
        state["all_findings"].extend(result.findings)
        return state

    def _node_log(self, state: PipelineState) -> PipelineState:
        return self._record(state, self.log_agent.run(state["payload"]))

    def _node_threat(self, state: PipelineState) -> PipelineState:
        return self._record(state, self.threat_agent.run(state["payload"]))

    def _node_vuln(self, state: PipelineState) -> PipelineState:
        return self._record(state, self.vuln_agent.run(state["payload"]))

    def _node_incident(self, state: PipelineState) -> PipelineState:
        payload = dict(state["payload"])
        payload["findings"] = list(state.get("all_findings", []))
        return self._record(state, self.incident_agent.run(payload))

    def _node_policy(self, state: PipelineState) -> PipelineState:
        return self._record(state, self.policy_agent.run(state["payload"]))

    # ---- public API ------------------------------------------------------
    def run(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Run the full pipeline and return aggregated results."""
        state: PipelineState = {"payload": payload or {}, "results": {}, "all_findings": []}

        if self._graph is not None:
            try:
                state = self._graph.invoke(state)
            except Exception as exc:  # pragma: no cover
                logger.warning("LangGraph run failed (%s); falling back.", exc)
                state = self._run_sequential(payload or {})
        else:
            state = self._run_sequential(payload or {})

        return self._summarise(state)

    def _run_sequential(self, payload: Dict[str, Any]) -> PipelineState:
        state: PipelineState = {"payload": payload, "results": {}, "all_findings": []}
        state = self._node_log(state)
        state = self._node_threat(state)
        state = self._node_vuln(state)
        state = self._node_incident(state)
        state = self._node_policy(state)
        return state

    def _summarise(self, state: PipelineState) -> Dict[str, Any]:
        results = state.get("results", {})
        all_findings = state.get("all_findings", [])
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        worst = "info"
        for f in all_findings:
            s = str(f.get("severity", "info")).lower()
            if sev_rank.get(s, 0) > sev_rank.get(worst, 0):
                worst = s
        return {
            "results": results,
            "total_findings": len(all_findings),
            "overall_severity": worst,
            "agents_run": list(results.keys()),
            "engine": "langgraph" if self._graph is not None else "sequential",
        }


_ORCHESTRATOR: SecurityOrchestrator | None = None


def get_orchestrator() -> SecurityOrchestrator:
    global _ORCHESTRATOR
    if _ORCHESTRATOR is None:
        _ORCHESTRATOR = SecurityOrchestrator()
    return _ORCHESTRATOR
