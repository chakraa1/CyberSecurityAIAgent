"""Runs the eval dataset against the agents and produces an :class:`EvalReport`."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from config import get_logger, get_settings
from evals.metrics import CaseResult, EvalReport, assertion_checks
from main.agents import (
    IncidentResponseAgent,
    LogMonitorAgent,
    PolicyCheckerAgent,
    ThreatIntelligenceAgent,
    VulnerabilityScannerAgent,
)

logger = get_logger(__name__)

_AGENT_REGISTRY = {
    "Log Monitor Agent": LogMonitorAgent,
    "Threat Intelligence Agent": ThreatIntelligenceAgent,
    "Vulnerability Scanner Agent": VulnerabilityScannerAgent,
    "Incident Response Agent": IncidentResponseAgent,
    "Policy Checker Agent": PolicyCheckerAgent,
}


def default_dataset_path() -> Path:
    return Path(__file__).resolve().parent / "datasets" / "security_cases.json"


def load_dataset(path: Optional[Path] = None) -> List[Dict[str, Any]]:
    path = path or default_dataset_path()
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


class Evaluator:
    """Executes cases and scores them with deterministic assertions."""

    def __init__(self) -> None:
        self._agents = {name: cls() for name, cls in _AGENT_REGISTRY.items()}

    def run_case(self, case: Dict[str, Any]) -> CaseResult:
        agent = self._agents.get(case["agent"])
        if agent is None:
            return CaseResult(case_id=case["id"], agent=case["agent"], passed=False,
                              checks=[{"name": "agent_exists", "passed": False,
                                       "detail": case["agent"]}])
        result = agent.run(case.get("payload", {})).to_dict()
        checks = assertion_checks(case.get("expect", {}), result)
        passed = all(c["passed"] for c in checks) if checks else True
        return CaseResult(
            case_id=case["id"],
            agent=case["agent"],
            passed=passed,
            checks=checks,
            finding_count=len(result.get("findings", [])),
            severity=result.get("severity", "info"),
            duration_ms=result.get("duration_ms", 0.0),
        )

    def run(self, dataset: Optional[List[Dict[str, Any]]] = None) -> EvalReport:
        dataset = dataset if dataset is not None else load_dataset()
        report = EvalReport()
        for case in dataset:
            cr = self.run_case(case)
            report.add(cr)
            logger.info("[eval] %s -> %s", cr.case_id, "PASS" if cr.passed else "FAIL")
        return report

    def run_and_save(self, out_dir: Optional[Path] = None) -> EvalReport:
        report = self.run()
        out_dir = out_dir or (get_settings().index_path.parent.parent / "eval_reports")
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "latest_report.json"
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(report.to_dict(), fh, indent=2)
        logger.info("Eval report saved to %s (pass rate %.1f%%).",
                    out_path, report.pass_rate)
        return report
