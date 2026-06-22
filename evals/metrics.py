"""Assertion checks and report data structures for the eval harness."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class CaseResult:
    case_id: str
    agent: str
    passed: bool
    checks: List[Dict[str, Any]] = field(default_factory=list)
    finding_count: int = 0
    severity: str = "info"
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvalReport:
    total: int = 0
    passed: int = 0
    cases: List[CaseResult] = field(default_factory=list)

    @property
    def pass_rate(self) -> float:
        return round(100.0 * self.passed / self.total, 1) if self.total else 0.0

    def add(self, case: CaseResult) -> None:
        self.cases.append(case)
        self.total += 1
        if case.passed:
            self.passed += 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total": self.total,
            "passed": self.passed,
            "failed": self.total - self.passed,
            "pass_rate": self.pass_rate,
            "cases": [c.to_dict() for c in self.cases],
        }


def assertion_checks(expect: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluate the ``expect`` block against an agent ``result`` dict.

    Returns a list of {name, passed, detail} check records.
    """
    findings: List[Dict[str, Any]] = result.get("findings", [])
    severity = str(result.get("severity", "info")).lower()
    checks: List[Dict[str, Any]] = []

    def add(name: str, passed: bool, detail: str = "") -> None:
        checks.append({"name": name, "passed": bool(passed), "detail": detail})

    if "min_findings" in expect:
        add("min_findings", len(findings) >= expect["min_findings"],
            f"{len(findings)} >= {expect['min_findings']}")
    if "max_findings" in expect:
        add("max_findings", len(findings) <= expect["max_findings"],
            f"{len(findings)} <= {expect['max_findings']}")
    if "severity_at_least" in expect:
        want = str(expect["severity_at_least"]).lower()
        add("severity_at_least",
            _SEV_RANK.get(severity, 0) >= _SEV_RANK.get(want, 0),
            f"{severity} >= {want}")
    if "contains_detector" in expect:
        want = expect["contains_detector"]
        add("contains_detector",
            any(f.get("detector") == want for f in findings),
            f"detector '{want}'")
    if "contains_id" in expect:
        want = expect["contains_id"]
        add("contains_id",
            any(f.get("id") == want for f in findings),
            f"id '{want}'")
    if "contains_title_substr" in expect:
        want = str(expect["contains_title_substr"]).lower()
        add("contains_title_substr",
            any(want in str(f.get("title", "")).lower() for f in findings),
            f"title contains '{want}'")
    return checks
