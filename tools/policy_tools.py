"""Policy / compliance checks against ISO 27001, NIST CSF and SOC 2.

Given a description of the current setup (a dict of booleans/values), each
framework's controls are evaluated and a pass/fail with remediation guidance is
returned. This powers the Policy Checker agent.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Callable, Dict, List

from config import get_logger

logger = get_logger(__name__)


@dataclass
class PolicyResult:
    framework: str
    control: str
    title: str
    status: str  # "pass" | "fail" | "unknown"
    severity: str
    recommendation: str

    def to_dict(self) -> Dict:
        return asdict(self)


# A control maps to: (framework, control_id, title, predicate, severity, remediation)
def _ctl(framework, control, title, key, severity, remediation):
    def check(setup: Dict) -> PolicyResult:
        val = setup.get(key)
        if val is None:
            status = "unknown"
        else:
            status = "pass" if bool(val) else "fail"
        return PolicyResult(
            framework=framework,
            control=control,
            title=title,
            status=status,
            severity=severity if status != "pass" else "info",
            recommendation="" if status == "pass" else remediation,
        )

    return check


_CONTROLS: List[Callable[[Dict], PolicyResult]] = [
    _ctl("NIST CSF", "PR.AC-1", "Identities & credentials managed (MFA)",
         "mfa_enabled", "high", "Enforce MFA for all privileged and remote access."),
    _ctl("NIST CSF", "PR.DS-1", "Data-at-rest is protected (encryption)",
         "encryption_at_rest", "high", "Enable encryption at rest for all data stores."),
    _ctl("NIST CSF", "PR.DS-2", "Data-in-transit is protected (TLS)",
         "tls_enabled", "high", "Enforce TLS for all service-to-service and client traffic."),
    _ctl("NIST CSF", "DE.CM-1", "Networks/systems monitored for anomalies",
         "logging_enabled", "medium", "Enable centralised logging and continuous monitoring."),
    _ctl("NIST CSF", "RS.RP-1", "Incident response plan exists & executed",
         "incident_response_plan", "medium", "Document and rehearse an incident response plan."),
    _ctl("ISO 27001", "A.8.8", "Technical vulnerability management",
         "vulnerability_management", "high", "Run regular vulnerability scans and patch on SLA."),
    _ctl("ISO 27001", "A.8.15", "Logging of activities",
         "audit_logging", "medium", "Maintain immutable audit logs of security events."),
    _ctl("ISO 27001", "A.5.15", "Access control policy enforced",
         "least_privilege", "high", "Apply least-privilege and review access regularly."),
    _ctl("SOC 2", "CC6.1", "Logical access controls restrict access",
         "access_control", "high", "Implement role-based access control and reviews."),
    _ctl("SOC 2", "CC7.2", "System monitored for security events",
         "logging_enabled", "medium", "Configure alerting on anomalous security events."),
    _ctl("SOC 2", "CC8.1", "Change management process",
         "change_management", "medium", "Adopt reviewed, auditable change management."),
    _ctl("SOC 2", "CC9.1", "Backups and recovery tested",
         "backups_tested", "medium", "Test backups and document RTO/RPO regularly."),
]


def check_compliance(setup: Dict, frameworks: List[str] | None = None) -> List[PolicyResult]:
    """Evaluate the setup against the requested frameworks (all by default)."""
    results = [ctl(setup) for ctl in _CONTROLS]
    if frameworks:
        wanted = {f.lower() for f in frameworks}
        results = [r for r in results if r.framework.lower() in wanted]
    fails = sum(1 for r in results if r.status == "fail")
    logger.info("Compliance check: %d control(s), %d failing.", len(results), fails)
    return results


def compliance_score(results: List[PolicyResult]) -> float:
    """Return a 0-100 compliance score based on passing controls."""
    scored = [r for r in results if r.status in {"pass", "fail"}]
    if not scored:
        return 0.0
    passed = sum(1 for r in scored if r.status == "pass")
    return round(100.0 * passed / len(scored), 1)
