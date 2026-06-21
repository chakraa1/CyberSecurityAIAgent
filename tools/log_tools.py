"""Log parsing + anomaly detection used by the Log Monitor agent.

These are deterministic detectors (rules + simple thresholds). They give the
agent reliable, explainable signals that the LLM layer then narrates. Keeping
detection deterministic also makes the eval suite stable.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from typing import Dict, List

from config import get_logger, get_settings

logger = get_logger(__name__)

_IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
_FAILED_AUTH_RE = re.compile(r"Failed password", re.IGNORECASE)

# Tunable detection threshold. Exposed via get/set so the loop-engineering
# module can sweep it and measure detection quality (see evals/loop.py).
_BRUTE_THRESHOLD = 5


def get_brute_force_threshold() -> int:
    return _BRUTE_THRESHOLD


def set_brute_force_threshold(value: int) -> None:
    """Set the failed-auth count that triggers a brute-force finding."""
    global _BRUTE_THRESHOLD
    _BRUTE_THRESHOLD = int(value)

# Web-attack signatures: name -> regex
_WEB_SIGNATURES = {
    "sql_injection": re.compile(r"('|%27)\s*or\s*'?1'?\s*=\s*'?1|union\s+select", re.I),
    "xss": re.compile(r"<script>|%3Cscript%3E", re.I),
    "path_traversal": re.compile(r"\.\./|%2e%2e", re.I),
    "secret_exposure": re.compile(r"/\.env|/\.git/|/admin/\.env", re.I),
    "scanner_tooling": re.compile(r"sqlmap|nikto|nmap|masscan", re.I),
}


@dataclass
class LogFinding:
    detector: str
    severity: str
    title: str
    description: str
    evidence: List[str] = field(default_factory=list)
    source_ip: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


def detect_brute_force(lines: List[str]) -> List[LogFinding]:
    """Detect SSH brute-force by counting failed auth per source IP."""
    by_ip: Dict[str, List[str]] = defaultdict(list)
    for line in lines:
        if _FAILED_AUTH_RE.search(line):
            m = _IP_RE.search(line)
            if m:
                by_ip[m.group(1)].append(line.strip())
    findings: List[LogFinding] = []
    for ip, evidence in by_ip.items():
        if len(evidence) >= _BRUTE_THRESHOLD:
            findings.append(
                LogFinding(
                    detector="brute_force",
                    severity="high",
                    title=f"SSH brute-force from {ip}",
                    description=(
                        f"{len(evidence)} failed authentication attempts from {ip} "
                        f"exceed the threshold of {_BRUTE_THRESHOLD}."
                    ),
                    evidence=evidence[:5],
                    source_ip=ip,
                )
            )
    return findings


def detect_web_attacks(lines: List[str]) -> List[LogFinding]:
    """Detect common web-layer attack signatures in access logs."""
    findings: List[LogFinding] = []
    for name, pattern in _WEB_SIGNATURES.items():
        matches = [ln.strip() for ln in lines if pattern.search(ln)]
        if matches:
            ip = ""
            m = _IP_RE.search(matches[0])
            if m:
                ip = m.group(1)
            severity = "critical" if name in {"sql_injection", "secret_exposure"} else "high"
            findings.append(
                LogFinding(
                    detector=name,
                    severity=severity,
                    title=f"{name.replace('_', ' ').title()} attempt detected",
                    description=f"{len(matches)} request(s) matched the {name} signature.",
                    evidence=matches[:5],
                    source_ip=ip,
                )
            )
    return findings


def detect_privilege_anomalies(lines: List[str]) -> List[LogFinding]:
    """Detect privilege-escalation anomalies (e.g. NOT in sudoers)."""
    findings: List[LogFinding] = []
    matches = [ln.strip() for ln in lines if "NOT in sudoers" in ln]
    if matches:
        findings.append(
            LogFinding(
                detector="privilege_escalation",
                severity="medium",
                title="Unauthorized sudo attempt",
                description="A user not present in sudoers attempted privileged commands.",
                evidence=matches[:5],
            )
        )
    return findings


def analyze_log_text(text: str) -> List[LogFinding]:
    """Run all detectors over raw log text."""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    findings: List[LogFinding] = []
    findings += detect_brute_force(lines)
    findings += detect_web_attacks(lines)
    findings += detect_privilege_anomalies(lines)
    logger.info("Log analysis produced %d finding(s) over %d lines.",
                len(findings), len(lines))
    return findings


def load_sample_logs() -> Dict[str, str]:
    """Return the bundled sample logs as {name: text}."""
    log_dir = get_settings().data_dir / "sample_logs"
    out: Dict[str, str] = {}
    if log_dir.exists():
        for path in sorted(log_dir.glob("*.log")):
            out[path.name] = path.read_text(encoding="utf-8")
    return out
