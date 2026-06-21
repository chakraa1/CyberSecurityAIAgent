"""Vulnerability scanning tools.

Static, deterministic checks for:
* source code (hardcoded secrets, dangerous calls, weak crypto),
* database configuration (MSSQL/MySQL/Oracle/PostgreSQL) exposure & weak auth,
* Docker image / Dockerfile misconfigurations.

These are intentionally lightweight, explainable heuristics — not a replacement
for a full SAST/DAST suite — so they run anywhere and feed the agents reliable
signals.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Dict, List

from config import get_logger

logger = get_logger(__name__)


@dataclass
class VulnFinding:
    scanner: str
    severity: str
    title: str
    description: str
    recommendation: str
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)


# ---- Source code scanning -----------------------------------------------
_CODE_RULES = [
    ("hardcoded_secret", "critical",
     re.compile(r"(?i)(api[_-]?key|secret|password|passwd|token)\s*[:=]\s*['\"][^'\"]{6,}['\"]"),
     "Hardcoded secret/credential found in source.",
     "Move secrets to environment variables or a secrets manager; rotate the exposed value."),
    ("sql_injection", "high",
     re.compile(r"(?i)(execute|cursor\.execute|query)\s*\(\s*[\"'].*%s?.*\+|f[\"'].*select.*\{"),
     "Potential SQL injection via string-built query.",
     "Use parameterised queries / prepared statements."),
    ("command_injection", "high",
     re.compile(r"(?i)(os\.system|subprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True)"),
     "Possible OS command injection.",
     "Avoid shell=True; pass argument lists and validate input."),
    ("dangerous_eval", "high",
     re.compile(r"(?<![\w.])(eval|exec)\s*\("),
     "Use of eval/exec on potentially untrusted input.",
     "Remove eval/exec or strictly validate/whitelist input."),
    ("weak_crypto", "medium",
     re.compile(r"(?i)\b(md5|sha1)\b|DES\("),
     "Weak cryptographic primitive in use.",
     "Use SHA-256+ for hashing and AES-GCM for encryption."),
    ("insecure_deserialization", "high",
     re.compile(r"(?i)(pickle\.loads|yaml\.load\s*\((?!.*Loader))"),
     "Insecure deserialization.",
     "Use safe loaders (yaml.safe_load) and avoid pickle on untrusted data."),
]


def scan_code(source: str, filename: str = "snippet") -> List[VulnFinding]:
    findings: List[VulnFinding] = []
    lines = source.splitlines()
    for name, severity, pattern, title, rec in _CODE_RULES:
        evidence = [
            f"{filename}:{i+1}: {ln.strip()}"
            for i, ln in enumerate(lines)
            if pattern.search(ln)
        ]
        if evidence:
            findings.append(
                VulnFinding(
                    scanner="code",
                    severity=severity,
                    title=title,
                    description=f"{len(evidence)} occurrence(s) matched rule '{name}'.",
                    recommendation=rec,
                    evidence=evidence[:5],
                )
            )
    logger.info("Code scan of %s produced %d finding(s).", filename, len(findings))
    return findings


# ---- Database configuration scanning ------------------------------------
_DB_DEFAULT_PORTS = {
    "mssql": 1433, "mysql": 3306, "oracle": 1521, "postgres": 5432,
}


def scan_database_config(config: Dict) -> List[VulnFinding]:
    """Evaluate a DB config dict for common exposure / weak-auth issues.

    Expected keys (all optional): engine, host, port, ssl, username, password,
    public_access, default_account.
    """
    findings: List[VulnFinding] = []
    engine = str(config.get("engine", "")).lower()

    host = str(config.get("host", ""))
    public = bool(config.get("public_access")) or host in {"0.0.0.0", "*"}
    if public:
        findings.append(VulnFinding(
            scanner="database", severity="critical",
            title=f"{engine or 'Database'} reachable from public network",
            description=f"Host '{host}' exposes the database publicly.",
            recommendation="Bind to private interfaces and restrict via firewall/security groups.",
            evidence=[f"host={host}"],
        ))

    if config.get("ssl") is False:
        findings.append(VulnFinding(
            scanner="database", severity="high",
            title="Database connection not using TLS",
            description="Traffic to the database is unencrypted.",
            recommendation="Enforce TLS/SSL for all database connections.",
            evidence=["ssl=false"],
        ))

    pwd = str(config.get("password", ""))
    weak = {"", "password", "admin", "root", "123456", "changeme", "sa"}
    if pwd.lower() in weak:
        findings.append(VulnFinding(
            scanner="database", severity="critical",
            title="Weak or default database password",
            description="The database account uses a weak/default password.",
            recommendation="Set a strong, rotated password and use a secrets manager.",
            evidence=[f"username={config.get('username', '?')}"],
        ))

    if config.get("default_account"):
        findings.append(VulnFinding(
            scanner="database", severity="medium",
            title="Default/sample account enabled",
            description="A default or sample account is enabled.",
            recommendation="Disable or remove default accounts (e.g. sa, scott/tiger).",
            evidence=[f"engine={engine}"],
        ))
    logger.info("DB config scan produced %d finding(s).", len(findings))
    return findings


# ---- Docker scanning -----------------------------------------------------
def scan_dockerfile(dockerfile: str) -> List[VulnFinding]:
    findings: List[VulnFinding] = []
    lines = [ln.strip() for ln in dockerfile.splitlines() if ln.strip()]
    text_l = dockerfile.lower()

    if not re.search(r"(?im)^\s*user\s+\w+", dockerfile) or re.search(r"(?im)^\s*user\s+root", dockerfile):
        findings.append(VulnFinding(
            scanner="docker", severity="high",
            title="Container runs as root",
            description="No non-root USER directive (or USER root) was found.",
            recommendation="Add a non-root USER and drop unnecessary capabilities.",
            evidence=["no non-root USER directive"],
        ))

    if re.search(r"(?im)^\s*from\s+\S+:latest", dockerfile) or re.search(r"(?im)^\s*from\s+[^:\s]+\s*$", dockerfile):
        findings.append(VulnFinding(
            scanner="docker", severity="medium",
            title="Unpinned base image",
            description="Base image uses ':latest' or no tag/digest.",
            recommendation="Pin base images by digest (FROM image@sha256:...).",
            evidence=[ln for ln in lines if ln.lower().startswith("from")][:3],
        ))

    if any(k in text_l for k in ("api_key", "secret", "password")) and "env" in text_l:
        findings.append(VulnFinding(
            scanner="docker", severity="critical",
            title="Secret baked into image",
            description="Secrets appear to be set via ENV/ARG in the Dockerfile.",
            recommendation="Use build secrets / runtime env injection; never bake secrets into layers.",
            evidence=[ln for ln in lines if any(k in ln.lower() for k in ("secret", "password", "api_key"))][:3],
        ))

    if "--privileged" in text_l or "cap_add: all" in text_l:
        findings.append(VulnFinding(
            scanner="docker", severity="high",
            title="Excessive container privileges",
            description="Privileged mode or broad capabilities requested.",
            recommendation="Run unprivileged and add only required capabilities.",
            evidence=["privileged/cap_add detected"],
        ))
    logger.info("Dockerfile scan produced %d finding(s).", len(findings))
    return findings
