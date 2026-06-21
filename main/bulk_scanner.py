"""Bulk scanner: resolve many targets and scan all mapped database servers.

Accepts heterogeneous inputs (hostnames, database-server names, or ServiceNow
Application Instances), resolves them to concrete database servers via the
:class:`~tools.asset_inventory.AssetInventory`, and scans each server with the
Vulnerability Scanner + Threat Intelligence agents, then produces per-server
incident-response plans. Results are aggregated into a single report suitable
for a fleet-wide view.

This is intentionally built on the same agents used elsewhere so behaviour stays
consistent between single and bulk scans.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from config import get_logger
from main.agents import (
    IncidentResponseAgent,
    ThreatIntelligenceAgent,
    VulnerabilityScannerAgent,
)
from tools.asset_inventory import AssetInventory, DatabaseServer, get_inventory

logger = get_logger(__name__)

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class TargetScanResult:
    name: str
    engine: str
    hostname: str
    app_instance: str
    source: str
    severity: str = "info"
    finding_count: int = 0
    results: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "engine": self.engine,
            "hostname": self.hostname,
            "app_instance": self.app_instance,
            "source": self.source,
            "severity": self.severity,
            "finding_count": self.finding_count,
            "results": self.results,
        }


class BulkScanner:
    """Resolves and scans many database servers in bulk."""

    def __init__(self, inventory: Optional[AssetInventory] = None) -> None:
        self._inventory = inventory or get_inventory()
        self._vuln_agent = VulnerabilityScannerAgent()
        self._threat_agent = ThreatIntelligenceAgent()
        self._incident_agent = IncidentResponseAgent()

    # ---- resolution ------------------------------------------------------
    def resolve(
        self,
        hostnames: Optional[List[str]] = None,
        db_servers: Optional[List[str]] = None,
        app_instances: Optional[List[str]] = None,
    ) -> List[DatabaseServer]:
        return self._inventory.resolve(
            hostnames=hostnames, db_servers=db_servers, app_instances=app_instances
        )

    # ---- per-target scan -------------------------------------------------
    def scan_target(self, server: DatabaseServer) -> TargetScanResult:
        vuln = self._vuln_agent.run({"database_config": server.to_scan_config()})
        threat = self._threat_agent.run({"components": [{"name": server.engine}]})

        combined_findings = list(vuln.findings) + list(threat.findings)
        incident = self._incident_agent.run({"findings": combined_findings})

        severity = _worst([vuln.severity, threat.severity])
        result = TargetScanResult(
            name=server.name,
            engine=server.engine,
            hostname=server.hostname or server.host,
            app_instance=server.app_instance,
            source=server.source,
            severity=severity,
            finding_count=len(combined_findings),
            results={
                "Vulnerability Scanner Agent": vuln.to_dict(),
                "Threat Intelligence Agent": threat.to_dict(),
                "Incident Response Agent": incident.to_dict(),
            },
        )
        return result

    # ---- public API ------------------------------------------------------
    def run(
        self,
        hostnames: Optional[List[str]] = None,
        db_servers: Optional[List[str]] = None,
        app_instances: Optional[List[str]] = None,
        max_workers: int = 8,
    ) -> Dict[str, Any]:
        servers = self.resolve(
            hostnames=hostnames, db_servers=db_servers, app_instances=app_instances
        )
        if not servers:
            return {
                "source": self._inventory.source,
                "resolved": 0,
                "targets": [],
                "summary": {
                    "total_targets": 0, "total_findings": 0,
                    "worst_severity": "info", "severity_counts": {},
                },
            }

        workers = max(1, min(max_workers, len(servers)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            target_results = list(pool.map(self.scan_target, servers))

        target_results.sort(key=lambda t: _SEV_RANK.get(t.severity, 0), reverse=True)

        severity_counts: Dict[str, int] = {}
        total_findings = 0
        worst = "info"
        for t in target_results:
            severity_counts[t.severity] = severity_counts.get(t.severity, 0) + 1
            total_findings += t.finding_count
            worst = _worst([worst, t.severity])

        logger.info("Bulk scan complete: %d target(s), %d finding(s), worst=%s.",
                    len(target_results), total_findings, worst)
        return {
            "source": self._inventory.source,
            "resolved": len(servers),
            "targets": [t.to_dict() for t in target_results],
            "summary": {
                "total_targets": len(target_results),
                "total_findings": total_findings,
                "worst_severity": worst,
                "severity_counts": severity_counts,
            },
        }


def _worst(severities: List[str]) -> str:
    worst = "info"
    for s in severities:
        if _SEV_RANK.get(str(s).lower(), 0) > _SEV_RANK.get(worst, 0):
            worst = str(s).lower()
    return worst


_BULK: Optional[BulkScanner] = None


def get_bulk_scanner() -> BulkScanner:
    global _BULK
    if _BULK is None:
        _BULK = BulkScanner()
    return _BULK
