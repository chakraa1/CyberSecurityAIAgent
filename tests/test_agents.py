"""Tests for agents and the LangGraph orchestrator (offline mode)."""

from main.agents import (
    IncidentResponseAgent,
    LogMonitorAgent,
    PolicyCheckerAgent,
    ThreatIntelligenceAgent,
    VulnerabilityScannerAgent,
)
from main.orchestrator import get_orchestrator


def test_log_monitor_agent_on_samples():
    res = LogMonitorAgent().run({"use_sample_logs": True})
    assert res.finding_count >= 1
    assert res.severity in {"critical", "high", "medium"}
    assert res.summary


def test_threat_intel_agent():
    res = ThreatIntelligenceAgent().run({"components": [{"name": "log4j"}]})
    assert any(f.get("id") == "CVE-2021-44228" for f in res.findings)


def test_vuln_scanner_agent():
    res = VulnerabilityScannerAgent().run({
        "code": "password = 'admin'\n",
        "dockerfile": "FROM x:latest\n",
        "database_config": {"engine": "mysql", "host": "0.0.0.0", "password": "root"},
    })
    assert res.finding_count >= 3


def test_incident_response_agent():
    res = IncidentResponseAgent().run({
        "findings": [{"detector": "brute_force", "severity": "high", "title": "bf"}]
    })
    assert res.finding_count >= 1
    assert res.findings[0]["steps"]


def test_policy_checker_agent():
    res = PolicyCheckerAgent().run({"setup": {"mfa_enabled": False}})
    assert "compliance_score" in res.metadata


def test_orchestrator_full_pipeline():
    out = get_orchestrator().run({
        "use_sample_logs": True,
        "components": [{"name": "log4j"}],
        "code": "API_KEY='sk-secret123'\n",
        "database_config": {"engine": "mysql", "host": "0.0.0.0", "password": "root"},
        "dockerfile": "FROM python:latest\n",
        "setup": {"mfa_enabled": False, "tls_enabled": True},
    })
    assert out["total_findings"] >= 1
    assert len(out["agents_run"]) == 5
    assert out["engine"] in {"langgraph", "sequential"}
