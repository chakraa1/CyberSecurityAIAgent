"""Unit tests for the deterministic tool layer."""

from tools.log_tools import analyze_log_text, set_brute_force_threshold
from tools.policy_tools import check_compliance, compliance_score
from tools.threat_intel_tools import lookup_cves_for_component, search_cve_by_keyword
from tools.vectorstore import Document, KnowledgeBase
from tools.vuln_scanner_tools import (
    scan_code,
    scan_database_config,
    scan_dockerfile,
)


def test_detect_brute_force():
    set_brute_force_threshold(5)
    log = "\n".join(
        f"sshd[1]: Failed password for root from 203.0.113.9 port {i} ssh2"
        for i in range(6)
    )
    findings = analyze_log_text(log)
    assert any(f.detector == "brute_force" for f in findings)
    assert findings[0].source_ip == "203.0.113.9"


def test_detect_sql_injection():
    log = "1.2.3.4 - - \"GET /x?id=1' OR '1'='1 HTTP/1.1\" 200 1 \"-\" \"sqlmap\""
    findings = analyze_log_text(log)
    detectors = {f.detector for f in findings}
    assert "sql_injection" in detectors


def test_clean_logs_no_findings():
    log = "1.2.3.4 - - \"GET /health HTTP/1.1\" 200 12 \"-\" \"kube-probe\""
    assert analyze_log_text(log) == []


def test_cve_lookup_log4j():
    matches = lookup_cves_for_component("apache log4j", "2.14.1")
    assert any(m.id == "CVE-2021-44228" for m in matches)


def test_cve_keyword_search():
    assert len(search_cve_by_keyword("openssl")) >= 1


def test_scan_code_secret_and_crypto():
    code = "API_KEY = 'sk-supersecret123'\nimport hashlib\nh=hashlib.md5(x).hexdigest()\n"
    findings = scan_code(code, "app.py")
    titles = " ".join(f.title.lower() for f in findings)
    assert "secret" in titles
    assert any(f.severity == "critical" for f in findings)


def test_scan_database_config():
    findings = scan_database_config(
        {"engine": "mysql", "host": "0.0.0.0", "ssl": False, "password": "root"}
    )
    assert len(findings) >= 2
    assert any(f.severity == "critical" for f in findings)


def test_scan_dockerfile():
    findings = scan_dockerfile("FROM python:latest\nCOPY . /app\n")
    assert len(findings) >= 2


def test_policy_compliance_score():
    setup = {
        "mfa_enabled": True, "encryption_at_rest": True, "tls_enabled": True,
        "logging_enabled": True, "incident_response_plan": True,
        "vulnerability_management": True, "audit_logging": True,
        "least_privilege": True, "access_control": True,
        "change_management": True, "backups_tested": True,
    }
    results = check_compliance(setup)
    assert compliance_score(results) == 100.0


def test_vectorstore_search():
    kb = KnowledgeBase()
    kb.add_documents([
        Document("SSH brute force is many failed logins", {"id": "a"}),
        Document("SQL injection uses OR 1=1 in queries", {"id": "b"}),
    ])
    hits = kb.search("failed ssh login attempts", k=1)
    assert hits and hits[0][0].metadata["id"] == "a"
