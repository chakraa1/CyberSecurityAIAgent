"""Streamlit UI for the CyberSecurityAIAgent multi-agent system.

Run with:
    streamlit run app/streamlit_app.py

The UI exposes each agent individually, an orchestrated full scan (LangGraph),
the evaluation suite and the loop-engineering demo. It runs offline by default
and upgrades automatically when OPENAI_API_KEY / TAVILY_API_KEY are set.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Ensure the project root is importable when launched via `streamlit run`.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st  # noqa: E402

from config import configure_logging, get_settings  # noqa: E402
from main.agents import (  # noqa: E402
    IncidentResponseAgent,
    LogMonitorAgent,
    PolicyCheckerAgent,
    ThreatIntelligenceAgent,
    VulnerabilityScannerAgent,
)
from main.bulk_scanner import get_bulk_scanner  # noqa: E402
from main.orchestrator import get_orchestrator  # noqa: E402
from tools.asset_inventory import get_inventory  # noqa: E402
from tools.log_tools import load_sample_logs  # noqa: E402

configure_logging()

SEVERITY_COLORS = {
    "critical": "#b00020",
    "high": "#e65100",
    "medium": "#f9a825",
    "low": "#2e7d32",
    "info": "#1565c0",
}


def severity_badge(sev: str) -> str:
    color = SEVERITY_COLORS.get(str(sev).lower(), "#555")
    return (
        f"<span style='background:{color};color:white;padding:2px 8px;"
        f"border-radius:8px;font-size:0.8em'>{str(sev).upper()}</span>"
    )


def render_result(result: dict) -> None:
    st.markdown(
        f"**{result['agent']}** &nbsp; {severity_badge(result.get('severity', 'info'))} "
        f"&nbsp; <span style='color:#888'>{result.get('finding_count', len(result.get('findings', [])))} "
        f"finding(s), {result.get('duration_ms', 0)} ms</span>",
        unsafe_allow_html=True,
    )
    st.markdown("**Summary**")
    st.text(result.get("summary", ""))

    findings = result.get("findings", [])
    if findings:
        with st.expander(f"Findings ({len(findings)})", expanded=True):
            for f in findings:
                title = f.get("title") or f.get("id") or f.get("control") or "finding"
                st.markdown(
                    f"{severity_badge(f.get('severity', 'info'))} **{title}**",
                    unsafe_allow_html=True,
                )
                detail = f.get("description") or f.get("summary") or ""
                if detail:
                    st.caption(detail)
                if f.get("steps"):
                    for i, step in enumerate(f["steps"], 1):
                        st.markdown(f"&nbsp;&nbsp;{i}. {step}")
                if f.get("evidence"):
                    st.code("\n".join(f["evidence"][:5]))
    if result.get("recommendations"):
        st.markdown("**Recommendations**")
        for rec in result["recommendations"]:
            st.markdown(f"- {rec}")


def sidebar() -> None:
    settings = get_settings()
    with st.sidebar:
        st.header("CyberSecurityAIAgent")
        st.caption("Multi-agent security analysis · LangGraph · FAISS · Streamlit")
        s = settings.summary()
        mode = "OFFLINE (deterministic)" if s["offline_mode"] else "LIVE LLM"
        st.markdown(f"**Mode:** {mode}")
        st.json(s)
        if s["offline_mode"]:
            st.info(
                "Running in offline mode. Set OPENAI_API_KEY (and optionally "
                "TAVILY_API_KEY) in a .env file to enable live LLM reasoning and "
                "web search."
            )


def tab_full_scan() -> None:
    st.subheader("Orchestrated full scan (LangGraph)")
    st.caption("Runs all five agents through the LangGraph pipeline.")

    col1, col2 = st.columns(2)
    with col1:
        component = st.text_input("Software component", "apache log4j")
        version = st.text_input("Version", "2.14.1")
    with col2:
        db_engine = st.selectbox("DB engine", ["mysql", "postgres", "mssql", "oracle"])
        db_public = st.checkbox("DB publicly accessible", value=True)

    code = st.text_area(
        "Code snippet to scan",
        "API_KEY = 'sk-supersecret123'\nimport hashlib\nh = hashlib.md5(x).hexdigest()\n",
        height=110,
    )
    dockerfile = st.text_area(
        "Dockerfile to scan", "FROM python:latest\nCOPY . /app\nCMD [\"python\",\"app.py\"]\n",
        height=90,
    )

    if st.button("Run full security scan", type="primary"):
        payload = {
            "use_sample_logs": True,
            "components": [{"name": component, "version": version}],
            "code": code,
            "filename": "app.py",
            "database_config": {
                "engine": db_engine, "host": "0.0.0.0" if db_public else "127.0.0.1",
                "ssl": False, "username": "root", "password": "root",
                "public_access": db_public,
            },
            "dockerfile": dockerfile,
            "setup": {
                "mfa_enabled": False, "encryption_at_rest": False, "tls_enabled": True,
                "logging_enabled": True, "incident_response_plan": False,
                "vulnerability_management": False, "audit_logging": True,
                "least_privilege": True, "access_control": True,
                "change_management": True, "backups_tested": False,
            },
        }
        with st.spinner("Running multi-agent pipeline..."):
            out = get_orchestrator().run(payload)
        st.success(
            f"Pipeline complete via **{out['engine']}** engine — "
            f"{out['total_findings']} total findings, "
            f"overall severity {out['overall_severity'].upper()}."
        )
        for agent_name, result in out["results"].items():
            st.divider()
            render_result(result)


def tab_log_monitor() -> None:
    st.subheader("Log Monitor Agent")
    samples = load_sample_logs()
    choice = st.selectbox("Sample log", ["(paste your own)"] + list(samples.keys()))
    default = samples.get(choice, "") if choice != "(paste your own)" else ""
    log_text = st.text_area("Log text", default or "\n".join(samples.values()), height=200)
    if st.button("Analyze logs", type="primary"):
        with st.spinner("Analyzing..."):
            res = LogMonitorAgent().run({"log_text": log_text, "use_sample_logs": False})
        render_result(res.to_dict())


def tab_threat_intel() -> None:
    st.subheader("Threat Intelligence Agent")
    name = st.text_input("Component name", "openssl")
    version = st.text_input("Version (optional)", "1.0.1f")
    keyword = st.text_input("Or keyword search", "")
    if st.button("Lookup threats", type="primary"):
        payload = {"components": [{"name": name, "version": version}]}
        if keyword:
            payload["keyword"] = keyword
        with st.spinner("Looking up CVEs..."):
            res = ThreatIntelligenceAgent().run(payload)
        render_result(res.to_dict())
        if res.metadata.get("web_context"):
            st.markdown("**Web / RAG context**")
            for c in res.metadata["web_context"]:
                st.markdown(f"- [{c['title']}]({c['url']}) ({c['source']})")


def tab_vuln_scanner() -> None:
    st.subheader("Vulnerability Scanner Agent")
    code = st.text_area("Code", "password = 'admin'\nos.system('rm -rf ' + path)\n", height=120)
    dockerfile = st.text_area("Dockerfile", "FROM ubuntu:latest\nUSER root\n", height=90)
    if st.button("Scan", type="primary"):
        payload = {
            "code": code, "filename": "app.py", "dockerfile": dockerfile,
            "database_config": {"engine": "postgres", "host": "0.0.0.0",
                                 "ssl": False, "password": "postgres"},
        }
        with st.spinner("Scanning..."):
            res = VulnerabilityScannerAgent().run(payload)
        render_result(res.to_dict())


def tab_policy() -> None:
    st.subheader("Policy Checker Agent")
    st.caption("Toggle the controls that are currently in place.")
    cols = st.columns(3)
    keys = [
        "mfa_enabled", "encryption_at_rest", "tls_enabled", "logging_enabled",
        "incident_response_plan", "vulnerability_management", "audit_logging",
        "least_privilege", "access_control", "change_management", "backups_tested",
    ]
    setup = {}
    for i, k in enumerate(keys):
        with cols[i % 3]:
            setup[k] = st.checkbox(k, value=(i % 2 == 0))
    if st.button("Check compliance", type="primary"):
        with st.spinner("Evaluating controls..."):
            res = PolicyCheckerAgent().run({"setup": setup})
        st.metric("Compliance score", f"{res.metadata.get('compliance_score', 0)}%")
        render_result(res.to_dict())


def tab_evals() -> None:
    st.subheader("Evaluation & Loop Engineering")
    st.caption("Assertion-based eval suite + brute-force threshold tuning loop.")
    if st.button("Run eval suite", type="primary"):
        from evals.evaluator import Evaluator

        with st.spinner("Running evals..."):
            report = Evaluator().run()
        st.metric("Pass rate", f"{report.pass_rate}%", f"{report.passed}/{report.total}")
        st.dataframe(
            [{"case": c.case_id, "agent": c.agent, "passed": c.passed,
              "findings": c.finding_count, "severity": c.severity}
             for c in report.cases],
            use_container_width=True,
        )
    if st.button("Run loop-engineering demo"):
        from evals.loop import ImprovementLoop

        with st.spinner("Sweeping detection threshold..."):
            history = ImprovementLoop().demo_threshold_sweep()
        h = history.to_dict()
        st.success(f"Best threshold config {h['best_config']} → "
                   f"{h['best_pass_rate']}% (improvement +{h['improvement']}pp)")
        st.dataframe(
            [{"iter": s.iteration, "threshold": s.config.get("brute_force_threshold"),
              "pass_rate": s.pass_rate, "accepted": s.accepted} for s in history.steps],
            use_container_width=True,
        )


WORKFLOW_DOT = r"""
digraph CyberSecurityAIAgent {
    rankdir=LR;
    fontname="Helvetica";
    node [fontname="Helvetica", style="filled", shape="box", color="#37474f",
          fontcolor="white"];
    edge [color="#90a4ae"];

    subgraph cluster_inputs {
        label="Inputs"; style="rounded"; color="#90a4ae"; fontcolor="#cfd8dc";
        host  [label="Hostname", fillcolor="#455a64"];
        dbname[label="Database server name", fillcolor="#455a64"];
        snow  [label="ServiceNow\nApplication Instance", fillcolor="#455a64"];
        logs  [label="Logs / Code /\nDockerfile / Setup", fillcolor="#455a64"];
    }

    inv  [label="Asset Inventory\n(ServiceNow CMDB / fixture)", fillcolor="#5e35b1"];
    resolve [label="Resolve mapped\ndatabase servers", fillcolor="#5e35b1"];

    subgraph cluster_agents {
        label="LangGraph multi-agent pipeline"; style="rounded";
        color="#90a4ae"; fontcolor="#cfd8dc";
        logmon [label="Log Monitor", fillcolor="#1565c0"];
        threat [label="Threat Intelligence\n(CVE + FAISS RAG + Tavily)", fillcolor="#1565c0"];
        vuln   [label="Vulnerability Scanner\n(code / DB / Docker)", fillcolor="#1565c0"];
        incident [label="Incident Response", fillcolor="#1565c0"];
        policy [label="Policy Checker\n(ISO/NIST/SOC2)", fillcolor="#1565c0"];
    }

    bulk [label="Bulk Scanner\n(scan all servers)", fillcolor="#00897b"];
    report [label="Aggregated report\n+ severity rollup", fillcolor="#e65100"];

    host -> inv;
    dbname -> inv;
    snow -> inv;
    inv -> resolve -> bulk;
    bulk -> vuln;
    bulk -> threat;
    vuln -> incident;
    threat -> incident;

    logs -> logmon;
    logmon -> threat -> vuln -> incident -> policy [style="dashed"];

    incident -> report;
    policy -> report;
}
"""


def tab_workflow() -> None:
    st.subheader("Workflow diagram")
    st.caption(
        "How inputs flow through the asset inventory, the bulk scanner and the "
        "LangGraph multi-agent pipeline to an aggregated report."
    )
    st.graphviz_chart(WORKFLOW_DOT, use_container_width=True)
    with st.expander("Legend"):
        st.markdown(
            "- **Inputs**: hostname, database-server name, ServiceNow Application "
            "Instance, or raw artifacts (logs/code/Dockerfile/setup).\n"
            "- **Asset Inventory** resolves an Application Instance (or host) to all "
            "mapped database servers via ServiceNow CMDB (offline fixture fallback).\n"
            "- **Bulk Scanner** fans out across every resolved server.\n"
            "- **LangGraph pipeline** (dashed path) is the single-target full scan."
        )


def tab_bulk_scan() -> None:
    st.subheader("Bulk scan (multiple inputs)")
    st.caption(
        "Provide any combination of hostnames, database-server names, or a "
        "ServiceNow Application Instance. All mapped database servers are resolved "
        "and scanned in bulk."
    )
    inventory = get_inventory()
    app_options = inventory.list_application_instances()

    col1, col2 = st.columns(2)
    with col1:
        app_instances = st.multiselect(
            "ServiceNow Application Instance(s)", app_options,
            default=app_options[:1] if app_options else [],
            help="Queries all database servers mapped to the application in the CMDB.",
        )
        hostnames_raw = st.text_area(
            "Hostnames (one per line)", "app-web-01.corp", height=90,
        )
    with col2:
        db_servers_raw = st.text_area(
            "Database server names (one per line)", "pg-analytics-1", height=90,
        )
        st.caption(f"Inventory source: **{inventory.source}**")

    if st.button("Run bulk scan", type="primary"):
        hostnames = [h for h in hostnames_raw.splitlines() if h.strip()]
        db_servers = [d for d in db_servers_raw.splitlines() if d.strip()]
        with st.spinner("Resolving inventory and scanning all mapped servers..."):
            report = get_bulk_scanner().run(
                hostnames=hostnames, db_servers=db_servers, app_instances=app_instances
            )

        summary = report["summary"]
        if report["resolved"] == 0:
            st.warning("No database servers were resolved from the provided inputs.")
            return

        st.success(
            f"Resolved & scanned **{summary['total_targets']}** database server(s) "
            f"({report['source']}) — {summary['total_findings']} findings, "
            f"worst severity {summary['worst_severity'].upper()}."
        )
        c1, c2, c3 = st.columns(3)
        c1.metric("Servers scanned", summary["total_targets"])
        c2.metric("Total findings", summary["total_findings"])
        c3.metric("Worst severity", summary["worst_severity"].upper())

        st.markdown("**Fleet overview**")
        st.dataframe(
            [
                {
                    "server": t["name"], "engine": t["engine"],
                    "hostname": t["hostname"], "app_instance": t["app_instance"],
                    "severity": t["severity"], "findings": t["finding_count"],
                }
                for t in report["targets"]
            ],
            use_container_width=True,
        )

        for t in report["targets"]:
            with st.expander(
                f"{t['name']} ({t['engine']}) — "
                f"{t['severity'].upper()} · {t['finding_count']} findings"
            ):
                for result in t["results"].values():
                    render_result(result)
                    st.divider()


def main() -> None:
    st.set_page_config(page_title="CyberSecurityAIAgent", page_icon="🛡️", layout="wide")
    sidebar()
    st.title("🛡️ CyberSecurityAIAgent")
    st.caption(
        "An AI-powered, multi-agent cybersecurity system: log monitoring, threat "
        "intelligence (CVE/RAG), vulnerability scanning, incident response and "
        "compliance — orchestrated with LangGraph."
    )
    tabs = st.tabs([
        "Workflow", "Bulk scan", "Full scan", "Log Monitor", "Threat Intel",
        "Vuln Scanner", "Policy Checker", "Evals & Loop",
    ])
    with tabs[0]:
        tab_workflow()
    with tabs[1]:
        tab_bulk_scan()
    with tabs[2]:
        tab_full_scan()
    with tabs[3]:
        tab_log_monitor()
    with tabs[4]:
        tab_threat_intel()
    with tabs[5]:
        tab_vuln_scanner()
    with tabs[6]:
        tab_policy()
    with tabs[7]:
        tab_evals()


main()
