# AGENTS.md

Operating guide for the `CyberSecurityAIAgent` project.

## Project overview

Multi-agent cybersecurity system (LangGraph orchestration, FAISS RAG, Streamlit
UI). Five agents: Log Monitor, Threat Intelligence, Vulnerability Scanner,
Incident Response, Policy Checker. See `README.md` for the full description.

## Layout

- `config/` — typed settings (`pydantic-settings`) + logging.
- `tools/` — deterministic tools (log detectors, CVE lookup, scanners, policy
  checks, FAISS vector store, web search). Pure functions; unit-tested.
- `main/` — `llm.py` (LLM factory + offline fallback), `agents/`, `orchestrator.py`.
- `evals/` — assertion-based eval harness + loop-engineering demo.
- `app/streamlit_app.py` — the UI (entry point for Streamlit Cloud).
- `data/` — sample logs, CVE corpus, RAG knowledge base.

## Standard commands

Documented in `README.md`. In short: `pip install -r requirements.txt`,
`streamlit run app/streamlit_app.py`, `python -m evals.run_evals --loop`,
`pytest`.

## Cursor Cloud specific instructions

- **Always work inside the project venv:** `source .venv/bin/activate` before
  running `pytest`, `streamlit`, or the evals. The update script creates/refreshes
  `.venv` and installs `requirements.txt`.
- **Offline by default:** with no `OPENAI_API_KEY` / `TAVILY_API_KEY`, the system
  runs in deterministic mode — the LLM factory (`main/llm.py`), embeddings
  (`tools/embeddings.py` hashing fallback) and web search (`tools/websearch.py`
  local corpus) all degrade gracefully. This is intentional and required for the
  eval suite to be reproducible. Set keys in a `.env` file (see `.env.example`)
  or Streamlit secrets to enable live LLM/web-search; no code change needed.
- **Eval determinism:** `evals/datasets/security_cases.json` is tuned to pass
  100% in offline mode. The loop-engineering demo
  (`ImprovementLoop.demo_threshold_sweep`) mutates the global brute-force
  threshold via `tools/log_tools.set_brute_force_threshold` and leaves it at the
  best value (5); tests that depend on it call `set_brute_force_threshold(5)`
  first to avoid cross-test order coupling.
- **Streamlit run:** launch with `streamlit run app/streamlit_app.py` (config in
  `.streamlit/config.toml` binds `0.0.0.0:8501`, headless). The app inserts the
  project root onto `sys.path` itself, so it can be launched from any CWD.
- **Bulk scan / CMDB:** `main/bulk_scanner.py` resolves hostnames, database
  server names and ServiceNow Application Instances to database servers via
  `tools/asset_inventory.py`. With `SNOW_INSTANCE_URL`/`SNOW_USERNAME`/
  `SNOW_PASSWORD` set it queries ServiceNow (`cmdb_ci_appl` + `cmdb_rel_ci`);
  otherwise it uses the offline fixture `data/cmdb/cmdb.json`. The ServiceNow
  backend falls back to the fixture on any API error, so bulk scans never hard
  fail. The Streamlit "Workflow" tab renders the architecture via
  `st.graphviz_chart` (no system Graphviz binary needed — Streamlit ships the
  renderer).
- **LangGraph engine:** `SecurityOrchestrator` builds a real `StateGraph`; if
  `langgraph` import/compile ever fails it silently falls back to an equivalent
  sequential pipeline. Check the `engine` field in the orchestrator output to
  confirm which path ran (`langgraph` vs `sequential`).
