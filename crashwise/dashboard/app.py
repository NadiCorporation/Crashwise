# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""CrashWise Control Plane — real-time campaign command center.

Bi-directional interface: live telemetry polling (1Hz) + God-Mode
signal dispatch via REST API. Dark-mode terminal aesthetic.

Usage::
    streamlit run crashwise/dashboard/app.py
"""

from __future__ import annotations

import asyncio
import base64
import os
import time
from typing import Any

import httpx
import streamlit as st

# ── Configuration ────────────────────────────────────────────────────────────

API_BASE = os.environ.get("CRASHWISE_API_URL", os.environ.get("API_URL", "http://localhost:8000"))

st.set_page_config(
    page_title="CrashWise",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Dark terminal CSS ────────────────────────────────────────────────────────

st.markdown("""
<style>
    .stApp { background-color: #0d1117; color: #c9d1d9; }
    .stSidebar { background-color: #161b22; }
    .stMetric label { color: #8b949e !important; font-size: 0.7rem !important; }
    .stMetric [data-testid="stMetricValue"] { color: #58a6ff !important; font-size: 1.4rem !important; }
    .block-container { padding-top: 1rem; }
    h1, h2, h3 { color: #f0f6fc !important; }
    .status-green { color: #3fb950; font-weight: bold; }
    .status-amber { color: #d29922; font-weight: bold; }
    .status-red { color: #f85149; font-weight: bold; }
    .mono { font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.8rem; }
    .terminal-pane {
        background: #0d1117; border: 1px solid #30363d; border-radius: 6px;
        padding: 12px; font-family: monospace; font-size: 0.75rem;
        color: #c9d1d9; overflow-x: auto; white-space: pre-wrap;
    }
    .badge {
        display: inline-block; padding: 2px 8px; border-radius: 10px;
        font-size: 0.65rem; font-weight: 700; text-transform: uppercase;
    }
    .badge-running { background: #1f6feb; color: #fff; }
    .badge-completed { background: #238636; color: #fff; }
    .badge-failed { background: #da3633; color: #fff; }
    .badge-stalled { background: #9e6a03; color: #fff; }
    .badge-pending { background: #30363d; color: #8b949e; }
</style>
""", unsafe_allow_html=True)


# ── API helpers ──────────────────────────────────────────────────────────────

def api_get(path: str, params: dict[str, Any] | None = None) -> Any:
    try:
        resp = httpx.get(f"{API_BASE}{path}", params=params, timeout=10.0)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None


def api_post(path: str, payload: dict[str, Any]) -> Any:
    try:
        resp = httpx.post(f"{API_BASE}{path}", json=payload, timeout=15.0)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"error": str(e)}


def api_delete(path: str) -> bool:
    try:
        resp = httpx.delete(f"{API_BASE}{path}", timeout=10.0)
        return resp.status_code in (200, 204)
    except Exception:
        return False


def status_badge(status: str) -> str:
    cls = f"badge-{status}" if status in ("running", "completed", "failed", "stalled", "pending") else "badge-pending"
    return f'<span class="badge {cls}">{status}</span>'


# ── Telemetry fetch ──────────────────────────────────────────────────────────

def fetch_telemetry() -> dict[str, Any]:
    data = api_get("/api/v1/telemetry/stream")
    if data is None:
        # Fallback: construct from campaigns
        return {"global_execs_per_sec": 0, "total_executions": 0, "unique_edges": 0, "crashes_found": 0}
    return data


# ── Navigation ───────────────────────────────────────────────────────────────

tabs = st.tabs(["⚡ LIVE", "📋 CAMPAIGNS", "🔴 CRASHES", "🎛️ GOD-MODE", "🔧 SETUP"])

# ══════════════════════════════════════════════════════════════════════════════
# TAB: LIVE TELEMETRY
# ══════════════════════════════════════════════════════════════════════════════

with tabs[0]:
    st.markdown("## Live Execution Telemetry")

    # Top metrics bar
    campaigns = api_get("/campaigns", {"limit": 50}) or []
    running = [c for c in campaigns if c.get("status") == "running"]
    workers = api_get("/workers") or []

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Active Campaigns", len(running))
    m2.metric("Workers Online", len(workers))
    m3.metric("Total Campaigns", len(campaigns))
    m4.metric("Completed", sum(1 for c in campaigns if c.get("status") == "completed"))
    m5.metric("Crashes Found", sum(c.get("run_count", 0) for c in campaigns))

    st.markdown("---")

    if running:
        for camp in running:
            cid = camp["id"]
            st.markdown(f"### `{camp['target_name']}` {status_badge('running')}", unsafe_allow_html=True)

            # Fetch campaign detail for run info
            detail = api_get(f"/campaigns/{cid}")
            if detail and detail.get("runs"):
                latest_run = detail["runs"][-1] if detail["runs"] else {}
                rc1, rc2, rc3, rc4 = st.columns(4)
                rc1.metric("Iteration", latest_run.get("iteration", "—"))
                rc2.metric("Executions", f"{latest_run.get('executions', 0):,}")
                rc3.metric("Coverage Edges", latest_run.get("coverage_edges", "—"))
                rc4.metric("Duration", f"{latest_run.get('duration_seconds', 0):.0f}s")

            # Verbose execution state from Temporal workflow queries
            live_state = api_get(f"/campaigns/{cid}/state")
            if live_state and not live_state.get("error"):
                stage = live_state.get("stage", "unknown")
                iteration = live_state.get("iteration", 0)
                pivot_count = live_state.get("pivot_count", 0)
                evolution_count = live_state.get("evolution_count", 0)
                paused = live_state.get("paused", False)
                pending_seeds = live_state.get("pending_seeds", 0)
                last_note = live_state.get("last_note", "")

                # Map stage to human-readable activity description
                stage_desc = {
                    "pending": "Initializing workflow…",
                    "seeding": "Activity: seed_corpus → harvesting test vectors",
                    "setup": "Activity: setup_target → clone + build + harness synthesis",
                    "executing": "Activity: execute_fuzzing → Docker container running",
                    "triage": "Activity: triage_results → crash classification + dedup",
                    "completed": "Workflow complete",
                    "failed": "Workflow failed",
                }.get(stage, f"Stage: {stage}")

                stage_color = {
                    "pending": "status-amber",
                    "seeding": "status-amber",
                    "setup": "status-amber",
                    "executing": "status-green",
                    "triage": "status-amber",
                    "completed": "status-green",
                    "failed": "status-red",
                }.get(stage, "status-amber")

                st.markdown(f"""
<div class="terminal-pane">
<span class="{stage_color}">●</span> <b>{stage_desc}</b>
<span class="status-green">●</span> Workflow: crashwise-campaign-{cid[:8]}…
<span class="status-green">●</span> Container: crashwise-{cid[:8]}-iter{iteration}
─────────────────────────────────────────────────
  Stage:          {stage.upper()}
  Iteration:      {iteration}
  Pivot Count:    {pivot_count} (MAB strategy switches)
  Evolution Count: {evolution_count} (harness rewrites)
  Paused:         {'YES ⏸' if paused else 'NO'}
  Pending Seeds:  {pending_seeds}
{f'  Last Note:      {last_note}' if last_note else ''}
</div>
""", unsafe_allow_html=True)
            else:
                # Fallback when Temporal query fails (workflow may have just started)
                st.markdown(f"""
<div class="terminal-pane">
<span class="status-green">●</span> Workflow: crashwise-campaign-{cid[:8]}…
<span class="status-amber">●</span> Stage: INITIALIZING (waiting for first heartbeat)
<span class="status-green">●</span> Container: crashwise-{cid[:8]}-iter0
</div>
""", unsafe_allow_html=True)
            st.markdown("")
    else:
        st.info("No active campaigns. Submit one via CLI or the Campaigns tab.")

    # Auto-refresh
    if st.button("🔄 Refresh", key="refresh_live"):
        st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# TAB: CAMPAIGNS
# ══════════════════════════════════════════════════════════════════════════════

with tabs[1]:
    st.markdown("## Campaigns")

    campaigns = api_get("/campaigns", {"limit": 100}) or []

    if not campaigns:
        st.info("No campaigns. Run `crashwise run <repo-url>` to start.")
    else:
        # Bulk actions
        del_col1, del_col2, del_col3 = st.columns([2, 2, 6])
        with del_col1:
            if st.button("🗑️ Delete All", type="secondary", key="del_all"):
                api_delete("/campaigns")
                st.rerun()
        with del_col2:
            if st.button("🗑️ Delete Failed", key="del_failed"):
                api_delete("/campaigns?status_filter=failed,stalled")
                st.rerun()

        st.markdown("---")
        for c in campaigns:
            col1, col2, col3, col4 = st.columns([4, 1, 1, 1])
            col1.markdown(
                f"**{c['target_name']}** {status_badge(c['status'])}<br>"
                f"<span class='mono'>{c['target_repo']}</span>",
                unsafe_allow_html=True,
            )
            col2.markdown(f"Runs: **{c['run_count']}**")
            col3.markdown(f"Seeds: **{c['seed_count']}**")
            with col4:
                if st.button("🗑️", key=f"del_{c['id']}", help="Delete campaign"):
                    api_delete(f"/campaigns/{c['id']}")
                    st.rerun()

            # Forensic pane for failed/stalled campaigns
            if c["status"] in ("failed", "stalled"):
                detail = api_get(f"/campaigns/{c['id']}")
                if detail:
                    with st.expander(f"⚠️ Failure Diagnostics — {c['target_name']}", expanded=False):
                        runs = detail.get("runs", [])
                        if runs:
                            last = runs[-1]
                            st.markdown(f"""
<div class="terminal-pane">
<span class="status-red">✗</span> Campaign Status: {c['status'].upper()}
<span class="status-red">✗</span> Last Iteration: {last.get('iteration', '?')}
<span class="status-red">✗</span> Executions: {last.get('executions', 0):,}
<span class="status-red">✗</span> Duration: {last.get('duration_seconds', 0):.1f}s
<span class="status-red">✗</span> Coverage Edges: {last.get('coverage_edges', 0)}
<span class="status-amber">→</span> Failure Boundary: {'Zero coverage (instrumentation failure)' if last.get('coverage_edges', 0) == 0 else 'Coverage plateau / stall detected'}
<span class="status-amber">→</span> Check: crashwise doctor && review build logs
</div>
""", unsafe_allow_html=True)
                        else:
                            st.markdown("""
<div class="terminal-pane">
<span class="status-red">✗</span> No runs recorded — setup_target likely failed.
<span class="status-amber">→</span> Probable cause: git clone failure, build system incompatibility, or missing harness.
<span class="status-amber">→</span> Action: Check Temporal UI at :8233 for activity error details.
</div>
""", unsafe_allow_html=True)

            st.markdown("<hr style='border-color:#21262d;margin:4px 0'>", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB: CRASHES
# ══════════════════════════════════════════════════════════════════════════════

with tabs[2]:
    st.markdown("## Crash Intelligence")

    campaigns = api_get("/campaigns", {"limit": 100}) or []
    campaign_map = {c["target_name"]: c["id"] for c in campaigns}

    if not campaign_map:
        st.info("No campaigns available.")
    else:
        sel_col, filt_col1, filt_col2 = st.columns([3, 2, 2])
        with sel_col:
            selected = st.selectbox("Campaign", list(campaign_map.keys()), key="crash_campaign")
        with filt_col1:
            cwe_filter = st.text_input("CWE Filter", placeholder="cwe-416", key="cwe_f")
        with filt_col2:
            min_score = st.number_input("Min Score", 0, 10, 0, key="min_s")

        cid = campaign_map[selected]
        params: dict[str, Any] = {}
        if cwe_filter:
            params["vulnerability_type"] = cwe_filter
        if min_score > 0:
            params["min_severity_score"] = min_score

        crashes = api_get(f"/campaigns/{cid}/crashes", params) or []

        if not crashes:
            st.info("No crashes match filters.")
        else:
            st.markdown(f"**{len(crashes)}** unique crashes")

            for i, c in enumerate(crashes):
                sev_color = "#f85149" if c["severity_score"] >= 8 else "#d29922" if c["severity_score"] >= 5 else "#3fb950"
                with st.expander(
                    f"#{i+1} {c['crash_type']} — {c['vulnerability_type']} "
                    f"[{c['severity_score']}/10]"
                ):
                    st.markdown(f"""
<div class="terminal-pane">
Type:       {c['crash_type']}
Severity:   <span style="color:{sev_color}">{c['severity']} ({c['severity_score']}/10)</span>
CWE:        {c['vulnerability_type']}
Signal:     {c['signal']}
Stack Hash: {c['stack_hash']}
Discovered: {c['created_at']}
</div>
""", unsafe_allow_html=True)

                    t1, t2 = st.tabs(["Stack Trace", "Suggested Patch"])
                    with t1:
                        st.code(c.get("stack_trace", "N/A")[:3000], language="text")
                    with t2:
                        if c.get("suggested_patch"):
                            st.code(c["suggested_patch"], language="cpp")
                        else:
                            st.caption("No patch available. Configure AI_PROVIDER for deep analysis.")

        # Export
        st.markdown("---")
        e1, e2 = st.columns(2)
        e1.link_button("Export Markdown", f"{API_BASE}/campaigns/{cid}/export?fmt=markdown")
        e2.link_button("Export JSON", f"{API_BASE}/campaigns/{cid}/export?fmt=json")


# ══════════════════════════════════════════════════════════════════════════════
# TAB: GOD-MODE CONTROL PLANE
# ══════════════════════════════════════════════════════════════════════════════

with tabs[3]:
    st.markdown("## God-Mode Runtime Control")
    st.caption("Bi-directional signal dispatch to active Temporal workflows.")

    campaigns = api_get("/campaigns", {"limit": 50}) or []
    running = [c for c in campaigns if c.get("status") == "running"]

    if not running:
        st.warning("No active campaigns to control. Start a campaign first.")
    else:
        target_names = {c["target_name"]: c["id"] for c in running}
        selected_target = st.selectbox("Target Campaign", list(target_names.keys()), key="god_target")
        workflow_id = f"crashwise-campaign-{target_names[selected_target]}"

        st.markdown("---")

        # ── PAUSE / RESUME ────────────────────────────────────────────────
        st.markdown("### ⏸️ Pause / Resume")
        p1, p2 = st.columns(2)
        with p1:
            if st.button("⏸️ PAUSE CAMPAIGN", use_container_width=True, type="primary"):
                result = api_post("/campaigns/signal", {
                    "workflow_id": workflow_id,
                    "signal": "pause_hunt",
                    "payload": True,
                })
                if result and result.get("ok"):
                    st.success(f"Signal sent: pause_hunt → {workflow_id[:30]}…")
                else:
                    st.error(f"Signal failed: {result}")
        with p2:
            if st.button("▶️ RESUME CAMPAIGN", use_container_width=True):
                result = api_post("/campaigns/signal", {
                    "workflow_id": workflow_id,
                    "signal": "pause_hunt",
                    "payload": False,
                })
                if result and result.get("ok"):
                    st.success(f"Signal sent: resume → {workflow_id[:30]}…")
                else:
                    st.error(f"Signal failed: {result}")

        st.markdown("---")

        # ── FORCE PIVOT ───────────────────────────────────────────────────
        st.markdown("### 🔀 Force Strategy Pivot")
        pivot_reason = st.text_input("Reason", value="operator override", key="pivot_reason")
        if st.button("🔀 FORCE PIVOT", use_container_width=True):
            result = api_post("/campaigns/signal", {
                "workflow_id": workflow_id,
                "signal": "force_pivot",
                "payload": pivot_reason,
            })
            if result and result.get("ok"):
                st.success(f"Signal sent: force_pivot ({pivot_reason})")
            else:
                st.error(f"Signal failed: {result}")

        st.markdown("---")

        # ── INJECT SEED ───────────────────────────────────────────────────
        st.markdown("### 💉 Inject Seed")
        uploaded = st.file_uploader(
            "Drop a seed file (.png, .json, .bin, etc.)",
            type=None,
            key="seed_upload",
        )
        if uploaded and st.button("💉 INJECT INTO CORPUS", use_container_width=True):
            raw_b64 = base64.b64encode(uploaded.read()).decode("ascii")
            result = api_post("/campaigns/signal", {
                "workflow_id": workflow_id,
                "signal": "inject_seed",
                "payload": {"filename": uploaded.name, "data_b64": raw_b64},
            })
            if result and result.get("ok"):
                st.success(f"Seed injected: {uploaded.name} ({len(raw_b64)} b64 chars)")
            else:
                st.error(f"Injection failed: {result}")

        st.markdown("---")

        # ── WORKFLOW QUERY ────────────────────────────────────────────────
        st.markdown("### 📊 Workflow State Query")
        if st.button("Query signal_status", key="query_status"):
            # Query goes through Temporal directly since there's no REST endpoint for queries.
            # Use nest_asyncio to handle Streamlit's event loop.
            try:
                import nest_asyncio
                nest_asyncio.apply()
                from crashwise.orchestration.client import connect as temporal_connect
                client = asyncio.run(temporal_connect())
                handle = client.get_workflow_handle(workflow_id)
                result = asyncio.run(handle.query("signal_status"))
                st.json(result)
            except ImportError:
                st.warning("Install `nest_asyncio` for workflow queries: `pip install nest_asyncio`")
            except Exception as e:
                st.error(f"Query failed: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# TAB: SETUP / ONBOARDING
# ══════════════════════════════════════════════════════════════════════════════

with tabs[4]:
    st.markdown("## Platform Configuration")
    st.caption("Configure LLM providers and infrastructure without editing .env files.")

    # ── Step 1: LLM Provider ─────────────────────────────────────────────
    st.markdown("### 1. Harness Synthesis LLM")

    provider = st.selectbox(
        "Provider",
        ["anthropic", "openai", "openai_compatible", "ollama"],
        key="setup_provider",
    )

    model_defaults = {
        "anthropic": "claude-sonnet-4-5",
        "openai": "gpt-4o",
        "openai_compatible": "llama3.1:70b",
        "ollama": "llama3.1:8b",
    }

    model = st.text_input("Model", value=model_defaults.get(provider, ""), key="setup_model")

    api_key = ""
    base_url = ""
    if provider in ("anthropic", "openai"):
        api_key = st.text_input(
            "API Key",
            type="password",
            placeholder="sk-ant-... or sk-...",
            key="setup_key",
        )
    elif provider == "openai_compatible":
        base_url = st.text_input("Base URL", value="http://localhost:11434/v1", key="setup_base")
        api_key = st.text_input("API Key (optional)", type="password", key="setup_compat_key")
    elif provider == "ollama":
        base_url = st.text_input("Ollama URL", value="http://localhost:11434", key="setup_ollama_url")

    # ── Test Connection ──────────────────────────────────────────────────
    if st.button("🔌 Test Connection", key="test_llm"):
        with st.spinner("Testing..."):
            try:
                if provider == "ollama":
                    resp = httpx.get(f"{base_url}/api/tags", timeout=5.0)
                    if resp.status_code == 200:
                        models = [m["name"] for m in resp.json().get("models", [])]
                        st.success(f"Connected. Available models: {', '.join(models[:5])}")
                    else:
                        st.error(f"Ollama returned {resp.status_code}")
                elif provider == "openai_compatible":
                    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
                    resp = httpx.get(f"{base_url}/models", headers=headers, timeout=5.0)
                    if resp.status_code == 200:
                        st.success("Connected to OpenAI-compatible endpoint.")
                    else:
                        st.error(f"Endpoint returned {resp.status_code}")
                elif provider == "anthropic":
                    resp = httpx.post(
                        "https://api.anthropic.com/v1/messages",
                        headers={
                            "x-api-key": api_key,
                            "anthropic-version": "2023-06-01",
                            "content-type": "application/json",
                        },
                        json={"model": model, "max_tokens": 1, "messages": [{"role": "user", "content": "hi"}]},
                        timeout=10.0,
                    )
                    if resp.status_code in (200, 201):
                        st.success(f"Anthropic API key valid. Model: {model}")
                    elif resp.status_code == 401:
                        st.error("Invalid API key.")
                    else:
                        st.warning(f"Anthropic returned {resp.status_code}: {resp.text[:200]}")
                elif provider == "openai":
                    resp = httpx.get(
                        "https://api.openai.com/v1/models",
                        headers={"Authorization": f"Bearer {api_key}"},
                        timeout=5.0,
                    )
                    if resp.status_code == 200:
                        st.success("OpenAI API key valid.")
                    else:
                        st.error(f"OpenAI returned {resp.status_code}")
            except Exception as e:
                st.error(f"Connection failed: {e}")

    st.markdown("---")

    # ── Step 2: Triage Provider (optional) ────────────────────────────────
    st.markdown("### 2. Crash Triage LLM (optional)")
    st.caption("Falls back to regex heuristics if not configured.")

    triage_provider = st.selectbox(
        "Triage Provider",
        ["disabled", "ollama", "venice", "openai_compatible"],
        key="triage_provider",
    )
    triage_model = ""
    triage_url = ""
    triage_key = ""
    if triage_provider != "disabled":
        triage_model = st.text_input("Triage Model", value="llama3.1:8b", key="triage_model")
        if triage_provider == "ollama":
            triage_url = st.text_input("Ollama URL", value="http://localhost:11434", key="triage_url")
        elif triage_provider in ("venice", "openai_compatible"):
            triage_url = st.text_input("API Base URL", key="triage_base")
            triage_key = st.text_input("API Key", type="password", key="triage_key")

    st.markdown("---")

    # ── Step 3: Infrastructure ────────────────────────────────────────────
    st.markdown("### 3. Infrastructure")

    db_url = st.text_input("Database URL", value="sqlite+aiosqlite:///./crashwise.db", key="db_url")
    redis_url = st.text_input("Redis URL", value="redis://localhost:6379/0", key="redis_url")
    temporal_host = st.text_input("Temporal Host", value="localhost:7233", key="temporal_host")

    st.markdown("---")

    # ── Save Configuration ────────────────────────────────────────────────
    if st.button("💾 Save & Apply Configuration", type="primary", use_container_width=True):
        env_lines = [
            f"CRASHWISE_LLM_MODEL={model}",
        ]
        if provider == "anthropic" and api_key:
            env_lines.append(f"ANTHROPIC_API_KEY={api_key}")
        elif provider == "openai" and api_key:
            env_lines.append(f"OPENAI_API_KEY={api_key}")
        elif provider in ("openai_compatible", "ollama"):
            if base_url:
                env_lines.append(f"OPENAI_API_BASE={base_url}")
            if api_key:
                env_lines.append(f"OPENAI_API_KEY={api_key}")

        if triage_provider != "disabled":
            env_lines.append(f"AI_PROVIDER={triage_provider}")
            env_lines.append(f"AI_MODEL={triage_model}")
            if triage_url:
                env_lines.append(f"OLLAMA_URL={triage_url}")
            if triage_key:
                env_lines.append(f"AI_API_KEY={triage_key}")

        env_lines.append(f"DATABASE_URL={db_url}")
        env_lines.append(f"REDIS_URL={redis_url}")
        env_lines.append(f"TEMPORAL_HOST={temporal_host}")

        env_content = "\n".join(env_lines) + "\n"

        try:
            env_path = os.path.join(os.getcwd(), ".env")
            with open(env_path, "w") as f:
                f.write(env_content)
            st.success(f"Configuration written to `{env_path}`")
            st.code(env_content, language="bash")
        except OSError as e:
            st.error(f"Failed to write .env: {e}")
            st.code(env_content, language="bash")
            st.caption("Copy the above manually to your .env file.")
