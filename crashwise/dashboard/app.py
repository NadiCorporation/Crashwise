# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""CrashWise Intelligence Dashboard — Streamlit frontend (Phase 11).

A human-friendly interface for exploring AI-driven triage results,
monitoring distributed worker health, and exporting crash reports.

Usage::

    streamlit run crashwise/dashboard/app.py

Pages
-----
* **Campaigns** — List all fuzzing campaigns with status.
* **Crash Intelligence** — Deep-dive into crashes with severity heatmap,
  CWE filters, and patch viewer.
* **Cluster Status** — Real-time worker replica health from Redis.
"""

from __future__ import annotations

import urllib.parse
from typing import Any

import httpx
import streamlit as st

# ── Configuration ──────────────────────────────────────────────────────────────

API_BASE = st.secrets.get("api_url", "http://localhost:8000")

st.set_page_config(
    page_title="CrashWise Intelligence Dashboard",
    page_icon="🧠",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ── Helpers ──────────────────────────────────────────────────────────────────

async def _api_get(path: str, params: dict[str, Any] | None = None) -> Any:
    """Async GET to the FastAPI backend."""
    url = f"{API_BASE}{path}"
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()


async def _api_post(path: str, payload: dict[str, Any]) -> Any:
    """Async POST to the FastAPI backend."""
    url = f"{API_BASE}{path}"
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, json=payload)
        resp.raise_for_status()
        return resp.json()


def _severity_color(score: int) -> str:
    """Return a CSS color for a severity score (0-10)."""
    if score >= 8:
        return "#dc2626"  # red-600
    if score >= 5:
        return "#ea580c"  # orange-600
    if score >= 3:
        return "#ca8a04"  # yellow-600
    return "#16a34a"  # green-600


def _severity_badge(score: int) -> str:
    """Return an HTML badge for a severity score."""
    color = _severity_color(score)
    label = "CRITICAL" if score >= 8 else "HIGH" if score >= 5 else "MEDIUM" if score >= 3 else "LOW"
    return f"""
    <span style="
        background-color: {color};
        color: white;
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 0.75rem;
        font-weight: bold;
    ">{label} ({score}/10)</span>
    """


# ── Navigation ─────────────────────────────────────────────────────────────────

page = st.sidebar.radio(
    "Navigation",
    ["🏠 Campaigns", "🔥 Crash Intelligence", "🖥️ Cluster Status", "⚙️ Settings"],
)

st.sidebar.markdown("---")
st.sidebar.caption("CrashWise v0.1.0 — Phase 13")


# ── Page: Campaigns ────────────────────────────────────────────────────────────

if page == "🏠 Campaigns":
    st.title("🧠 CrashWise Campaigns")
    st.markdown("Overview of all fuzzing campaigns and their current status.")

    import asyncio

    try:
        campaigns = asyncio.run(_api_get("/campaigns", {"limit": 100}))
    except Exception as exc:
        st.error(f"Failed to fetch campaigns: {exc}")
        st.stop()

    if not campaigns:
        st.info("No campaigns found. Start one via the API or CLI.")
    else:
        cols = st.columns(4)
        total = len(campaigns)
        running = sum(1 for c in campaigns if c["status"] == "running")
        completed = sum(1 for c in campaigns if c["status"] == "completed")
        crashed = sum(1 for c in campaigns if c["status"] == "failed")
        cols[0].metric("Total Campaigns", total)
        cols[1].metric("Running", running)
        cols[2].metric("Completed", completed)
        cols[3].metric("Failed", crashed)

        st.markdown("---")

        for c in campaigns:
            with st.container():
                c1, c2, c3 = st.columns([3, 1, 1])
                c1.markdown(f"**{c['target_name']}**  
`{c['target_repo']}`")
                c2.markdown(f"Status: **{c['status']}**")
                c3.markdown(f"Runs: {c['run_count']} | Seeds: {c['seed_count']}")
                if st.button("🔍 View Details", key=f"btn_{c['id']}"):
                    st.session_state.selected_campaign = c["id"]
                    st.rerun()
                st.markdown("---")


# ── Page: Crash Intelligence ───────────────────────────────────────────────────

elif page == "🔥 Crash Intelligence":
    st.title("🔥 Crash Intelligence")
    st.markdown("AI-driven triage results with severity heatmap, CWE filters, and patch viewer.")

    import asyncio

    # Campaign selector
    try:
        campaigns = asyncio.run(_api_get("/campaigns", {"limit": 100}))
    except Exception as exc:
        st.error(f"Failed to fetch campaigns: {exc}")
        st.stop()

    campaign_options = {c["target_name"]: c["id"] for c in campaigns}
    if not campaign_options:
        st.info("No campaigns available. Start a campaign first.")
        st.stop()

    selected_name = st.selectbox("Select Campaign", list(campaign_options.keys()))
    campaign_id = campaign_options[selected_name]

    # Filters
    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        cwe_filter = st.text_input("🔍 Filter by CWE (e.g., cwe-416)", "")
    with col2:
        min_score = st.slider("Minimum Severity Score", 0, 10, 0)

    params: dict[str, Any] = {}
    if cwe_filter.strip():
        params["vulnerability_type"] = cwe_filter.strip()
    if min_score > 0:
        params["min_severity_score"] = min_score

    try:
        crashes = asyncio.run(
            _api_get(f"/campaigns/{campaign_id}/crashes", params)
        )
    except Exception as exc:
        st.error(f"Failed to fetch crashes: {exc}")
        st.stop()

    if not crashes:
        st.info("No crashes match the selected filters.")
    else:
        st.markdown(f"**{len(crashes)} crashes found**")

        # Severity heatmap / distribution
        st.markdown("### Severity Distribution")
        scores = [c["severity_score"] for c in crashes]
        import pandas as pd

        df = pd.DataFrame({"Score": scores})
        st.bar_chart(df["Score"].value_counts().sort_index())

        st.markdown("---")

        # Crash cards
        for idx, c in enumerate(crashes, 1):
            with st.expander(f"Crash #{idx}: {c['crash_type']} — {c['vulnerability_type']}"):
                st.markdown(_severity_badge(c["severity_score"]), unsafe_allow_html=True)
                st.markdown(f"**Signal:** {c['signal']}  |  **Stack Hash:** `{c['stack_hash']}`")

                tabs = st.tabs(["📋 Details", "🔧 Patch", "📜 Stack Trace"])

                with tabs[0]:
                    st.json({
                        "crash_type": c["crash_type"],
                        "severity": c["severity"],
                        "severity_score": c["severity_score"],
                        "vulnerability_type": c["vulnerability_type"],
                        "signal": c["signal"],
                        "logs_path": c["logs_path"],
                        "created_at": c["created_at"],
                    })

                with tabs[1]:
                    if c["suggested_patch"]:
                        st.code(c["suggested_patch"], language="cpp")
                        # Bounty Report button
                        if st.button(
                            "💰 1-Click Bounty Report",
                            key=f"bounty_{c['id']}",
                            help="Copy AI-generated report to clipboard",
                        ):
                            report_text = f"""\
# {c['crash_type'].replace('-', ' ').title()} in {selected_name}

**Severity:** {c['severity']} ({c['severity_score']}/10)
**CWE:** {c['vulnerability_type']}
**Status:** {c.get('verification_status', 'pending')}

## Suggested Patch
```cpp
{c['suggested_patch']}
```

## Stack Trace
```
{c['stack_trace'][:1500]}
```

---
*Generated by CrashWise*
"""
                            st.code(report_text, language="markdown")
                            st.success("Report generated! Copy the text above.")

                        # Verify Patch button
                        if st.button(
                            "🧪 Verify Patch",
                            key=f"verify_{c['id']}",
                            help="Trigger autonomous patch verification workflow",
                        ):
                            with st.spinner("Triggering verification workflow..."):
                                import asyncio

                                try:
                                    resp = asyncio.run(
                                        _api_post(
                                            f"/crashes/{c['id']}/verify",
                                            {
                                                "crash_id": c["id"],
                                                "campaign_id": campaign_id,
                                                "repo_url": campaign_options.get(selected_name, ""),
                                                "patch": c["suggested_patch"],
                                                "seed_path": c["logs_path"],
                                                "fuzzer_type": "libfuzzer",
                                                "timeout_seconds": 60,
                                            },
                                        )
                                    )
                                    st.success(f"Verification started: `{resp['workflow_id']}`")
                                except Exception as exc:
                                    st.error(f"Failed to start verification: {exc}")
                    else:
                        st.info("No patch suggestion available. AI provider may not be configured.")

                with tabs[2]:
                    st.code(c["stack_trace"][:3000], language="text")

        # Export button
        st.markdown("---")
        export_col1, export_col2 = st.columns(2)
        with export_col1:
            md_url = f"{API_BASE}/campaigns/{campaign_id}/export?fmt=markdown"
            st.link_button("📥 Export Markdown Report", md_url)
        with export_col2:
            json_url = f"{API_BASE}/campaigns/{campaign_id}/export?fmt=json"
            st.link_button("📥 Export JSON Report", json_url)


# ── Page: Cluster Status ─────────────────────────────────────────────────────

elif page == "🖥️ Cluster Status":
    st.title("🖥️ Cluster Status")
    st.markdown("Real-time worker replica health from Redis heartbeat registry.")

    import asyncio

    try:
        workers = asyncio.run(_api_get("/workers"))
    except Exception as exc:
        st.error(f"Failed to fetch worker status: {exc}")
        st.stop()

    if not workers:
        st.info("No active workers detected. Ensure Redis is enabled and workers are running.")
    else:
        st.markdown(f"**{len(workers)} active worker(s)**")

        cols = st.columns(3)
        for idx, w in enumerate(workers):
            with cols[idx % 3]:
                st.metric(
                    label=w["name"],
                    value=w["status"].upper(),
                    delta="Online" if w["status"] == "online" else "Offline",
                )

        st.markdown("---")
        st.markdown("### Worker Details")
        for w in workers:
            st.markdown(f"- **{w['name']}** — Status: `{w['status']}`")


# ── Page: Settings ───────────────────────────────────────────────────────────

elif page == "⚙️ Settings":
    st.title("⚙️ Notification Settings")
    st.markdown("Configure alert channels for high-severity verified crashes.")

    st.markdown("### Webhook")
    webhook_url = st.text_input(
        "Webhook URL",
        value=st.secrets.get("webhook_url", ""),
        help="Slack/Discord incoming webhook URL",
    )
    webhook_format = st.selectbox(
        "Webhook Format",
        ["slack", "discord", "generic"],
        index=0,
    )

    st.markdown("### SMTP (Secure Email)")
    smtp_host = st.text_input("SMTP Host", value=st.secrets.get("smtp_host", ""))
    smtp_port = st.number_input("SMTP Port", value=587, min_value=1, max_value=65535)
    smtp_user = st.text_input("SMTP Username", value=st.secrets.get("smtp_user", ""))
    smtp_password = st.text_input(
        "SMTP Password",
        type="password",
        value=st.secrets.get("smtp_password", ""),
    )
    smtp_from = st.text_input("From Address", value="crashwise@localhost")
    smtp_to = st.text_input(
        "To Addresses (comma-separated)",
        value=st.secrets.get("smtp_to", ""),
    )

    st.markdown("### PGP Encryption")
    pgp_key = st.text_area(
        "PGP Public Key (armored)",
        value=st.secrets.get("pgp_public_key", ""),
        help="Optional: encrypt email notifications with PGP",
        height=150,
    )

    st.markdown("### Thresholds")
    min_cvss = st.slider(
        "Minimum CVSS to Notify",
        0.0,
        10.0,
        7.0,
        0.1,
        help="Only notify when verified crash CVSS >= this value",
    )

    if st.button("💾 Save Settings"):
        st.success("Settings saved to session state (not persisted to server).")
        st.session_state.notification_settings = {
            "webhook_url": webhook_url,
            "webhook_format": webhook_format,
            "smtp_host": smtp_host,
            "smtp_port": smtp_port,
            "smtp_user": smtp_user,
            "smtp_password": smtp_password,
            "smtp_from": smtp_from,
            "smtp_to": smtp_to,
            "pgp_public_key": pgp_key,
            "min_cvss_threshold": min_cvss,
        }


# ── Footer ───────────────────────────────────────────────────────────────────

st.sidebar.markdown("---")
st.sidebar.caption("Built with ❤️ by CrashWise Contributors")
