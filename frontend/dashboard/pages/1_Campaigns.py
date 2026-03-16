"""
Campaigns Page - View and manage fuzz campaigns.

Displays:
- Active and historical campaigns
- Campaign status and progress
- Real-time updates via Temporal queries
"""

import asyncio
import os
import streamlit as st
from datetime import datetime
import pandas as pd
from typing import Dict, Any, List

# Import utilities
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.temporal_client import TemporalDashboardClient, run_async
from utils.minio_client import MinIODashboardClient

# Configuration
TEMPORAL_ADDRESS = os.getenv("TEMPORAL_ADDRESS", "temporal:7233")
TEMPORAL_NAMESPACE = os.getenv("TEMPORAL_NAMESPACE", "default")

# Page config
st.set_page_config(
    page_title="Campaigns - CrashWise",
    page_icon="🎯",
    layout="wide",
)

st.title("🎯 Fuzz Campaigns")
st.markdown("View and manage continuous fuzzing campaigns")

# Sidebar info
with st.sidebar:
    st.markdown("---")
    st.markdown("### Connection Status")
    st.markdown(f"**Temporal:** `{TEMPORAL_ADDRESS}`")
    st.markdown(f"**Namespace:** `{TEMPORAL_NAMESPACE}`")

# Filter controls
col_filter1, col_filter2, col_filter3 = st.columns([2, 2, 1])

with col_filter1:
    status_filter = st.selectbox(
        "Status",
        options=["All", "Running", "Completed", "Failed"],
        index=0,
        help="Filter campaigns by status",
    )

with col_filter2:
    limit = st.slider(
        "Max Results",
        min_value=5,
        max_value=100,
        value=20,
        help="Maximum number of campaigns to display",
    )

with col_filter3:
    if st.button("🔄 Refresh", use_container_width=True, type="primary"):
        st.rerun()

st.markdown("---")

# Session state for campaigns
if "campaigns" not in st.session_state:
    st.session_state.campaigns = []


# Fetch campaigns from Temporal
async def fetch_campaigns(status_filter: str, limit: int) -> List[Dict[str, Any]]:
    """Fetch campaigns from Temporal."""
    client = TemporalDashboardClient()
    async with client:
        campaigns = await client.list_campaigns(
            status_filter=status_filter,
            limit=limit,
        )
    return campaigns


# Main content
try:
    with st.spinner("Fetching campaigns from Temporal..."):
        campaigns = run_async(fetch_campaigns(status_filter, limit))
        st.session_state.campaigns = campaigns

    if campaigns:
        # Convert to DataFrame
        df = pd.DataFrame(campaigns)

        # Format start time
        df["started"] = df["start_time"].apply(
            lambda x: x.strftime("%Y-%m-%d %H:%M:%S") if x else "-"
        )

        # Format close time
        df["finished"] = df["close_time"].apply(
            lambda x: x.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(x) and x else "—"
        )

        # Status emoji mapping
        status_emoji = {
            "running": "🟢",
            "completed": "✅",
            "failed": "❌",
            "terminated": "⏹️",
            "canceled": "🚫",
        }
        df["status_display"] = df["status"].apply(
            lambda s: f"{status_emoji.get(s, '⚪')} {s.upper()}"
        )

        # Select view mode
        view_mode = st.radio(
            "View Mode",
            options=["Table", "Cards"],
            horizontal=True,
        )

        if view_mode == "Table":
            # Display as DataFrame
            st.dataframe(
                df[
                    ["workflow_id", "status_display", "started", "finished", "duration"]
                ],
                column_config={
                    "workflow_id": st.column_config.TextColumn(
                        "Campaign ID",
                        width="medium",
                        help="Unique workflow identifier",
                    ),
                    "status_display": st.column_config.TextColumn(
                        "Status",
                        width="small",
                    ),
                    "started": st.column_config.TextColumn(
                        "Started",
                        width="medium",
                    ),
                    "finished": st.column_config.TextColumn(
                        "Finished",
                        width="medium",
                    ),
                    "duration": st.column_config.TextColumn(
                        "Duration",
                        width="small",
                    ),
                },
                use_container_width=True,
                hide_index=True,
            )
        else:
            # Display as cards
            for idx, row in df.iterrows():
                with st.container(border=True):
                    col1, col2, col3 = st.columns([2, 1, 1])

                    with col1:
                        st.markdown(f"**{row['workflow_id']}**")
                        st.markdown(f"📊 {row['duration']}")

                    with col2:
                        st.markdown(f"{row['status_display']}")

                    with col3:
                        if st.button("📊 Details", key=f"detail_{idx}"):
                            st.session_state.selected_campaign = row["workflow_id"]
                            st.switch_page("pages/2_Crashes.py")

        # Summary stats
        st.markdown("---")
        st.subheader("📊 Summary")

        col1, col2, col3, col4 = st.columns(4)

        status_counts = df["status"].value_counts()

        with col1:
            running = status_counts.get("running", 0)
            st.metric("🟢 Running", running, delta=None)

        with col2:
            completed = status_counts.get("completed", 0)
            st.metric("✅ Completed", completed, delta=None)

        with col3:
            failed = status_counts.get("failed", 0)
            st.metric("❌ Failed", failed, delta=None)

        with col4:
            st.metric("📋 Total", len(campaigns), delta=None)

        # Export options
        st.markdown("---")
        col_exp1, col_exp2 = st.columns(2)

        with col_exp1:
            csv = df[
                ["workflow_id", "status", "started", "finished", "duration"]
            ].to_csv(index=False)
            st.download_button(
                "📥 Download CSV",
                csv,
                "campaigns.csv",
                "text/csv",
                use_container_width=True,
            )

        with col_exp2:
            if st.button("➕ Start New Campaign", use_container_width=True):
                st.switch_page("pages/3_Start_New.py")

        # Coverage History Section
        st.markdown("---")
        st.subheader("📈 Coverage Progress")

        # Select campaign for coverage view
        if campaigns:
            selected_for_coverage = st.selectbox(
                "Select campaign to view coverage",
                options=[c["workflow_id"] for c in campaigns],
                format_func=lambda x: x[:20] + "..." if len(x) > 20 else x,
                key="coverage_campaign_select",
            )

            if selected_for_coverage:
                try:
                    with st.spinner("Fetching coverage history..."):
                        selected_campaign = next(
                            (
                                c
                                for c in campaigns
                                if c["workflow_id"] == selected_for_coverage
                            ),
                            None,
                        )

                        # Check if coverage history is available
                        # Note: coverage_history comes from workflow results
                        coverage_history = (
                            selected_campaign.get("coverage_history", [])
                            if selected_campaign
                            else []
                        )

                        if coverage_history:
                            import pandas as pd

                            # Convert to DataFrame
                            df_coverage = pd.DataFrame(coverage_history)

                            if (
                                "edges" in df_coverage.columns
                                and "time" in df_coverage.columns
                            ):
                                # Calculate coverage percentage if total known
                                if "total_edges" in df_coverage.columns:
                                    total = (
                                        df_coverage["total_edges"].iloc[0]
                                        if df_coverage["total_edges"].iloc[0] > 0
                                        else 1
                                    )
                                    df_coverage["coverage_percent"] = (
                                        df_coverage["edges"] / total * 100
                                    )

                                # Display metrics
                                col_cov1, col_cov2, col_cov3 = st.columns(3)

                                with col_cov1:
                                    latest_edges = (
                                        df_coverage["edges"].iloc[-1]
                                        if len(df_coverage) > 0
                                        else 0
                                    )
                                    st.metric("Current Edges", int(latest_edges))

                                with col_cov2:
                                    if "crashes" in df_coverage.columns:
                                        latest_crashes = (
                                            df_coverage["crashes"].iloc[-1]
                                            if len(df_coverage) > 0
                                            else 0
                                        )
                                        st.metric("Crashes Found", int(latest_crashes))

                                with col_cov3:
                                    if "execs" in df_coverage.columns:
                                        latest_execs = (
                                            df_coverage["execs"].iloc[-1]
                                            if len(df_coverage) > 0
                                            else 0
                                        )
                                        st.metric(
                                            "Executions", f"{int(latest_execs):,}"
                                        )

                                # Line chart
                                st.line_chart(
                                    df_coverage.set_index("time")[["edges"]],
                                    use_container_width=True,
                                )
                        else:
                            st.info("No coverage history available for this campaign")
                            st.markdown("""
                            **Coverage history is only available for completed campaigns with monitoring enabled.**
                            
                            Run campaigns with the auto_fuzz_campaign workflow to track coverage progress.
                            """)
                except Exception as e:
                    st.warning(f"Could not load coverage data: {e}")

        # Stall Warning Section
        if campaigns:
            stall_campaigns = [
                c
                for c in campaigns
                if c.get("stall_events") and len(c.get("stall_events", [])) > 0
            ]

            if stall_campaigns:
                st.warning(f"⚠️ {len(stall_campaigns)} campaign(s) have coverage stalls")
                for c in stall_campaigns[:3]:  # Show first 3
                    with st.expander(f"🔴 {c['workflow_id'][:20]}...", expanded=False):
                        st.markdown(f"**Stall Count:** {c.get('stall_count', 0)}")
                        st.markdown(f"**Max Edges:** {c.get('max_edges', 0)}")
                        actions = c.get("stall_actions_taken", [])
                        if actions:
                            st.markdown(f"**Actions Taken:** {', '.join(actions)}")

    else:
        st.info("📭 No campaigns found matching the criteria.")
        st.markdown("""
        **Start a new campaign:**
        
        ```
        cw fuzz start ./binary --seeds ./seeds --duration 2h
        ```
        
        Or use the [Start New](/Start_New) page.
        """)

        if st.button("➕ Start New Campaign", type="primary"):
            st.switch_page("pages/3_Start_New.py")

except Exception as e:
    st.error(f"❌ Failed to fetch campaigns")

    with st.expander("🔍 Error Details", expanded=False):
        st.code(str(e), language="text")

    st.markdown("""
    **Troubleshooting:**
    1. Ensure Temporal is running: `docker compose up -d temporal`
    2. Check connection: `TEMPORAL_ADDRESS={TEMPORAL_ADDRESS}`
    3. Verify namespace: `TEMPORAL_NAMESPACE={TEMPORAL_NAMESPACE}`
    4. Check Temporal UI: [http://localhost:8080](http://localhost:8080)
    """)

# Footer
st.markdown("---")
st.markdown(
    f"""
<small>
Last updated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} |
<a href="/">Home</a> |
<a href="/Crashes">Crashes</a> |
<a href="/Start_New">Start New</a>
</small>
""",
    unsafe_allow_html=True,
)
