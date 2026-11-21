"""
Forensic Dashboard Module for U-15 Incident Reconstruction Platform.
Displays high-level operational statistics, evidence distributions, anomaly counts,
and recent investigation cases in a cybersecurity dark-theme layout.
"""
import streamlit as st
import database.db as db
from app.components.charts import (
    create_source_distribution_chart,
    create_confidence_distribution_chart
)
from datetime import datetime

def render_dashboard():
    st.markdown("## 🛡️ Forensic Investigation Command Center")
    st.caption("U-15 | Cross-Artifact Incident Reconstruction from Process, Registry and Network Evidence")

    # Fetch global telemetry statistics
    stats = db.get_dashboard_stats()

    # Top metric KPI cards
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Investigations", stats["total_cases"], help="Active and completed forensic cases")
    with col2:
        st.metric("Evidence Files", stats["total_files"], help="Raw Procmon, Registry, and Network evidence files")
    with col3:
        total_events = (
            stats["total_process_events"] +
            stats["total_registry_events"] +
            stats["total_network_events"]
        )
        st.metric("Normalized Events", f"{total_events:,}", help="Parsed and standardized forensic records")
    with col4:
        st.metric("Correlated Links", f"{stats['total_relationships']:,}", help="Cross-artifact causal and provenance relationships")

    # Second row of metric cards
    col5, col6, col7, col8 = st.columns(4)
    with col5:
        st.metric("Process Events", f"{stats['total_process_events']:,}", delta="Sysinternals")
    with col6:
        st.metric("Registry Events", f"{stats['total_registry_events']:,}", delta="Hive / Reg")
    with col7:
        st.metric("Network Events", f"{stats['total_network_events']:,}", delta="Wireshark / Socket")
    with col8:
        st.metric("Flagged Anomalies", stats["total_anomalies"], delta_color="inverse", help="Suspicious cross-source patterns (persistence, C2, child processes)")

    st.markdown("---")

    # Visualizations Row
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        dist_fig = create_source_distribution_chart(stats["source_distribution"])
        st.plotly_chart(dist_fig, use_container_width=True)

    with chart_col2:
        # Load sample confidences across all cases for distribution view
        current_case = st.session_state.get("current_case_id")
        if current_case:
            rels = db.get_relationships(current_case)
            confs = [r.get("confidence_score", 0.5) for r in rels]
        else:
            confs = []
        conf_fig = create_confidence_distribution_chart(confs)
        st.plotly_chart(conf_fig, use_container_width=True)

    st.markdown("### 📋 Recent Forensic Investigations")
    recent = stats.get("recent_cases", [])
    if recent:
        for c in recent:
            with st.container():
                c_col1, c_col2, c_col3, c_col4 = st.columns([2, 3, 2, 2])
                with c_col1:
                    st.markdown(f"**`{c['case_id']}`**")
                with c_col2:
                    st.write(c["name"])
                with c_col3:
                    st.caption(f"Created: {c['created_at'][:10]}")
                with c_col4:
                    if st.button("Open Case", key=f"open_{c['case_id']}"):
                        st.session_state["current_case_id"] = c["case_id"]
                        st.session_state["current_case_name"] = c["name"]
                        st.rerun()
    else:
        st.info("No investigations created yet. Navigate to 'Case Management' or load a controlled experiment to begin.")
