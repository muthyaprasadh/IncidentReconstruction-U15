"""
Evidence Analysis & Correlation Page for U-15 Incident Reconstruction Platform.
Enables browsing normalized events and executing the cross-artifact correlation engine.
"""
import streamlit as st
import pandas as pd
import database.db as db
from database.models import NormalizedEvent
from correlation.correlation_engine import CorrelationEngine
from config.settings import DEFAULT_TIME_WINDOW_SECONDS

CATEGORY_COLORS = {
    "Directly observed": "#10B981",
    "Strongly supported": "#3B82F6",
    "Temporal association": "#F59E0B",
    "Inferred": "#8B5CF6",
    "Unknown": "#6B7280"
}

def render_evidence_analysis_page():
    st.markdown("## 🔬 Evidence Normalization & Cross-Artifact Correlation")
    st.caption("Inspect standardized event schemas and execute explainable cross-artifact correlation.")

    case_id = st.session_state.get("current_case_id")
    if not case_id:
        st.warning("⚠️ Please select an active investigation case first.")
        return

    st.info(f"Active Case: **`{case_id}`**")

    # Ingested events statistics
    raw_events = db.get_events(case_id)
    if not raw_events:
        st.info("No normalized events in this case yet. Please upload evidence in 'Evidence Upload' or generate a lab scenario.")
        return

    proc_count = sum(1 for e in raw_events if e["source"] == "process")
    reg_count = sum(1 for e in raw_events if e["source"] == "registry")
    net_count = sum(1 for e in raw_events if e["source"] == "network")

    m_col1, m_col2, m_col3, m_col4 = st.columns(4)
    with m_col1:
        st.metric("Total Ingested Events", len(raw_events))
    with m_col2:
        st.metric("Process Events", proc_count)
    with m_col3:
        st.metric("Registry Events", reg_count)
    with m_col4:
        st.metric("Network Events", net_count)

    st.markdown("---")
    
    # 1. Execution Section: Run Correlation Engine
    st.markdown("### ⚙️ Cross-Artifact Correlation Engine")
    st.caption("Rule-based correlation engine adhering to forensic provenance, PID reuse guards, and 5-tuple socket matching.")

    c_col1, c_col2 = st.columns([3, 1])
    with c_col1:
        temp_window = st.slider(
            "Temporal Correlation Window (± seconds)",
            min_value=1.0,
            max_value=30.0,
            value=float(DEFAULT_TIME_WINDOW_SECONDS),
            step=1.0,
            help="Maximum allowable time difference for cross-artifact temporal proximity attribution."
        )
    with c_col2:
        st.write("")
        st.write("")
        run_btn = st.button("🚀 Run Correlation Engine", type="primary")

    if run_btn:
        with st.spinner("Correlating process, registry, and network evidence..."):
            events_obj = [NormalizedEvent(**{k: v for k, v in d.items() if k in NormalizedEvent.__annotations__}) for d in raw_events]
            engine = CorrelationEngine(case_id=case_id, temporal_window=temp_window)
            rels = engine.run(events_obj, save_to_db=True)
            st.success(f"Correlation executed successfully: **{len(rels)}** unique cross-artifact relationships identified.")
            st.rerun()

    # View Existing Relationships
    current_rels = db.get_relationships(case_id)
    if current_rels:
        st.markdown(f"#### 🔗 Correlated Relationships ({len(current_rels)})")
        
        # Filter controls
        f_col1, f_col2 = st.columns([2, 2])
        with f_col1:
            cats = list({r["relationship_category"] for r in current_rels})
            cat_filter = st.multiselect("Filter by Relationship Category", options=cats, default=cats)
        with f_col2:
            r_types = list({r["relationship_type"] for r in current_rels})
            type_filter = st.multiselect("Filter by Relationship Type", options=r_types, default=r_types)

        filtered_rels = [
            r for r in current_rels
            if r["relationship_category"] in cat_filter and r["relationship_type"] in type_filter
        ]

        # Display relationships cards
        for r in filtered_rels:
            cat = r["relationship_category"]
            c_color = CATEGORY_COLORS.get(cat, "#6B7280")
            conf = float(r.get("confidence_score", 0))

            with st.container():
                st.markdown(
                    f"""
                    <div style="background-color: #1F2937; border-left: 4px solid {c_color}; border-radius: 6px; padding: 12px; margin-bottom: 10px; border: 1px solid #374151;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                            <span style="font-weight: bold; color: #F3F4F6; font-size: 0.95rem;">
                                <code>{r['source_event_id']}</code> ➔ <code>{r['target_event_id']}</code>
                            </span>
                            <div>
                                <span style="background-color: {c_color}22; color: {c_color}; border: 1px solid {c_color}55; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; margin-right: 8px;">
                                    {cat.upper()}
                                </span>
                                <span style="background-color: #374151; color: #9CA3AF; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-family: monospace;">
                                    Conf: {conf:.2f}
                                </span>
                            </div>
                        </div>
                        <div style="color: #60A5FA; font-weight: 600; font-size: 0.85rem; margin-bottom: 4px;">
                            Relationship Type: {r['relationship_type']} ({r.get('correlation_method')})
                        </div>
                        <div style="color: #E5E7EB; font-size: 0.9rem; margin-bottom: 6px;">
                            {r.get('explanation')}
                        </div>
                        <div style="font-size: 0.75rem; color: #9CA3AF;">
                            Supporting Identifiers: <code>{', '.join(r.get('supporting_identifiers', [])) or 'None'}</code>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
    else:
        st.warning("No relationships currently generated for this case. Click 'Run Correlation Engine' above.")

    st.markdown("---")
    # 2. Browse Normalized Events Table
    st.markdown("### 📋 Normalized Forensic Events Browser")
    
    col_src_filter, col_search = st.columns([1, 2])
    with col_src_filter:
        view_source = st.selectbox("Filter Source", ["All Sources", "Process", "Registry", "Network"])
    with col_search:
        ev_search = st.text_input("Filter events", placeholder="Search by PID, process, key, IP...").strip().lower()

    filtered_evs = raw_events
    if view_source != "All Sources":
        filtered_evs = [e for e in filtered_evs if e["source"] == view_source.lower()]
    if ev_search:
        filtered_evs = [
            e for e in filtered_evs
            if ev_search in f"{e.get('process_name')} {e.get('pid')} {e.get('registry_key')} {e.get('dst_ip')} {e.get('event_type')}".lower()
        ]

    # Convert to DataFrame for interactive display
    display_rows = []
    for e in filtered_evs:
        display_rows.append({
            "Event ID": e["event_id"],
            "Timestamp": e["timestamp"],
            "Source": e["source"].upper(),
            "Type": e["event_type"],
            "Process": f"{e.get('process_name') or ''} ({e.get('pid') or ''})",
            "Target / Key / Socket": e.get("registry_key") or (f"{e.get('dst_ip')}:{e.get('dst_port')}" if e.get("dst_ip") else e.get("file_path", "")),
            "Provenance": f"{e.get('evidence_file')} ({e.get('evidence_reference')})"
        })

    st.dataframe(pd.DataFrame(display_rows), use_container_width=True, height=350)
