"""
Interactive Incident Timeline Component for Streamlit.
Renders reconstructed forensic timeline with category badges, cross-artifact links,
provenance inspection, and full search/filter capabilities.
"""
import streamlit as st
from typing import List, Dict, Any

SOURCE_BADGES = {
    "process": ("#EF4444", "PROCESS"),
    "registry": ("#F59E0B", "REGISTRY"),
    "network": ("#3B82F6", "NETWORK")
}

CATEGORY_BADGES = {
    "Directly observed": "#10B981",    # Emerald
    "Strongly supported": "#3B82F6",   # Blue
    "Temporal association": "#F59E0B", # Amber
    "Inferred": "#8B5CF6",            # Purple
    "Unknown": "#6B7280"              # Gray
}

def render_timeline_view(timeline_entries: List[Dict[str, Any]]):
    """Renders chronological cards for all timeline entries."""
    if not timeline_entries:
        st.info("No events available in the reconstructed timeline.")
        return

    # Filter controls
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        search_query = st.text_input("🔍 Search timeline events", placeholder="Filter by process, IP, key, or path...").strip().lower()
    with col2:
        source_filter = st.multiselect("Evidence Sources", options=["process", "registry", "network"], default=["process", "registry", "network"])
    with col3:
        only_linked = st.checkbox("Only show correlated events", value=False)

    filtered = []
    for entry in timeline_entries:
        if entry["source"] not in source_filter:
            continue
        if only_linked and entry.get("link_count", 0) == 0:
            continue
        if search_query:
            haystack = f"{entry.get('process_name')} {entry.get('registry_key')} {entry.get('network_destination')} {entry.get('file_path')} {entry.get('description')}".lower()
            if search_query not in haystack:
                continue
        filtered.append(entry)

    st.caption(f"Showing **{len(filtered)}** of **{len(timeline_entries)}** reconstructed events")

    # Render entries
    for idx, entry in enumerate(filtered):
        src_color, src_label = SOURCE_BADGES.get(entry["source"], ("#6B7280", "EVENT"))
        
        with st.container():
            st.markdown(
                f"""
                <div style="background-color: #1F2937; border-left: 4px solid {src_color}; border-radius: 6px; padding: 12px; margin-bottom: 12px; border: 1px solid #374151;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                        <span style="font-family: monospace; color: #9CA3AF; font-size: 0.85rem;">⏱️ {entry['display_time']}</span>
                        <span style="background-color: {src_color}22; color: {src_color}; padding: 2px 8px; border-radius: 4px; font-weight: 600; font-size: 0.75rem; border: 1px solid {src_color}55;">
                            {src_label}
                        </span>
                    </div>
                    <div style="color: #F3F4F6; font-size: 0.95rem; font-weight: 500; margin-bottom: 6px;">
                        {entry['description']}
                    </div>
                    <div style="display: flex; gap: 15px; font-size: 0.8rem; color: #9CA3AF; margin-bottom: 6px;">
                        <span><b>Entity:</b> {entry.get('process_name') or 'N/A'} (PID: {entry.get('pid') or 'N/A'})</span>
                        <span><b>Type:</b> {entry.get('event_type')}</span>
                        <span><b>Provenance:</b> {entry.get('evidence_provenance')}</span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            # Expandable related links and raw metadata
            has_links = entry.get("link_count", 0) > 0
            label = f"🔗 Cross-Artifact Links ({entry.get('link_count')}) & Provenance Details" if has_links else "📄 Provenance Details"
            with st.expander(label, expanded=False):
                if has_links:
                    st.markdown("**Correlated Relationships:**")
                    for link in entry.get("related_links", []):
                        cat_color = CATEGORY_BADGES.get(link["category"], "#6B7280")
                        st.markdown(
                            f"""
                            - <span style="background-color:{cat_color}22; color:{cat_color}; padding:2px 6px; border-radius:3px; font-weight:bold; font-size:0.75rem;">
                                {link['category']}
                              </span>
                              **{link['type']}** (Confidence: `{link['confidence']:.2f}`): {link['explanation']}
                            """,
                            unsafe_allow_html=True
                        )
                st.markdown("**Raw Event Metadata:**")
                st.json(entry.get("raw_metadata", {}))
