"""
Interactive Evidence Graph Page for U-15 Incident Reconstruction Platform.
Renders physics-driven PyVis graph and Plotly topology with node details,
centrality metrics, causal path discovery, and subgraph filtering.
"""
import streamlit as st
import streamlit.components.v1 as components
import json
import database.db as db
from graph.graph_builder import EvidenceGraphBuilder
from graph.graph_analyzer import EvidenceGraphAnalyzer
from app.components.graph_visualizer import render_pyvis_network, render_plotly_network

def render_graph_view_page():
    st.markdown("## 🕸️ Cross-Artifact Evidence Graph")
    st.caption("Interactive multi-entity forensic graph visualizing causal connections across Process, Registry, and Network domains.")

    case_id = st.session_state.get("current_case_id")
    if not case_id:
        st.warning("⚠️ Please select an active investigation case first.")
        return

    with st.expander("Graph rendering scope", expanded=True):
        scope_col1, scope_col2 = st.columns(2)
        with scope_col1:
            event_limit = st.slider(
                "Maximum events to render",
                min_value=100,
                max_value=400,
                value=250,
                step=50,
            )
        with scope_col2:
            event_order = st.radio(
                "Sample selection",
                ["Most correlated", "Most recent", "Earliest"],
                horizontal=True,
            )

    total_event_count = db.get_event_count(case_id)
    if event_order == "Most correlated":
        events = db.get_most_correlated_events(case_id, limit=event_limit)
        if not events:
            events = db.get_events(case_id, limit=event_limit, newest_first=True)
            events.reverse()
            st.caption("No correlated events are stored; showing the most recent event sample.")
    else:
        events = db.get_events(
            case_id,
            limit=event_limit,
            newest_first=(event_order == "Most recent"),
        )
        if event_order == "Most recent":
            events.reverse()
    relationships = db.get_relationships(
        case_id,
        event_ids=[event["event_id"] for event in events],
    )

    st.info(
        f"Displaying {len(events):,} of {total_event_count:,} case events. "
        "Only relationships with both endpoints in this sample are shown."
    )

    if not events:
        st.info("No events or relationships to graph. Please ingest evidence and execute correlation first.")
        return

    # Build graph
    builder = EvidenceGraphBuilder(case_id=case_id)
    raw_graph = builder.build_graph(events, relationships)
    analyzer = EvidenceGraphAnalyzer(raw_graph)
    stats = analyzer.get_summary_statistics()

    # Top KPI Metrics Row
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    with kpi1:
        st.metric("Total Graph Entities", stats["node_count"])
    with kpi2:
        st.metric("Directed Causal Edges", stats["edge_count"])
    with kpi3:
        st.metric("Incident Clusters", stats["connected_clusters"])
    with kpi4:
        st.metric("Graph Density", f"{stats['density']:.4f}")

    st.markdown("---")

    # Filter Sidebar / Expander
    with st.expander("🛠️ Graph Filters & Causal Path Discovery", expanded=False):
        f_col1, f_col2, f_col3 = st.columns(3)
        with f_col1:
            min_conf = st.slider("Minimum Edge Confidence", 0.0, 1.0, 0.0, 0.05)
        with f_col2:
            node_types = st.multiselect(
                "Filter Entity Types",
                ["process", "registry", "network", "file", "event"],
                default=["process", "registry", "network", "file", "event"]
            )
        with f_col3:
            cat_options = [
                "Directly observed",
                "Strongly supported",
                "Temporal association",
                "Unattributed",
                "Inferred",
                "Unknown",
            ]
            sel_cats = st.multiselect("Allowed Relationship Categories", cat_options, default=cat_options)

        # Path finder
        st.markdown("**🔍 Causal Path Finder (Attack Chain Reconstruction)**")
        node_query = st.text_input(
            "Search node IDs or labels",
            key=f"graph_node_search_{case_id}",
        ).strip().lower()
        matching_node_ids = []
        if node_query:
            matching_node_ids = [
                node_id
                for node_id, attributes in raw_graph.nodes(data=True)
                if node_query in str(node_id).lower()
                or node_query in str(attributes.get("label", "")).lower()
            ][:500]
            if not matching_node_ids:
                st.caption("No graph nodes match that search.")
        else:
            st.caption("Search for a node to enable causal path selection.")

        p_col1, p_col2, p_col3 = st.columns([3, 3, 2])
        with p_col1:
            src_node = st.selectbox(
                "Source Entity (Root / Process)",
                options=[""] + matching_node_ids,
                index=0,
            )
        with p_col2:
            tgt_node = st.selectbox(
                "Target Entity (Socket / Registry / Child)",
                options=[""] + matching_node_ids,
                index=0,
            )
        with p_col3:
            st.write("")
            st.write("")
            find_path_btn = st.button("Find Causal Paths")

        if find_path_btn and src_node and tgt_node:
            paths = analyzer.find_causal_paths(src_node, tgt_node, max_paths=100)
            if paths:
                st.success(
                    f"Returned up to {len(paths)} directed causal path(s) between "
                    f"`{src_node}` and `{tgt_node}` (maximum 100)."
                )
                for p_idx, p in enumerate(paths, 1):
                    st.markdown(f"**Path #{p_idx}:** `{' ➔ '.join(p)}`")
            else:
                st.warning(f"No direct causal path found between `{src_node}` and `{tgt_node}` within cutoff depth.")

    # Filter subgraph
    filtered_graph = analyzer.filter_subgraph(
        min_confidence=min_conf,
        allowed_categories=sel_cats,
        allowed_node_types=node_types
    )

    # Graph Rendering Tabs
    tab_vis, tab_plotly, tab_analytics = st.tabs(["Interactive Physics Graph (PyVis)", "Vector 2D Topology (Plotly)", "Topological Analytics"])

    with tab_vis:
        st.caption("💡 Drag nodes, zoom in/out, hover over entities for forensic timestamps and line numbers.")
        if filtered_graph.number_of_nodes() > 0:
            html_vis = render_pyvis_network(filtered_graph, height="650px")
            components.html(html_vis, height=670, scrolling=False)
        else:
            st.warning("No nodes match the selected filter criteria.")

    with tab_plotly:
        if filtered_graph.number_of_nodes() > 0:
            fig_plotly = render_plotly_network(filtered_graph)
            st.plotly_chart(fig_plotly, use_container_width=True)
        else:
            st.warning("No nodes to display in Plotly view.")

    with tab_analytics:
        st.markdown("#### 🎯 Central Forensic Pivot Entities")
        st.caption("Entities exhibiting highest degree centrality and structural fanout.")
        central = stats.get("central_nodes", [])
        if central:
            st.table(central)
        else:
            st.info("No central entities calculated.")

    st.markdown("---")
    # Export Graph Data
    st.markdown("### 💾 Export Evidence Graph")
    exp_col1, exp_col2 = st.columns([2, 4])
    with exp_col1:
        graph_json = json.dumps(builder.to_json_dict(), indent=2)
        st.download_button(
            label="📥 Download Graph JSON",
            data=graph_json,
            file_name=f"evidence_graph_{case_id}.json",
            mime="application/json"
        )
