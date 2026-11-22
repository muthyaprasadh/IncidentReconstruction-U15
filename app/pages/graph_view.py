import hashlib
import json

import streamlit as st
import streamlit.components.v1 as components
import database.db as db

from graph.graph_builder import EvidenceGraphBuilder
from graph.graph_analyzer import EvidenceGraphAnalyzer
from app.components.graph_visualizer import (
    render_pyvis_network,
    render_plotly_network
)


def _create_graph_fingerprint(case_id, events, relationships):
    payload = {
        "case_id": case_id,
        "events": events,
        "relationships": relationships
    }

    serialized = json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=False,
        default=str
    )

    return hashlib.sha256(
        serialized.encode("utf-8")
    ).hexdigest()


def _get_cached_graph(case_id, events, relationships):
    fingerprint = _create_graph_fingerprint(
        case_id,
        events,
        relationships
    )

    cache_key = "evidence_graph_cache"

    cached = st.session_state.get(cache_key)

    if cached and cached.get("fingerprint") == fingerprint:
        return (
            cached["graph"],
            cached["graph_json"],
            cached["statistics"]
        )

    builder = EvidenceGraphBuilder(case_id=case_id)

    graph = builder.build_graph(
        events,
        relationships
    )

    graph_json = builder.to_json_dict()

    analyzer = EvidenceGraphAnalyzer(graph)

    statistics = analyzer.get_summary_statistics()

    st.session_state[cache_key] = {
        "fingerprint": fingerprint,
        "graph": graph,
        "graph_json": graph_json,
        "statistics": statistics
    }

    return graph, graph_json, statistics


def render_graph_view_page():
    st.markdown("## Cross-Artifact Evidence Graph")

    st.caption(
        "Interactive forensic graph showing process, registry, file and network "
        "evidence with explicitly distinguished observations and correlations."
    )

    case_id = st.session_state.get("current_case_id")

    if not case_id:
        st.warning("Please select an active investigation case first.")
        return

    with st.expander("Graph rendering scope", expanded=True):
        scope_col1, scope_col2 = st.columns(2)

        with scope_col1:
            event_limit = st.slider(
                "Maximum events to render",
                min_value=100,
                max_value=400,
                value=100,
                step=50,
                key=f"graph_event_limit_{case_id}"
            )

        with scope_col2:
            event_order = st.radio(
                "Sample selection",
                ["Most correlated", "Most recent", "Earliest"],
                horizontal=True,
                key=f"graph_event_order_{case_id}"
            )

    total_event_count = db.get_event_count(case_id)

    if event_order == "Most correlated":
        events = db.get_most_correlated_events(
            case_id,
            limit=event_limit
        )

        if not events:
            events = db.get_events(
                case_id,
                limit=event_limit,
                newest_first=True
            )

            events.reverse()

            st.caption(
                "No correlated events were returned. "
                "Showing the most recent event sample."
            )

    else:
        events = db.get_events(
            case_id,
            limit=event_limit,
            newest_first=(event_order == "Most recent")
        )

        if event_order == "Most recent":
            events.reverse()

    if not events:
        st.info("No events are available for this case.")
        return

    event_ids = [
        event["event_id"]
        for event in events
        if event.get("event_id")
    ]

    relationships = db.get_relationships(
        case_id,
        event_ids=event_ids
    )

    st.info(
        f"Displaying {len(events):,} of {total_event_count:,} case events. "
        "Only relationships with both endpoints in the selected sample are included."
    )

    with st.spinner("Preparing evidence graph..."):
        graph, graph_json_dict, stats = _get_cached_graph(
            case_id,
            events,
            relationships
        )

    analyzer = EvidenceGraphAnalyzer(graph)

    st.markdown("### Graph Overview")

    kpi1, kpi2, kpi3, kpi4 = st.columns(4)

    kpi1.metric(
        "Graph Entities",
        f"{stats['node_count']:,}"
    )

    kpi2.metric(
        "Total Graph Edges",
        f"{stats['edge_count']:,}"
    )

    kpi3.metric(
        "Cross-Event Relationships",
        f"{stats['cross_event_relationship_count']:,}"
    )

    kpi4.metric(
        "Supported Causal Links",
        f"{stats['causal_relationship_count']:,}"
    )

    detail_col1, detail_col2, detail_col3 = st.columns(3)

    detail_col1.metric(
        "Observation Edges",
        f"{stats['observation_edge_count']:,}"
    )

    detail_col2.metric(
        "Connected Clusters",
        f"{stats['connected_clusters']:,}"
    )

    detail_col3.metric(
        "Graph Density",
        f"{stats['density']:.4f}"
    )

    st.markdown("---")

    with st.expander("Graph Filters and Path Discovery", expanded=False):
        filter_col1, filter_col2, filter_col3 = st.columns(3)

        with filter_col1:
            min_confidence = st.slider(
                "Minimum Edge Confidence",
                min_value=0.0,
                max_value=1.0,
                value=0.0,
                step=0.05,
                key=f"graph_confidence_{case_id}"
            )

        with filter_col2:
            all_node_types = [
                "process",
                "registry",
                "network",
                "file",
                "event"
            ]

            node_types = st.multiselect(
                "Filter Entity Types",
                all_node_types,
                default=all_node_types,
                key=f"graph_node_types_{case_id}"
            )

        with filter_col3:
            category_options = [
                "Directly observed",
                "Strongly supported",
                "Temporal association",
                "Unattributed",
                "Inferred",
                "Unknown"
            ]

            selected_categories = st.multiselect(
                "Relationship Categories",
                category_options,
                default=category_options,
                key=f"graph_categories_{case_id}"
            )

        st.markdown("#### Evidence Path Discovery")

        node_query = st.text_input(
            "Search node IDs or labels",
            key=f"graph_node_search_{case_id}"
        ).strip().lower()

        matching_node_ids = []

        if node_query:
            matching_node_ids = [
                node_id
                for node_id, attributes in graph.nodes(data=True)
                if (
                    node_query in str(node_id).lower()
                    or node_query in str(
                        attributes.get("label", "")
                    ).lower()
                )
            ][:500]

            if not matching_node_ids:
                st.caption("No graph nodes match the search.")
        else:
            st.caption("Search for a node to enable path selection.")

        path_col1, path_col2 = st.columns(2)

        with path_col1:
            source_node = st.selectbox(
                "Source Entity",
                options=[""] + matching_node_ids,
                key=f"graph_source_node_{case_id}"
            )

        with path_col2:
            target_node = st.selectbox(
                "Target Entity",
                options=[""] + matching_node_ids,
                key=f"graph_target_node_{case_id}"
            )

        path_col1, path_col2 = st.columns(2)

        with path_col1:
            causal_path_button = st.button(
                "Find Supported Causal Paths",
                key=f"graph_causal_path_{case_id}",
                width="stretch"
            )

        with path_col2:
            evidence_path_button = st.button(
                "Find Evidence Paths",
                key=f"graph_evidence_path_{case_id}",
                width="stretch"
            )

        if causal_path_button or evidence_path_button:
            if not source_node or not target_node:
                st.warning("Select both source and target entities.")

            elif causal_path_button:
                paths = analyzer.find_causal_paths(
                    source_node,
                    target_node,
                    max_paths=100
                )

                if paths:
                    st.success(
                        f"Found {len(paths)} supported causal path(s)."
                    )

                    for index, path in enumerate(paths, 1):
                        st.markdown(
                            f"**Causal Path {index}:** "
                            f"`{' → '.join(path)}`"
                        )
                else:
                    st.info(
                        "No supported SPAWNED causal path was found "
                        "between the selected entities."
                    )

            else:
                paths = analyzer.find_evidence_paths(
                    source_node,
                    target_node,
                    max_paths=100
                )

                if paths:
                    st.success(
                        f"Found {len(paths)} directed evidence path(s)."
                    )

                    st.caption(
                        "Evidence paths can include observations and associations. "
                        "They do not independently establish causation."
                    )

                    for index, path in enumerate(paths, 1):
                        st.markdown(
                            f"**Evidence Path {index}:** "
                            f"`{' → '.join(path)}`"
                        )
                else:
                    st.info(
                        "No directed evidence path was found "
                        "between the selected entities."
                    )

    filtered_graph = analyzer.filter_subgraph(
        min_confidence=min_confidence,
        allowed_categories=selected_categories,
        allowed_node_types=node_types
    )

    st.markdown("---")
    st.markdown("### Evidence Graph Visualization")

    selected_view = st.radio(
        "Select visualization",
        [
            "Interactive Physics Graph",
            "2D Evidence Topology",
            "Graph Analytics"
        ],
        horizontal=True,
        key=f"graph_view_selector_{case_id}"
    )

    st.caption(
        f"Showing {filtered_graph.number_of_nodes():,} entities and "
        f"{filtered_graph.number_of_edges():,} edges after filtering."
    )

    if selected_view == "Interactive Physics Graph":
        if filtered_graph.number_of_nodes() > 0:
            st.caption(
                "Hover over nodes to inspect forensic metadata. "
                "Labels are hidden by default to reduce visual clutter."
            )

            html_visualization = render_pyvis_network(
                filtered_graph,
                height="650px",
                show_labels=False
            )

            components.html(
                html_visualization,
                height=670,
                scrolling=False
            )
        else:
            st.warning("No nodes match the selected filters.")

    elif selected_view == "2D Evidence Topology":
        if filtered_graph.number_of_nodes() > 0:
            with st.spinner("Rendering 2D evidence topology..."):
                figure = render_plotly_network(filtered_graph)

            st.plotly_chart(
                figure,
                width="stretch",
                key=f"graph_plotly_{case_id}"
            )
        else:
            st.warning("No nodes are available for the Plotly view.")

    elif selected_view == "Graph Analytics":
        st.markdown("#### Relationship Category Distribution")

        category_counts = stats.get(
            "relationship_category_counts",
            {}
        )

        if category_counts:
            st.dataframe(
                [
                    {
                        "Relationship Category": category,
                        "Count": count
                    }
                    for category, count in category_counts.items()
                ],
                width="stretch",
                hide_index=True
            )
        else:
            st.info("No relationship categories are available.")

        st.markdown("#### Relationship Type Distribution")

        type_counts = stats.get(
            "relationship_type_counts",
            {}
        )

        if type_counts:
            st.dataframe(
                [
                    {
                        "Relationship Type": relationship_type,
                        "Count": count
                    }
                    for relationship_type, count in type_counts.items()
                ],
                width="stretch",
                hide_index=True
            )
        else:
            st.info("No relationship types are available.")

        st.markdown("#### Central Forensic Entities")

        central_nodes = stats.get("central_nodes", [])

        if central_nodes:
            st.dataframe(
                central_nodes,
                width="stretch",
                hide_index=True
            )
        else:
            st.info("No central entities were calculated.")

        cluster_sizes = stats.get("cluster_sizes", [])

        if cluster_sizes:
            st.markdown("#### Largest Connected Clusters")
            st.write(cluster_sizes)

    st.markdown("---")
    st.markdown("### Export Evidence Graph")

    graph_json = json.dumps(
        graph_json_dict,
        indent=2,
        ensure_ascii=False
    )

    st.download_button(
        label="Download Graph JSON",
        data=graph_json,
        file_name=f"evidence_graph_{case_id}.json",
        mime="application/json",
        key=f"graph_json_download_{case_id}",
        width="stretch"
    )

    st.caption(
        "The JSON export preserves graph nodes, observations, relationship "
        "categories, confidence scores and evidence provenance."
    )