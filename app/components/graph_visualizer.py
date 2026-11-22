import html
import math

import networkx as nx
import plotly.graph_objects as go

from pyvis.network import Network


def _safe_text(value):
    if value is None:
        return ""

    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(item) for item in value)

    return str(value)


def _safe_confidence(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _calculate_component_positions(graph):
    if graph.number_of_nodes() == 0:
        return {}

    undirected = graph.to_undirected()

    components = sorted(
        nx.connected_components(undirected),
        key=lambda component: (-len(component), min(map(str, component)))
    )

    component_count = len(components)
    columns = max(1, math.ceil(math.sqrt(component_count)))
    positions = {}

    cell_width = 650
    cell_height = 460

    for index, component in enumerate(components):
        nodes = sorted(component, key=str)
        subgraph = undirected.subgraph(nodes)

        row = index // columns
        column = index % columns

        center_x = column * cell_width
        center_y = row * cell_height

        if len(nodes) == 1:
            positions[nodes[0]] = (center_x, center_y)
            continue

        local_positions = nx.spring_layout(
            subgraph,
            seed=42,
            k=1.2 / math.sqrt(len(nodes)),
            iterations=80,
            scale=1.0
        )

        radius = min(190, max(55, 24 * math.sqrt(len(nodes))))

        for node, (x, y) in local_positions.items():
            positions[node] = (
                center_x + float(x) * radius,
                center_y + float(y) * radius
            )

    return positions


def render_pyvis_network(
    graph: nx.MultiDiGraph,
    height: str = "650px",
    show_labels: bool = False
) -> str:

    net = Network(
        height=height,
        width="100%",
        bgcolor="#111827",
        font_color="#F9FAFB",
        directed=True,
        neighborhood_highlight=True,
        select_menu=False,
        filter_menu=False,
        cdn_resources="in_line"
    )

    positions = _calculate_component_positions(graph)

    for node_id, data in graph.nodes(data=True):
        label = _safe_text(data.get("label", node_id))
        node_type = data.get("node_type", "event")
        color = data.get("color", "#9CA3AF")
        shape = data.get("shape", "dot")

        title = html.escape(
            _safe_text(data.get("title", label))
        )

        x, y = positions[node_id]

        size = {
            "process": 23,
            "registry": 20,
            "network": 19,
            "file": 19,
            "event": 15
        }.get(node_type, 18)

        net.add_node(
            str(node_id),
            label=label if show_labels else "",
            title=title,
            color=color,
            shape=shape,
            size=size,
            x=int(x),
            y=int(y),
            physics=True,
            fixed=False,
            borderWidth=2,
            shadow=False,
            font={
                "size": 12,
                "color": "#F9FAFB",
                "face": "Arial"
            }
        )

    for source, target, key, data in graph.edges(
        keys=True,
        data=True
    ):
        relationship_type = data.get(
            "relationship_type",
            "RELATED_TO"
        )

        category = data.get(
            "relationship_category",
            "Unknown"
        )

        confidence = _safe_confidence(
            data.get("confidence_score", 0)
        )

        color = data.get("color", "#6B7280")
        dashes = data.get("dashes", False)
        width = data.get("width", 1.5)

        method = _safe_text(
            data.get("correlation_method", "")
        )

        explanation = _safe_text(
            data.get("explanation", "")
        )

        identifiers = _safe_text(
            data.get("supporting_identifiers", [])
        )

        evidence_sources = _safe_text(
            data.get("evidence_sources", [])
        )

        title = (
            f"Relationship: {html.escape(str(relationship_type))}<br>"
            f"Category: {html.escape(str(category))}<br>"
            f"Confidence: {confidence:.3f}<br>"
            f"Method: {html.escape(method)}<br>"
            f"Explanation: {html.escape(explanation)}<br>"
            f"Supporting identifiers: {html.escape(identifiers)}<br>"
            f"Evidence sources: {html.escape(evidence_sources)}"
        )

        net.add_edge(
            str(source),
            str(target),
            label="",
            title=title,
            color=color,
            dashes=dashes,
            width=width,
            arrows="to"
        )

    net.set_options("""
    {
      "autoResize": true,
      "interaction": {
        "hover": true,
        "navigationButtons": true,
        "keyboard": {
          "enabled": true,
          "bindToWindow": false
        },
        "multiselect": true,
        "tooltipDelay": 150,
        "hideEdgesOnDrag": true,
        "hideNodesOnDrag": false,
        "zoomView": true,
        "dragView": true,
        "selectConnectedEdges": true
      },
      "physics": {
        "enabled": true,
        "solver": "barnesHut",
        "barnesHut": {
          "gravitationalConstant": -4500,
          "centralGravity": 0.25,
          "springLength": 120,
          "springConstant": 0.035,
          "damping": 0.85,
          "avoidOverlap": 0.5
        },
        "minVelocity": 0.75,
        "stabilization": {
          "enabled": true,
          "iterations": 250,
          "updateInterval": 50,
          "fit": true
        }
      },
      "layout": {
        "improvedLayout": false
      },
      "nodes": {
        "borderWidth": 2,
        "shadow": false,
        "font": {
          "size": 12,
          "color": "#F9FAFB"
        }
      },
      "edges": {
        "smooth": {
          "enabled": true,
          "type": "dynamic",
          "roundness": 0.25
        },
        "selectionWidth": 2,
        "hoverWidth": 2
      }
    }
    """)

    return net.generate_html(notebook=False)


def _edge_hover_text(data):
    relationship_type = _safe_text(
        data.get("relationship_type", "RELATED_TO")
    )

    category = _safe_text(
        data.get("relationship_category", "Unknown")
    )

    confidence = _safe_confidence(
        data.get("confidence_score", 0)
    )

    method = _safe_text(
        data.get("correlation_method", "")
    )

    explanation = _safe_text(
        data.get("explanation", "")
    )

    supporting_identifiers = _safe_text(
        data.get("supporting_identifiers", [])
    )

    evidence_sources = _safe_text(
        data.get("evidence_sources", [])
    )

    return (
        f"Relationship: {relationship_type}<br>"
        f"Category: {category}<br>"
        f"Confidence: {confidence:.3f}<br>"
        f"Method: {method}<br>"
        f"Explanation: {explanation}<br>"
        f"Supporting identifiers: {supporting_identifiers}<br>"
        f"Evidence sources: {evidence_sources}"
    )


def render_plotly_network(
    graph: nx.MultiDiGraph
) -> go.Figure:

    fig = go.Figure()

    if graph.number_of_nodes() == 0:
        fig.update_layout(
            title="Evidence Graph",
            paper_bgcolor="#111827",
            plot_bgcolor="#1F2937",
            font=dict(color="#F3F4F6")
        )
        return fig

    positions = _calculate_component_positions(graph)
    edge_groups = {}

    for source, target, key, data in graph.edges(
        keys=True,
        data=True
    ):
        edge_color = data.get("color", "#6B7280")
        edge_width = data.get("width", 1.5)

        edge_dash = (
            "dash" if data.get("dashes", False) else "solid"
        )

        group_key = (
            edge_color,
            edge_width,
            edge_dash
        )

        edge_groups.setdefault(
            group_key,
            {
                "x": [],
                "y": [],
                "text": []
            }
        )

        group = edge_groups[group_key]

        start = positions[source]
        end = positions[target]

        hover_text = _edge_hover_text(data)

        group["x"].extend([start[0], end[0], None])
        group["y"].extend([start[1], end[1], None])
        group["text"].extend([hover_text, hover_text, ""])

    for (
        edge_color,
        edge_width,
        edge_dash
    ), group in edge_groups.items():

        fig.add_trace(
            go.Scattergl(
                x=group["x"],
                y=group["y"],
                mode="lines",
                line=dict(
                    width=edge_width,
                    color=edge_color,
                    dash=edge_dash
                ),
                hoverinfo="text",
                text=group["text"],
                showlegend=False
            )
        )

    node_x = []
    node_y = []
    node_hover = []
    node_colors = []
    node_symbols = []
    node_sizes = []

    shape_to_symbol = {
        "box": "square",
        "diamond": "diamond",
        "dot": "circle",
        "triangle": "triangle-up",
        "ellipse": "circle"
    }

    for node_id, data in graph.nodes(data=True):
        x, y = positions[node_id]

        node_x.append(x)
        node_y.append(y)

        node_hover.append(
            _safe_text(
                data.get("title", data.get("label", node_id))
            )
        )

        node_colors.append(
            data.get("color", "#3B82F6")
        )

        node_symbols.append(
            shape_to_symbol.get(
                data.get("shape", "dot"),
                "circle"
            )
        )

        node_sizes.append(
            25 if data.get("node_type") != "event" else 16
        )

    fig.add_trace(
        go.Scattergl(
            x=node_x,
            y=node_y,
            mode="markers",
            hoverinfo="text",
            hovertext=node_hover,
            marker=dict(
                color=node_colors,
                size=node_sizes,
                symbol=node_symbols,
                line_width=1,
                line_color="#111827"
            ),
            showlegend=False
        )
    )

    fig.update_layout(
        title=dict(
            text="Cross-Artifact Evidence Graph",
            font=dict(size=16, color="#60A5FA")
        ),
        showlegend=False,
        hovermode="closest",
        dragmode="pan",
        margin=dict(
            b=20,
            l=20,
            r=20,
            t=40
        ),
        xaxis=dict(
            showgrid=False,
            zeroline=False,
            showticklabels=False
        ),
        yaxis=dict(
            showgrid=False,
            zeroline=False,
            showticklabels=False,
            scaleanchor="x",
            scaleratio=1
        ),
        paper_bgcolor="#111827",
        plot_bgcolor="#1F2937",
        font=dict(color="#F3F4F6")
    )

    return fig