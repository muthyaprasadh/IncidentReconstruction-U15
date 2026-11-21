"""
Interactive Evidence Graph Visualizer for U-15 Incident Reconstruction.
Renders physics-driven NetworkX MultiDiGraph in Streamlit using PyVis (Vis.js)
and Plotly fallback with node shapes, edge styles, tooltips, and forensic metadata.
"""
from pathlib import Path
import tempfile
import networkx as nx
from pyvis.network import Network
import plotly.graph_objects as go
from typing import Dict, Any, Optional
import streamlit as st

def render_pyvis_network(graph: nx.MultiDiGraph, height: str = "600px") -> str:
    """
    Generates interactive HTML for Vis.js canvas with custom styling,
    physics options, search, zoom, and node/edge inspection tooltips.
    """
    net = Network(height=height, width="100%", bgcolor="#111827", font_color="#F9FAFB", directed=True)
    
    # Configure physics for forensic layout readability
    net.barnes_hut(
        gravity=-8000,
        central_gravity=0.3,
        spring_length=120,
        spring_strength=0.05,
        damping=0.85,
        overlap=0
    )

    # Add Nodes
    for n, data in graph.nodes(data=True):
        label = data.get("label", str(n))
        node_type = data.get("node_type", "event")
        color = data.get("color", "#9CA3AF")
        shape = data.get("shape", "dot")
        title = data.get("title", label)
        
        # Scale sizes
        size = 25 if node_type != "event" else 18

        net.add_node(
            n,
            label=label,
            title=title,
            color=color,
            shape=shape,
            size=size,
            borderWidth=2,
            shadow=True
        )

    # Add Edges
    for u, v, key, data in graph.edges(keys=True, data=True):
        rel_type = data.get("relationship_type", "RELATED_TO")
        color = data.get("color", "#6B7280")
        dashes = data.get("dashes", False)
        width = data.get("width", 2)
        title = data.get("title", rel_type)

        net.add_edge(
            u, v,
            label=rel_type,
            title=title,
            color=color,
            dashes=dashes,
            width=width,
            arrows="to"
        )

    with tempfile.TemporaryDirectory() as temp_dir:
        output_path = Path(temp_dir) / "evidence_graph.html"
        net.save_graph(str(output_path))
        return output_path.read_text(encoding="utf-8")

def render_plotly_network(graph: nx.MultiDiGraph) -> go.Figure:
    """Renders 2D Plotly network graph visualization."""
    pos = nx.spring_layout(graph, seed=42, k=0.8)

    edge_x = []
    edge_y = []
    edge_text = []

    for u, v, data in graph.edges(data=True):
        if u in pos and v in pos:
            x0, y0 = pos[u]
            x1, y1 = pos[v]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
            edge_hover = "<br>".join([
                str(data.get("relationship_type", "RELATED_TO")),
                str(data.get("relationship_category", "Unknown")),
                f"Confidence: {data.get('confidence_score', 0):.2f}",
                str(data.get("correlation_method", "")),
                str(data.get("explanation", "")),
                ", ".join(data.get("supporting_identifiers", [])),
            ])
            edge_text.extend([edge_hover, edge_hover, ""])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=1.5, color="#6B7280"),
        hoverinfo="text",
        text=edge_text,
        mode="lines"
    )

    node_x = []
    node_y = []
    node_text = []
    node_colors = []
    node_symbols = []

    shape_to_symbol = {
        "box": "square",
        "diamond": "diamond",
        "dot": "circle",
        "triangle": "triangle-up",
        "ellipse": "circle"
    }

    for n, data in graph.nodes(data=True):
        if n in pos:
            x, y = pos[n]
            node_x.append(x)
            node_y.append(y)
            node_text.append(data.get("title", str(n)))
            node_colors.append(data.get("color", "#3B82F6"))
            shape = data.get("shape", "dot")
            node_symbols.append(shape_to_symbol.get(shape, "circle"))

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode="markers+text",
        hoverinfo="text",
        text=[graph.nodes[n].get("label", "") for n in graph.nodes() if n in pos],
        textposition="top center",
        hovertext=node_text,
        marker=dict(
            color=node_colors,
            size=20,
            symbol=node_symbols,
            line_width=2,
            line_color="#111827"
        )
    )

    fig = go.Figure(data=[edge_trace, node_trace],
        layout=go.Layout(
            title=dict(text="Evidence Multi-DiGraph (Plotly Canvas)", font=dict(size=16, color="#60A5FA")),
            showlegend=False,
            hovermode="closest",
            margin=dict(b=20, l=20, r=20, t=40),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            paper_bgcolor="#111827",
            plot_bgcolor="#1F2937",
            font=dict(color="#F3F4F6")
        )
    )
    return fig
