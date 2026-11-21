
"""
Interactive Plotly Visualizations for U-15 Incident Reconstruction Platform.
Cybersecurity Dark Theme styled charts for:
- Evidence source distribution
- Correlation confidence distribution
- Baseline comparison (Precision, Recall, F1, FPR)
- Missing-evidence ablation study
- Temporal window sensitivity
- Process creation evidence graph
"""

import plotly.express as px
import plotly.graph_objects as go
from typing import Dict, Any, List

DARK_LAYOUT_TEMPLATE = dict(
    paper_bgcolor="#111827",
    plot_bgcolor="#1F2937",
    font=dict(color="#F3F4F6", family="Inter, system-ui, sans-serif"),
    margin=dict(l=40, r=40, t=50, b=40),
    legend=dict(
        bgcolor="rgba(31, 41, 55, 0.7)",
        bordercolor="#374151",
        borderwidth=1
    )
)


def create_source_distribution_chart(source_counts: Dict[str, int]) -> go.Figure:
    """Renders donut chart of evidence sources."""

    labels = list(source_counts.keys())
    values = list(source_counts.values())

    colors = ["#EF4444", "#F59E0B", "#3B82F6"]

    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=0.55,
        marker=dict(
            colors=colors,
            line=dict(color="#111827", width=2)
        ),
        textinfo="label+percent",
        hoverinfo="label+value+percent"
    )])

    fig.update_layout(
        title=dict(
            text="Evidence Source Distribution",
            font=dict(size=16, color="#60A5FA")
        ),
        **DARK_LAYOUT_TEMPLATE
    )

    return fig


def create_confidence_distribution_chart(confidences: List[float]) -> go.Figure:
    """Renders histogram of correlation confidence scores."""

    if not confidences:
        confidences = [0.0]

    fig = go.Figure(data=[go.Histogram(
        x=confidences,
        nbinsx=10,
        marker_color="#8B5CF6",
        opacity=0.85,
        marker=dict(line=dict(color="#111827", width=1))
    )])

    fig.update_layout(
        title=dict(
            text="Correlation Confidence Distribution",
            font=dict(size=16, color="#A78BFA")
        ),
        xaxis=dict(
            title="Confidence Score (0.0 - 1.0)",
            range=[0, 1.05],
            gridcolor="#374151"
        ),
        yaxis=dict(
            title="Relationship Count",
            gridcolor="#374151"
        ),
        **DARK_LAYOUT_TEMPLATE
    )

    return fig


def create_baseline_comparison_chart(
    comparison_data: List[Dict[str, Any]]
) -> go.Figure:
    """Renders grouped baseline comparison chart."""

    methods = [d["method"] for d in comparison_data]
    precisions = [d.get("precision", 0) for d in comparison_data]
    recalls = [d.get("recall", 0) for d in comparison_data]
    f1s = [d.get("f1_score", 0) for d in comparison_data]
    fprs = [d.get("false_positive_rate", 0) for d in comparison_data]

    fig = go.Figure()

    fig.add_trace(go.Bar(
        name="Precision",
        x=methods,
        y=precisions,
        marker_color="#10B981"
    ))

    fig.add_trace(go.Bar(
        name="Recall",
        x=methods,
        y=recalls,
        marker_color="#3B82F6"
    ))

    fig.add_trace(go.Bar(
        name="F1-Score",
        x=methods,
        y=f1s,
        marker_color="#8B5CF6"
    ))

    fig.add_trace(go.Bar(
        name="False Positive Rate",
        x=methods,
        y=fprs,
        marker_color="#EF4444"
    ))

    fig.update_layout(
        barmode="group",
        title=dict(
            text="Multi-Source Investigation Accuracy vs Baselines",
            font=dict(size=16, color="#60A5FA")
        ),
        yaxis=dict(
            title="Score (0.0 - 1.0)",
            range=[0, 1.1],
            gridcolor="#374151"
        ),
        xaxis=dict(gridcolor="#374151"),
        **DARK_LAYOUT_TEMPLATE
    )

    return fig


def create_ablation_chart(
    ablation_results: List[Dict[str, Any]]
) -> go.Figure:
    """Renders horizontal comparison of F1 and Recall."""

    configs = [r["configuration"] for r in ablation_results]
    f1s = [r["f1_score"] for r in ablation_results]
    recalls = [r["recall"] for r in ablation_results]

    fig = go.Figure()

    fig.add_trace(go.Bar(
        name="F1-Score",
        y=configs,
        x=f1s,
        orientation="h",
        marker_color="#8B5CF6"
    ))

    fig.add_trace(go.Bar(
        name="Recall",
        y=configs,
        x=recalls,
        orientation="h",
        marker_color="#3B82F6"
    ))

    fig.update_layout(
        barmode="group",
        title=dict(
            text="Ablation Study: Impact of Missing Evidence Sources",
            font=dict(size=16, color="#F59E0B")
        ),
        xaxis=dict(
            title="Score (0.0 - 1.0)",
            range=[0, 1.1],
            gridcolor="#374151"
        ),
        yaxis=dict(
            gridcolor="#374151",
            autorange="reversed"
        ),
        **DARK_LAYOUT_TEMPLATE
    )

    return fig


def create_sensitivity_chart(
    sensitivity_results: List[Dict[str, Any]]
) -> go.Figure:
    """Renders temporal window sensitivity charts."""

    fig = go.Figure()

    b3_data = [
        r for r in sensitivity_results
        if "Baseline 3" in r["method"]
    ]

    prop_data = [
        r for r in sensitivity_results
        if "Proposed" in r["method"]
    ]

    if b3_data:
        x_vals = [d["window_seconds"] for d in b3_data]

        fig.add_trace(go.Scatter(
            x=x_vals,
            y=[d["false_positive_rate"] for d in b3_data],
            mode="lines+markers",
            name="Baseline 3 - FPR",
            line=dict(color="#EF4444", dash="dash", width=3)
        ))

        fig.add_trace(go.Scatter(
            x=x_vals,
            y=[d["f1_score"] for d in b3_data],
            mode="lines+markers",
            name="Baseline 3 - F1-Score",
            line=dict(color="#F59E0B", width=2)
        ))

    if prop_data:
        x_vals = [d["window_seconds"] for d in prop_data]

        fig.add_trace(go.Scatter(
            x=x_vals,
            y=[d["false_positive_rate"] for d in prop_data],
            mode="lines+markers",
            name="Proposed Method - FPR",
            line=dict(color="#10B981", width=3)
        ))

        fig.add_trace(go.Scatter(
            x=x_vals,
            y=[d["f1_score"] for d in prop_data],
            mode="lines+markers",
            name="Proposed Method - F1-Score",
            line=dict(color="#3B82F6", width=3)
        ))

    fig.update_layout(
        title=dict(
            text="Sensitivity Analysis: Temporal Window vs Reconstruction Quality",
            font=dict(size=16, color="#10B981")
        ),
        xaxis=dict(
            title="Temporal Correlation Window (seconds)",
            gridcolor="#374151"
        ),
        yaxis=dict(
            title="Rate / Score",
            range=[0, 1.1],
            gridcolor="#374151"
        ),
        **DARK_LAYOUT_TEMPLATE
    )

    return fig


def create_process_tree_chart(
    events: List[Dict[str, Any]],
    relationships: List[Dict[str, Any]]
) -> go.Figure:
    """
    Visualizes validated SPAWNED relationships using a Sankey graph.

    Unique event IDs are used internally so repeated process names and PIDs
    do not collapse into ambiguous hierarchy nodes.

    All valid SPAWNED relationships are retained, including multiple-parent
    relationships. This graph represents recorded evidence relationships,
    not necessarily a uniquely established process lineage.
    """

    event_by_id = {
        event.get("event_id"): event
        for event in events
        if event.get("event_id")
        and event.get("source") == "process"
    }

    spawn_rels = [
        relationship
        for relationship in relationships
        if relationship.get("relationship_type") == "SPAWNED"
        and relationship.get("source_event_id") in event_by_id
        and relationship.get("target_event_id") in event_by_id
    ]

    fig = go.Figure()

    if not spawn_rels:
        fig.add_annotation(
            text="No validated process creation relationships available",
            x=0.5,
            y=0.5,
            xref="paper",
            yref="paper",
            showarrow=False,
            font=dict(size=15, color="#F3F4F6")
        )

        fig.update_layout(
            title="Process Creation Evidence Graph",
            **DARK_LAYOUT_TEMPLATE
        )

        return fig

    node_ids = list(dict.fromkeys(
        event_id
        for relationship in spawn_rels
        for event_id in (
            relationship["source_event_id"],
            relationship["target_event_id"]
        )
    ))

    node_index = {
        event_id: index
        for index, event_id in enumerate(node_ids)
    }

    labels = []
    hover_text = []

    for event_id in node_ids:
        event = event_by_id[event_id]

        name = event.get("process_name") or "Unknown Process"
        pid = event.get("pid", "Unknown")
        event_type = event.get("event_type", "Unknown")
        timestamp = event.get("timestamp") or "Unavailable"

        labels.append(f"{name}<br>PID: {pid}")

        hover_text.append(
            f"Process: {name}<br>"
            f"PID: {pid}<br>"
            f"Event type: {event_type}<br>"
            f"Event ID: {event_id}<br>"
            f"Timestamp: {timestamp}"
        )

    sources = [
        node_index[relationship["source_event_id"]]
        for relationship in spawn_rels
    ]

    targets = [
        node_index[relationship["target_event_id"]]
        for relationship in spawn_rels
    ]

    confidences = [
        relationship.get("confidence_score", 0) or 0
        for relationship in spawn_rels
    ]

    link_hover = [
        (
            "Relationship: SPAWNED<br>"
            f"Confidence: {confidence:.2f}<br>"
            f"Method: {relationship.get('correlation_method', 'Unknown')}<br>"
            f"Explanation: {relationship.get('explanation') or 'Not provided'}"
        )
        for relationship, confidence in zip(spawn_rels, confidences)
    ]

    fig.add_trace(go.Sankey(
        arrangement="snap",
        node=dict(
            pad=25,
            thickness=20,
            line=dict(color="#374151", width=0.8),
            label=labels,
            customdata=hover_text,
            hovertemplate="%{customdata}<extra></extra>",
            color="#3B82F6"
        ),
        link=dict(
            source=sources,
            target=targets,
            value=[1] * len(spawn_rels),
            customdata=link_hover,
            hovertemplate="%{customdata}<extra></extra>",
            color="rgba(59, 130, 246, 0.35)"
        )
    ))

    fig.update_layout(
        title=dict(
            text=(
                f"Process Creation Evidence Graph "
                f"({len(node_ids)} nodes, {len(spawn_rels)} relationships)"
            ),
            font=dict(size=16, color="#60A5FA")
        ),
        height=max(600, min(1100, len(node_ids) * 35)),
        **DARK_LAYOUT_TEMPLATE
    )

    return fig