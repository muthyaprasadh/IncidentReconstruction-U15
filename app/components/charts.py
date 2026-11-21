"""
Interactive Plotly Visualizations for U-15 Incident Reconstruction Platform.
Cybersecurity Dark Theme styled charts for:
- Evidence source distribution
- Correlation confidence distribution
- Baseline comparison (Precision, Recall, F1, FPR)
- Missing-evidence ablation study
- Temporal window sensitivity
- Process tree hierarchy
"""
import plotly.express as px
import plotly.graph_objects as go
from typing import Dict, Any, List

DARK_LAYOUT_TEMPLATE = dict(
    paper_bgcolor="#111827",
    plot_bgcolor="#1F2937",
    font=dict(color="#F3F4F6", family="Inter, system-ui, sans-serif"),
    margin=dict(l=40, r=40, t=50, b=40),
    legend=dict(bgcolor="rgba(31, 41, 55, 0.7)", bordercolor="#374151", borderwidth=1)
)

def create_source_distribution_chart(source_counts: Dict[str, int]) -> go.Figure:
    """Renders donut chart of evidence sources."""
    labels = list(source_counts.keys())
    values = list(source_counts.values())
    colors = ["#EF4444", "#F59E0B", "#3B82F6"]  # Process (red), Registry (amber), Network (blue)

    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=0.55,
        marker=dict(colors=colors, line=dict(color="#111827", width=2)),
        textinfo="label+percent",
        hoverinfo="label+value+percent"
    )])
    fig.update_layout(
        title=dict(text="Evidence Source Distribution", font=dict(size=16, color="#60A5FA")),
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
        title=dict(text="Correlation Confidence Distribution", font=dict(size=16, color="#A78BFA")),
        xaxis=dict(title="Confidence Score (0.0 - 1.0)", range=[0, 1.05], gridcolor="#374151"),
        yaxis=dict(title="Relationship Count", gridcolor="#374151"),
        **DARK_LAYOUT_TEMPLATE
    )
    return fig

def create_baseline_comparison_chart(comparison_data: List[Dict[str, Any]]) -> go.Figure:
    """
    Renders grouped bar chart comparing:
    Baseline 1 (Proc only), Baseline 2 (Proc+Reg), Baseline 3 (All, no graph), Proposed Method.
    """
    methods = [d["method"] for d in comparison_data]
    precisions = [d.get("precision", 0) for d in comparison_data]
    recalls = [d.get("recall", 0) for d in comparison_data]
    f1s = [d.get("f1_score", 0) for d in comparison_data]
    fprs = [d.get("false_positive_rate", 0) for d in comparison_data]

    fig = go.Figure()
    fig.add_trace(go.Bar(name="Precision", x=methods, y=precisions, marker_color="#10B981"))
    fig.add_trace(go.Bar(name="Recall", x=methods, y=recalls, marker_color="#3B82F6"))
    fig.add_trace(go.Bar(name="F1-Score", x=methods, y=f1s, marker_color="#8B5CF6"))
    fig.add_trace(go.Bar(name="False Positive Rate", x=methods, y=fprs, marker_color="#EF4444"))

    fig.update_layout(
        barmode="group",
        title=dict(text="Multi-Source Investigation Accuracy vs Baselines", font=dict(size=16, color="#60A5FA")),
        yaxis=dict(title="Score (0.0 - 1.0)", range=[0, 1.1], gridcolor="#374151"),
        xaxis=dict(gridcolor="#374151"),
        **DARK_LAYOUT_TEMPLATE
    )
    return fig

def create_ablation_chart(ablation_results: List[Dict[str, Any]]) -> go.Figure:
    """Renders horizontal comparison of F1 and Recall across ablated evidence configurations."""
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
        title=dict(text="Ablation Study: Impact of Missing Evidence Sources", font=dict(size=16, color="#F59E0B")),
        xaxis=dict(title="Score (0.0 - 1.0)", range=[0, 1.1], gridcolor="#374151"),
        yaxis=dict(gridcolor="#374151", autorange="reversed"),
        **DARK_LAYOUT_TEMPLATE
    )
    return fig

def create_sensitivity_chart(sensitivity_results: List[Dict[str, Any]]) -> go.Figure:
    """
    Renders line charts showing how temporal window (±1s, ±5s, ±10s, ±30s)
    affects F1-Score and False Positive Rate for Naive vs Proposed methods.
    """
    fig = go.Figure()

    # Split by method
    b3_data = [r for r in sensitivity_results if "Baseline 3" in r["method"]]
    prop_data = [r for r in sensitivity_results if "Proposed" in r["method"]]

    if b3_data:
        x_vals = [d["window_seconds"] for d in b3_data]
        fig.add_trace(go.Scatter(
            x=x_vals,
            y=[d["false_positive_rate"] for d in b3_data],
            mode="lines+markers",
            name="Baseline 3 - FPR (Spurious Associations)",
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
        title=dict(text="Sensitivity Analysis: Temporal Window vs Reconstruction Quality", font=dict(size=16, color="#10B981")),
        xaxis=dict(title="Temporal Correlation Window (seconds)", gridcolor="#374151"),
        yaxis=dict(title="Rate / Score", range=[0, 1.1], gridcolor="#374151"),
        **DARK_LAYOUT_TEMPLATE
    )
    return fig

def create_process_tree_chart(events: List[Dict[str, Any]], relationships: List[Dict[str, Any]]) -> go.Figure:
    """Visualizes parent-child process tree as a directed hierarchy."""
    proc_events = [e for e in events if e.get("source") == "process" and e.get("pid") is not None]
    proc_by_id = {e["event_id"]: e for e in proc_events}
    
    spawn_rels = [r for r in relationships if r.get("relationship_type") == "SPAWNED"]

    labels = []
    parents = []
    values = []

    # Map root nodes
    targets = {r["target_event_id"] for r in spawn_rels}
    for e in proc_events:
        eid = e["event_id"]
        label = f"{e.get('process_name')} ({e.get('pid')})"
        labels.append(label)
        values.append(1)

        # find if target of a spawn
        parent_rel = next((r for r in spawn_rels if r["target_event_id"] == eid), None)
        if parent_rel and parent_rel["source_event_id"] in proc_by_id:
            p_ev = proc_by_id[parent_rel["source_event_id"]]
            parents.append(f"{p_ev.get('process_name')} ({p_ev.get('pid')})")
        else:
            parents.append("")

    if not labels:
        labels = ["No Process Telemetry"]
        parents = [""]
        values = [1]

    fig = go.Figure(go.Treemap(
        labels=labels,
        parents=parents,
        values=values,
        marker=dict(colors=["#3B82F6", "#8B5CF6", "#10B981", "#F59E0B"] * (len(labels)//4 + 1))
    ))
    fig.update_layout(
        title=dict(text="Reconstructed Process Tree Hierarchy", font=dict(size=16, color="#60A5FA")),
        **DARK_LAYOUT_TEMPLATE
    )
    return fig
