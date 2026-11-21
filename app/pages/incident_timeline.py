"""
Incident Timeline & Reconstruction Page for U-15 Incident Reconstruction Platform.
Presents the automatically reconstructed chronological incident timeline,
narrative generation, process hierarchy tree, and PDF/CSV export.
"""
import streamlit as st
import pandas as pd
from pathlib import Path
import database.db as db
from reconstruction.timeline_generator import TimelineGenerator
from reconstruction.incident_narrative import IncidentNarrativeGenerator
from reconstruction.report_generator import ForensicReportGenerator
from app.components.timeline import render_timeline_view
from app.components.charts import create_process_tree_chart
from graph.graph_builder import EvidenceGraphBuilder
from graph.graph_analyzer import EvidenceGraphAnalyzer

def render_incident_timeline_page():
    st.markdown("## ⏱️ Automatically Reconstructed Incident Timeline")
    st.caption("Chronological reconstruction of cross-artifact activities with empirical observations and provenance support.")

    case_id = st.session_state.get("current_case_id")
    if not case_id:
        st.warning("⚠️ Please select an active investigation case first.")
        return

    case_info = db.get_case_by_id(case_id) or {"case_id": case_id, "name": "Active Investigation"}
    events = db.get_events(case_id)
    relationships = db.get_relationships(case_id)

    if not events:
        st.info("No events to reconstruct. Ingest evidence and run correlation first.")
        return

    # Generate timeline and narrative
    timeline_gen = TimelineGenerator(events, relationships)
    timeline_entries = timeline_gen.generate_timeline()

    narrative_gen = IncidentNarrativeGenerator(timeline_entries, relationships)
    narrative_data = narrative_gen.generate_narrative()

    # 1. Executive Incident Narrative Section
    st.markdown("### 📖 Chronological Incident Narrative")
    with st.container():
        st.markdown(
            f"""
            <div style="background-color: #111827; border: 1px solid #374151; border-left: 5px solid #3B82F6; border-radius: 6px; padding: 16px; margin-bottom: 20px; font-family: monospace; font-size: 0.95rem; line-height: 1.6; color: #E5E7EB; white-space: pre-wrap;">
{narrative_data.get('chronological_story')}
            </div>
            """,
            unsafe_allow_html=True
        )
        st.caption(f"🛡️ *{narrative_data.get('forensic_disclaimer')}*")

    st.markdown("---")

    # 2. Activity Phase Distribution KPI Cards
    phases = narrative_data.get("phases_summary", {})
    p1, p2, p3, p4 = st.columns(4)
    with p1:
        st.metric("Process Launches", phases.get("Process Execution", 0))
    with p2:
        st.metric("File Actions", phases.get("File Activity", 0))
    with p3:
        st.metric("Registry Modifications", phases.get("Registry Activity", 0))
    with p4:
        st.metric("Network Sockets", phases.get("Network Activity", 0))

    st.markdown("---")

    # 3. Interactive Timeline and Process Tree Tabs
    tab_cards, tab_tree, tab_table = st.tabs(["Interactive Timeline Cards", "Process Tree Hierarchy", "Tabular Event Data"])

    with tab_cards:
        render_timeline_view(timeline_entries)

    with tab_tree:
        tree_fig = create_process_tree_chart(events, relationships)
        st.plotly_chart(tree_fig, use_container_width=True)

    with tab_table:
        df_rows = []
        for entry in timeline_entries:
            df_rows.append({
                "Timestamp (UTC)": entry["timestamp"],
                "Source": entry["source"].upper(),
                "Event Type": entry["event_type"],
                "Process": f"{entry.get('process_name') or ''} ({entry.get('pid') or ''})",
                "Summary": entry["description"],
                "Related Links": entry["link_count"],
                "Evidence Reference": entry["evidence_provenance"]
            })
        st.dataframe(pd.DataFrame(df_rows), use_container_width=True, height=400)

    st.markdown("---")

    # 4. Export & Report Generation
    st.markdown("### 📄 Investigation Report & Forensic Exports")
    
    exp_col1, exp_col2, exp_col3 = st.columns(3)

    with exp_col1:
        # Export CSV
        csv_df = pd.DataFrame(df_rows)
        csv_data = csv_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="📥 Export Reconstructed Timeline (CSV)",
            data=csv_data,
            file_name=f"timeline_{case_id}.csv",
            mime="text/csv"
        )

    with exp_col2:
        # Generate PDF Report Button
        if st.button("📑 Generate Official PDF Investigation Report", type="primary"):
            with st.spinner("Compiling research investigation PDF report with ReportLab..."):
                evidence_files = db.get_evidence_files(case_id)
                builder = EvidenceGraphBuilder(case_id)
                graph = builder.build_graph(events, relationships)
                analyzer = EvidenceGraphAnalyzer(graph)
                graph_stats = analyzer.get_summary_statistics()

                eval_runs = db.get_evaluation_runs(case_id)
                eval_data = []
                for er in eval_runs:
                    m = er.get("metrics", {})
                    eval_data.append({
                        "method": er.get("method"),
                        "precision": m.get("precision", 0),
                        "recall": m.get("recall", 0),
                        "f1_score": m.get("f1_score", 0),
                        "false_positive_rate": m.get("false_positive_rate", 0)
                    })

                pdf_path = ForensicReportGenerator.generate_pdf_report(
                    case_info=case_info,
                    evidence_files=evidence_files,
                    timeline_entries=timeline_entries,
                    relationships=relationships,
                    narrative_data=narrative_data,
                    evaluation_data=eval_data if eval_data else None,
                    graph_stats=graph_stats
                )
                st.session_state["generated_pdf_path"] = str(pdf_path)
                st.success(f"PDF Report generated: {pdf_path.name}")

        if "generated_pdf_path" in st.session_state:
            p = Path(st.session_state["generated_pdf_path"])
            if p.exists():
                with open(p, "rb") as pdf_f:
                    st.download_button(
                        label=f"⬇️ Download {p.name}",
                        data=pdf_f.read(),
                        file_name=p.name,
                        mime="application/pdf"
                    )
