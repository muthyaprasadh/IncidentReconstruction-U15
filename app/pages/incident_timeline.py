import csv
import hashlib
import io
from pathlib import Path

import pandas as pd
import streamlit as st

import database.db as db
from reconstruction.timeline_generator import TimelineGenerator
from reconstruction.incident_narrative import IncidentNarrativeGenerator
from reconstruction.report_generator import ForensicReportGenerator
from app.components.timeline import DETAILS_STATE_KEY, render_timeline_view
from app.components.charts import create_process_tree_chart
from graph.graph_builder import EvidenceGraphBuilder
from graph.graph_analyzer import EvidenceGraphAnalyzer

PAGE_SIZE = 100
EXPORT_BATCH_SIZE = 1000
SOURCE_OPTIONS = {
    "All Sources": None,
    "Process": "process",
    "Registry": "registry",
    "Network": "network",
}
SOURCE_WIDGET_KEY = "timeline_source_filter_v3"
SOURCE_SELECTION_STATE_KEY = "timeline_source_selection"


def _remember_timeline_source():
    st.session_state[SOURCE_SELECTION_STATE_KEY] = st.session_state[
        SOURCE_WIDGET_KEY
    ]


def _timeline_to_rows(entries):
    return [
        {
            "Timestamp (UTC)": entry.get("timestamp", ""),
            "Source": (entry.get("source") or "").upper(),
            "Event Type": entry.get("event_type", ""),
            "Process": f"{entry.get('process_name') or ''} ({entry.get('pid') or ''})",
            "Summary": entry.get("description", ""),
            "Related Links": entry.get("link_count", 0),
            "Evidence Reference": entry.get("evidence_provenance", ""),
        }
        for entry in entries
    ]


def _generate_page_timeline(case_id, source, search, page):
    events = db.get_events(
        case_id=case_id,
        source=source,
        search=search,
        limit=PAGE_SIZE,
        offset=page * PAGE_SIZE,
    )
    if not events:
        return [], [], []

    event_ids = [event["event_id"] for event in events]
    relationships = db.get_relationships(
        case_id=case_id,
        event_ids=event_ids,
        include_external=True,
    )
    entries = TimelineGenerator(events, relationships).generate_timeline()
    return events, relationships, entries


def _generate_full_case_csv(case_id, source=None, search=None):
    output = io.StringIO()
    writer = None
    offset = 0
    exported_count = 0
    fieldnames = [
        "Timestamp (UTC)", "Source", "Event Type", "Process",
        "Summary", "Related Links", "Evidence Reference",
    ]

    while True:
        events = db.get_events(
            case_id=case_id,
            source=source,
            search=search,
            limit=EXPORT_BATCH_SIZE,
            offset=offset,
        )
        if not events:
            break

        event_ids = [event["event_id"] for event in events]
        relationships = db.get_relationships(
            case_id=case_id,
            event_ids=event_ids,
            include_external=True,
        )
        entries = TimelineGenerator(events, relationships).generate_timeline()
        rows = _timeline_to_rows(entries)

        if writer is None:
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()

        writer.writerows(rows)
        exported_count += len(rows)
        offset += EXPORT_BATCH_SIZE

    if writer is None:
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

    return output.getvalue().encode("utf-8-sig"), exported_count


def _generate_full_narrative(case_id):
    events = db.get_events(case_id)
    if not events:
        return None
    relationships = db.get_relationships(case_id)
    entries = TimelineGenerator(events, relationships).generate_timeline()
    return IncidentNarrativeGenerator(entries, relationships).generate_narrative()


def _generate_process_tree(case_id):
    events = db.get_events(case_id)
    if not events:
        return None
    relationships = db.get_relationships(case_id)
    return create_process_tree_chart(events, relationships)


def _generate_pdf(case_id, case_info):
    events = db.get_events(case_id)
    if not events:
        return None

    relationships = db.get_relationships(case_id)
    timeline_entries = TimelineGenerator(events, relationships).generate_timeline()
    narrative_data = IncidentNarrativeGenerator(
        timeline_entries, relationships
    ).generate_narrative()

    builder = EvidenceGraphBuilder(case_id)
    graph = builder.build_graph(events, relationships)
    graph_stats = EvidenceGraphAnalyzer(graph).get_summary_statistics()

    eval_data = []
    for run in db.get_evaluation_runs(case_id):
        metrics = run.get("metrics", {})
        eval_data.append({
            "method": run.get("method"),
            "precision": metrics.get("precision", 0),
            "recall": metrics.get("recall", 0),
            "f1_score": metrics.get("f1_score", 0),
            "false_positive_rate": metrics.get("false_positive_rate", 0),
        })

    return ForensicReportGenerator.generate_pdf_report(
        case_info=case_info,
        evidence_files=db.get_evidence_files(case_id),
        timeline_entries=timeline_entries,
        relationships=relationships,
        narrative_data=narrative_data,
        evaluation_data=eval_data or None,
        graph_stats=graph_stats,
    )


def render_incident_timeline_page():
    st.markdown("## Automatically Reconstructed Incident Timeline")
    st.caption(
        "Chronological reconstruction of cross-artifact activities "
        "with empirical observations and provenance support."
    )

    case_id = st.session_state.get("current_case_id")
    if not case_id:
        st.warning("Please select an active investigation case first.")
        return

    case_info = db.get_case_by_id(case_id) or {
        "case_id": case_id,
        "name": "Active Investigation",
    }
    st.markdown(f"**Investigation:** `{case_id}`")

    st.markdown("### Timeline Filters")
    filter_col1, filter_col2 = st.columns([1, 2])
    with filter_col1:
        if SOURCE_SELECTION_STATE_KEY not in st.session_state:
            st.session_state[SOURCE_SELECTION_STATE_KEY] = "All Sources"

        saved_source_label = st.session_state[SOURCE_SELECTION_STATE_KEY]
        if (
            not isinstance(saved_source_label, str)
            or saved_source_label not in SOURCE_OPTIONS
        ):
            st.error(
                f"Invalid saved evidence source selection: "
                f"{saved_source_label!r}. Select a valid source after correcting "
                "the saved session state."
            )
            return

        if SOURCE_WIDGET_KEY in st.session_state:
            widget_source_label = st.session_state[SOURCE_WIDGET_KEY]
            if (
                not isinstance(widget_source_label, str)
                or widget_source_label not in SOURCE_OPTIONS
            ):
                st.error(
                    f"Invalid evidence source selection: "
                    f"{widget_source_label!r}. Select a valid source."
                )
                return
        else:
            st.session_state[SOURCE_WIDGET_KEY] = saved_source_label

        source_label = st.selectbox(
            "Evidence Source",
            options=list(SOURCE_OPTIONS.keys()),
            key=SOURCE_WIDGET_KEY,
            on_change=_remember_timeline_source,
        )
        if not isinstance(source_label, str) or source_label not in SOURCE_OPTIONS:
            st.error(
                f"Invalid evidence source selection: {source_label!r}. "
                "Select a valid source."
            )
            return
        st.session_state[SOURCE_SELECTION_STATE_KEY] = source_label
        selected_source = SOURCE_OPTIONS[source_label]
        st.caption(
            f"Active source filter: **{source_label}** "
            f"(database value: `{selected_source or 'all'}`)"
        )

    with filter_col2:
        search_query = st.text_input(
            "Search Events",
            placeholder="Search process, PID, registry key, IP, event ID, file path...",
            key="timeline_search_filter",
        ).strip()

    current_filter = (case_id, selected_source, search_query)
    if st.session_state.get("timeline_previous_filter_v3") != current_filter:
        st.session_state["timeline_page"] = 0
        st.session_state["timeline_previous_filter_v3"] = current_filter
        st.session_state.pop(DETAILS_STATE_KEY, None)

    total_events = db.get_event_count(
        case_id=case_id,
        source=selected_source,
        search=search_query,
    )

    with st.expander("Filter diagnostics", expanded=False):
        st.write("Selected dropdown value:", source_label)
        st.write("Source passed to database:", repr(selected_source))
        st.write("Filtered event count:", total_events)
        st.write(
            "Unfiltered event count:",
            db.get_event_count(case_id=case_id),
        )
        st.write(
            "Direct count for selected source:",
            db.get_event_count(case_id=case_id, source=selected_source),
        )

    if total_events == 0:
        st.info("No events match the selected filters. Try another source or search term.")
        return

    total_pages = max(1, (total_events + PAGE_SIZE - 1) // PAGE_SIZE)
    current_page = min(
        max(st.session_state.get("timeline_page", 0), 0),
        total_pages - 1,
    )
    st.session_state["timeline_page"] = current_page

    metric_col1, metric_col2, metric_col3 = st.columns(3)
    metric_col1.metric("Matching Events", f"{total_events:,}")
    metric_col2.metric("Events Per Page", PAGE_SIZE)
    metric_col3.metric("Total Pages", f"{total_pages:,}")

    events, relationships, timeline_entries = _generate_page_timeline(
        case_id, selected_source, search_query, current_page
    )
    if not events:
        st.info("No events available on this page.")
        return

    st.markdown("### Timeline Navigation")
    nav_col1, nav_col2, nav_col3 = st.columns([1, 2, 1])
    with nav_col1:
        if st.button("Previous", disabled=current_page == 0, use_container_width=True):
            st.session_state["timeline_page"] -= 1
            st.rerun()
    with nav_col2:
        st.markdown(
            f"<div style='text-align:center;padding:8px'>Page "
            f"<b>{current_page + 1}</b> of <b>{total_pages}</b></div>",
            unsafe_allow_html=True,
        )
    with nav_col3:
        if st.button(
            "Next",
            disabled=current_page >= total_pages - 1,
            use_container_width=True,
        ):
            st.session_state["timeline_page"] += 1
            st.rerun()

    st.markdown("### Chronological Incident Narrative")
    narrative_key = f"timeline_narrative_{case_id}"
    if st.button("Generate Full Case Narrative", key="generate_full_narrative"):
        with st.spinner("Reconstructing the full case narrative. Large cases may take some time..."):
            st.session_state[narrative_key] = _generate_full_narrative(case_id)

    narrative_data = st.session_state.get(narrative_key)
    if narrative_data:
        st.text_area(
            "Full Case Chronology",
            value=narrative_data.get("chronological_story", ""),
            height=350,
            disabled=True,
        )
        st.caption(narrative_data.get("forensic_disclaimer", ""))
        phases = narrative_data.get("phases_summary", {})
        phase_cols = st.columns(4)
        phase_labels = [
            ("Process Launches", "Process Execution"),
            ("File Actions", "File Activity"),
            ("Registry Modifications", "Registry Activity"),
            ("Network Sockets", "Network Activity"),
        ]
        for col, (label, key) in zip(phase_cols, phase_labels):
            col.metric(label, phases.get(key, 0))
        findings = narrative_data.get("correlated_findings", [])
        if findings:
            st.markdown("#### High-Confidence Correlated Findings")
            st.dataframe(pd.DataFrame(findings), use_container_width=True, hide_index=True)
    else:
        st.info(
            "The full-case narrative has not been generated. "
            "Generate it when you need the complete chronology."
        )

    st.markdown("### Investigation Report & Forensic Exports")
    export_col1, export_col2 = st.columns(2)

    with export_col1:
        st.markdown("#### Full-Case CSV Export")
        st.caption("Exports every event matching the current source and search filters.")
        filter_signature = f"{selected_source or 'all'}|{search_query}"
        filter_hash = hashlib.sha256(
            filter_signature.encode("utf-8")
        ).hexdigest()[:16]
        csv_data_key = f"timeline_csv_{case_id}_{filter_hash}"
        csv_count_key = f"timeline_csv_count_{case_id}_{filter_hash}"

        if st.button("Prepare Full-Case CSV", key="prepare_full_csv"):
            with st.spinner("Generating full-case timeline CSV in batches..."):
                csv_data, exported_count = _generate_full_case_csv(
                    case_id, selected_source, search_query
                )
                expected_count = db.get_event_count(
                    case_id=case_id,
                    source=selected_source,
                    search=search_query,
                )
                if exported_count != expected_count:
                    st.error(
                        f"CSV validation failed: exported {exported_count:,} "
                        f"records, but {expected_count:,} events match the filters. "
                        "The CSV has not been made available for download."
                    )
                    st.session_state.pop(csv_data_key, None)
                    st.session_state.pop(csv_count_key, None)
                else:
                    st.session_state[csv_data_key] = csv_data
                    st.session_state[csv_count_key] = exported_count

        csv_data = st.session_state.get(csv_data_key)
        if csv_data:
            exported_count = st.session_state.get(csv_count_key, 0)
            st.success(f"Prepared and validated {exported_count:,} timeline records.")
            st.download_button(
                "Download Full-Case Timeline CSV",
                data=csv_data,
                file_name=f"timeline_{case_id}.csv",
                mime="text/csv",
                key=f"download_full_timeline_csv_{filter_hash}",
            )

    with export_col2:
        st.markdown("#### PDF Investigation Report")
        st.caption("Generates the existing executive investigation report.")
        if st.button(
            "Generate PDF Investigation Report",
            type="primary",
            key="generate_timeline_pdf",
        ):
            with st.spinner("Generating the PDF investigation report..."):
                try:
                    pdf_path = _generate_pdf(case_id, case_info)
                    if pdf_path:
                        st.session_state[f"generated_pdf_path_{case_id}"] = str(pdf_path)
                        st.success(f"PDF generated: {pdf_path.name}")
                    else:
                        st.warning("No events available for PDF generation.")
                except Exception as exc:
                    st.error(f"PDF generation failed: {exc}")

        pdf_path_value = st.session_state.get(f"generated_pdf_path_{case_id}")
        if pdf_path_value:
            pdf_path = Path(pdf_path_value)
            if pdf_path.exists():
                with open(pdf_path, "rb") as pdf_file:
                    st.download_button(
                        "Download PDF Investigation Report",
                        data=pdf_file.read(),
                        file_name=pdf_path.name,
                        mime="application/pdf",
                        key="download_timeline_pdf",
                    )

    st.markdown("### Timeline Views")
    selected_view = st.radio(
        "Select View",
        ["Interactive Timeline", "Process Tree", "Tabular Event Data"],
        horizontal=True,
        key="timeline_selected_view",
    )

    if selected_view == "Interactive Timeline":
        st.caption(f"Displaying {len(timeline_entries)} events from the current page.")
        render_timeline_view(timeline_entries)
    elif selected_view == "Process Tree":
        st.warning(
            "The process tree uses the full case event and relationship data. "
            "Large cases may take some time to process."
        )
        if st.button("Generate Full Case Process Tree", key="generate_process_tree"):
            with st.spinner("Building the complete process hierarchy..."):
                st.session_state[f"process_tree_{case_id}"] = _generate_process_tree(case_id)
        tree_fig = st.session_state.get(f"process_tree_{case_id}")
        if tree_fig is not None:
            st.plotly_chart(tree_fig, use_container_width=True)
    elif selected_view == "Tabular Event Data":
        st.dataframe(
            pd.DataFrame(_timeline_to_rows(timeline_entries)),
            use_container_width=True,
            height=500,
            hide_index=True,
        )
        st.caption(
            "The table displays only the current page. Use the full-case CSV export "
            "to export all matching events."
        )
