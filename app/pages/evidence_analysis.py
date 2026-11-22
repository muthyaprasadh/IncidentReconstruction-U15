"""
Evidence Analysis & Correlation Page for U-15 Incident Reconstruction Platform.
Supports SQL-based filtering, pagination and cross-artifact correlation.
"""

import json
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

RELATIONSHIP_PAGE_SIZE = 50
EVENT_PAGE_SIZE = 100


def get_connection():
    return db.get_db_connection()


def get_event_statistics(case_id):
    conn = get_connection()

    try:
        total = conn.execute(
            "SELECT COUNT(*) FROM events WHERE case_id = ?",
            (case_id,)
        ).fetchone()[0]

        rows = conn.execute(
            """
            SELECT source, COUNT(*) AS total
            FROM events
            WHERE case_id = ?
            GROUP BY source
            """,
            (case_id,)
        ).fetchall()

        counts = {
            "process": 0,
            "registry": 0,
            "network": 0
        }

        for row in rows:
            counts[row["source"]] = row["total"]

        return total, counts

    finally:
        conn.close()


def get_relationship_options(case_id):
    conn = get_connection()

    try:
        categories = conn.execute(
            """
            SELECT DISTINCT relationship_category
            FROM relationships
            WHERE case_id = ?
            ORDER BY relationship_category
            """,
            (case_id,)
        ).fetchall()

        types = conn.execute(
            """
            SELECT DISTINCT relationship_type
            FROM relationships
            WHERE case_id = ?
            ORDER BY relationship_type
            """,
            (case_id,)
        ).fetchall()

        return (
            [r["relationship_category"] for r in categories],
            [r["relationship_type"] for r in types]
        )

    finally:
        conn.close()


def get_relationship_count(case_id, category, relationship_type):
    conditions = ["case_id = ?"]
    params = [case_id]

    if category != "All Categories":
        conditions.append("relationship_category = ?")
        params.append(category)

    if relationship_type != "All Types":
        conditions.append("relationship_type = ?")
        params.append(relationship_type)

    conn = get_connection()

    try:
        query = (
            "SELECT COUNT(*) FROM relationships WHERE "
            + " AND ".join(conditions)
        )

        return conn.execute(query, params).fetchone()[0]

    finally:
        conn.close()


def get_relationship_page(
    case_id,
    category,
    relationship_type,
    page,
    page_size
):
    conditions = ["case_id = ?"]
    params = [case_id]

    if category != "All Categories":
        conditions.append("relationship_category = ?")
        params.append(category)

    if relationship_type != "All Types":
        conditions.append("relationship_type = ?")
        params.append(relationship_type)

    offset = (page - 1) * page_size

    query = (
        "SELECT * FROM relationships WHERE "
        + " AND ".join(conditions)
        + " ORDER BY id LIMIT ? OFFSET ?"
    )

    params.extend([page_size, offset])

    conn = get_connection()

    try:
        rows = conn.execute(query, params).fetchall()

        results = []

        for row in rows:
            item = dict(row)

            for field in (
                "supporting_identifiers",
                "evidence_sources"
            ):
                value = item.get(field)

                if value:
                    try:
                        item[field] = json.loads(value)
                    except (TypeError, ValueError):
                        item[field] = []
                else:
                    item[field] = []

            results.append(item)

        return results

    finally:
        conn.close()


def get_event_page(
    case_id,
    source,
    search,
    page,
    page_size
):
    conditions = ["case_id = ?"]
    params = [case_id]

    if source != "All Sources":
        conditions.append("source = ?")
        params.append(source.lower())

    if search:
        conditions.append(
            """
            (
                LOWER(COALESCE(process_name, '')) LIKE ?
                OR CAST(pid AS TEXT) LIKE ?
                OR LOWER(COALESCE(registry_key, '')) LIKE ?
                OR LOWER(COALESCE(dst_ip, '')) LIKE ?
                OR LOWER(COALESCE(event_type, '')) LIKE ?
            )
            """
        )

        pattern = f"%{search.lower()}%"
        params.extend([pattern] * 5)

    where_clause = " AND ".join(conditions)

    conn = get_connection()

    try:
        total = conn.execute(
            f"SELECT COUNT(*) FROM events WHERE {where_clause}",
            params
        ).fetchone()[0]

        offset = (page - 1) * page_size

        query = f"""
            SELECT
                event_id,
                timestamp,
                source,
                event_type,
                process_name,
                pid,
                registry_key,
                dst_ip,
                dst_port,
                file_path,
                evidence_file,
                evidence_reference
            FROM events
            WHERE {where_clause}
            ORDER BY timestamp
            LIMIT ? OFFSET ?
        """

        rows = conn.execute(
            query,
            params + [page_size, offset]
        ).fetchall()

        return total, [dict(row) for row in rows]

    finally:
        conn.close()


def render_pagination(page_key, total_pages):
    current_page = st.session_state.get(page_key, 1)

    col1, col2, col3 = st.columns([1, 2, 1])

    with col1:
        if st.button(
            "⬅ Previous",
            disabled=current_page <= 1,
            key=f"{page_key}_previous"
        ):
            st.session_state[page_key] = current_page - 1
            st.rerun()

    with col2:
        st.markdown(
            f"<center>Page {current_page} of {total_pages}</center>",
            unsafe_allow_html=True
        )

    with col3:
        if st.button(
            "Next ➡",
            disabled=current_page >= total_pages,
            key=f"{page_key}_next"
        ):
            st.session_state[page_key] = current_page + 1
            st.rerun()


def render_evidence_analysis_page():

    st.markdown(
        "## 🔬 Evidence Normalization & Cross-Artifact Correlation"
    )

    st.caption(
        "Inspect standardized event schemas and execute explainable "
        "cross-artifact correlation."
    )

    case_id = st.session_state.get("current_case_id")

    if not case_id:
        st.warning("Please select an active investigation case first.")
        return

    st.info(f"Active Case: **`{case_id}`**")

    total_events, event_counts = get_event_statistics(case_id)

    if total_events == 0:
        st.info("No normalized events available for this case.")
        return

    m1, m2, m3, m4 = st.columns(4)

    with m1:
        st.metric("Total Ingested Events", f"{total_events:,}")

    with m2:
        st.metric("Process Events", f"{event_counts['process']:,}")

    with m3:
        st.metric("Registry Events", f"{event_counts['registry']:,}")

    with m4:
        st.metric("Network Events", f"{event_counts['network']:,}")

    st.markdown("---")

    st.markdown("### ⚙️ Cross-Artifact Correlation Engine")

    st.caption(
        "Rule-based correlation engine adhering to forensic provenance, "
        "PID reuse guards, and 5-tuple socket matching."
    )

    c1, c2 = st.columns([3, 1])

    with c1:
        temp_window = st.slider(
            "Temporal Correlation Window (± seconds)",
            min_value=1.0,
            max_value=30.0,
            value=float(DEFAULT_TIME_WINDOW_SECONDS),
            step=1.0
        )

    with c2:
        st.write("")
        st.write("")

        run_btn = st.button(
            "🚀 Run Correlation Engine",
            type="primary",
            key=f"run_correlation_{case_id}"
        )

    if run_btn:

        with st.spinner("Running correlation engine..."):

            raw_events = db.get_events(case_id)

            events_obj = [
                NormalizedEvent(
                    **{
                        k: v
                        for k, v in event.items()
                        if k in NormalizedEvent.__annotations__
                    }
                )
                for event in raw_events
            ]

            engine = CorrelationEngine(
                case_id=case_id,
                temporal_window=temp_window
            )

            relationships = engine.run(
                events_obj,
                save_to_db=True
            )

            st.success(
                f"Correlation completed: {len(relationships):,} relationships."
            )

            st.rerun()

    st.markdown("---")

    st.markdown("### 🔗 Correlated Relationships")

    categories, relationship_types = get_relationship_options(case_id)

    if not relationship_types:
        st.warning("No relationships available for this case.")
    else:

        f1, f2 = st.columns(2)

        with f1:
            selected_category = st.selectbox(
                "Filter by Relationship Category",
                ["All Categories"] + categories,
                key=f"relationship_category_{case_id}"
            )

        with f2:
            selected_type = st.selectbox(
                "Filter by Relationship Type",
                ["All Types"] + relationship_types,
                key=f"relationship_type_{case_id}"
            )

        filter_signature = (
            selected_category,
            selected_type
        )

        signature_key = f"relationship_signature_{case_id}"
        page_key = f"relationship_page_{case_id}"

        if st.session_state.get(signature_key) != filter_signature:
            st.session_state[signature_key] = filter_signature
            st.session_state[page_key] = 1

        total_relationships = get_relationship_count(
            case_id,
            selected_category,
            selected_type
        )

        total_pages = max(
            1,
            (total_relationships + RELATIONSHIP_PAGE_SIZE - 1)
            // RELATIONSHIP_PAGE_SIZE
        )

        current_page = st.session_state.get(page_key, 1)

        if current_page > total_pages:
            current_page = total_pages
            st.session_state[page_key] = current_page

        st.info(
            f"Showing {total_relationships:,} matching relationships "
            f"out of all relationship records."
        )

        if total_relationships:

            relationships = get_relationship_page(
                case_id,
                selected_category,
                selected_type,
                current_page,
                RELATIONSHIP_PAGE_SIZE
            )

            st.caption(
                f"Displaying {len(relationships)} records on this page."
            )

            for index, relationship in enumerate(relationships):

                category = relationship.get(
                    "relationship_category",
                    "Unknown"
                )

                relationship_type = relationship.get(
                    "relationship_type",
                    "Unknown"
                )

                confidence = float(
                    relationship.get("confidence_score", 0) or 0
                )

                color = CATEGORY_COLORS.get(
                    category,
                    "#6B7280"
                )

                with st.container(border=True):

                    st.markdown(
                        f"**{relationship.get('source_event_id')} "
                        f"→ {relationship.get('target_event_id')}**"
                    )

                    col1, col2, col3 = st.columns([2, 1, 1])

                    with col1:
                        st.markdown(
                            f"Relationship: `{relationship_type}`"
                        )

                    with col2:
                        st.markdown(
                            f"Category: :green[{category}]"
                        )

                    with col3:
                        st.metric(
                            "Confidence",
                            f"{confidence:.2f}"
                        )

                    st.caption(
                        "Correlation Method: "
                        + str(
                            relationship.get(
                                "correlation_method",
                                "Unknown"
                            )
                        )
                    )

                    st.write(
                        relationship.get(
                            "explanation",
                            "No explanation available."
                        )
                    )

                    identifiers = relationship.get(
                        "supporting_identifiers",
                        []
                    )

                    if not isinstance(identifiers, list):
                        identifiers = []

                    st.caption(
                        "Supporting Identifiers: "
                        + (
                            ", ".join(str(x) for x in identifiers)
                            if identifiers
                            else "None"
                        )
                    )

            render_pagination(page_key, total_pages)

        else:
            st.warning(
                "No relationships match the selected filters."
            )

    st.markdown("---")

    st.markdown("### 📋 Normalized Forensic Events Browser")

    col1, col2 = st.columns([1, 2])

    with col1:
        view_source = st.selectbox(
            "Filter Source",
            [
                "All Sources",
                "Process",
                "Registry",
                "Network"
            ],
            key=f"event_source_{case_id}"
        )

    with col2:
        search = st.text_input(
            "Search Events",
            placeholder="Search PID, process, registry key, IP...",
            key=f"event_search_{case_id}"
        ).strip()

    event_signature = (view_source, search)

    event_signature_key = f"event_signature_{case_id}"
    event_page_key = f"event_page_{case_id}"

    if st.session_state.get(event_signature_key) != event_signature:
        st.session_state[event_signature_key] = event_signature
        st.session_state[event_page_key] = 1

    event_total, event_rows = get_event_page(
        case_id,
        view_source,
        search,
        st.session_state.get(event_page_key, 1),
        EVENT_PAGE_SIZE
    )

    event_pages = max(
        1,
        (event_total + EVENT_PAGE_SIZE - 1) // EVENT_PAGE_SIZE
    )

    if st.session_state.get(event_page_key, 1) > event_pages:
        st.session_state[event_page_key] = event_pages

        event_total, event_rows = get_event_page(
            case_id,
            view_source,
            search,
            event_pages,
            EVENT_PAGE_SIZE
        )

    st.caption(
        f"Showing {len(event_rows)} of {event_total:,} matching events."
    )

    display_rows = []

    for event in event_rows:

        display_rows.append({
            "Event ID": event["event_id"],
            "Timestamp": event["timestamp"],
            "Source": event["source"].upper(),
            "Type": event["event_type"],
            "Process": (
                f"{event.get('process_name') or ''} "
                f"({event.get('pid') or ''})"
            ),
            "Target / Key / Socket": (
                event.get("registry_key")
                or (
                    f"{event.get('dst_ip')}:{event.get('dst_port')}"
                    if event.get("dst_ip")
                    else event.get("file_path") or ""
                )
            ),
            "Provenance": (
                f"{event.get('evidence_file')} "
                f"({event.get('evidence_reference')})"
            )
        })

    st.dataframe(
        pd.DataFrame(display_rows),
        use_container_width=True,
        height=400
    )

    render_pagination(
        event_page_key,
        event_pages
    )