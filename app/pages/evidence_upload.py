"""
Evidence Upload Page for U-15 Incident Reconstruction Platform.
Provides dedicated forensic ingestion pipelines for Process, Registry, and Network evidence.
Preserves raw forensic files, computes cryptographic hashes, and invokes native parsers.
"""

import streamlit as st
from pathlib import Path
import hashlib
import database.db as db

from database.models import EvidenceFile
from config.settings import RAW_DATA_DIR
from parsers.procmon_parser import ProcmonParser
from parsers.registry_parser import RegistryParser
from parsers.network_parser import NetworkParser
from parsers.sysmon_parser import SysmonParser
from experiments.test_scenario_generator import (
    ControlledExperimentGenerator,
    AVAILABLE_SCENARIOS
)


def compute_sha256(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()


def save_and_ingest_file(
    uploaded_file,
    case_id: str,
    source_type: str,
    capture_timezone: str = "Asia/Kolkata"
) -> dict:

    """Saves raw forensic file, computes its hash, and invokes the appropriate parser."""

    dest_dir = RAW_DATA_DIR / case_id
    dest_dir.mkdir(parents=True, exist_ok=True)

    dest_path = dest_dir / uploaded_file.name

    bytes_data = uploaded_file.getvalue()

    with open(dest_path, "wb") as f:
        f.write(bytes_data)

    sha256 = compute_sha256(bytes_data)
    file_size = len(bytes_data)

    ev_record = EvidenceFile(
        case_id=case_id,
        source_type=source_type,
        file_name=uploaded_file.name,
        file_path=str(dest_path),
        file_size=file_size,
        file_hash=sha256,
        status="Ingested"
    )

    file_id = db.add_evidence_file(ev_record)

    parsed_events = []
    errors = []
    warnings = []

    case_row = db.get_case_by_id(case_id) or {}
    base_date = case_row.get("collection_date") or None

    if source_type == "process":

        parser = ProcmonParser(case_id=case_id)

        parsed_events = parser.parse_file(
            str(dest_path),
            base_date=base_date,
            timezone_name=capture_timezone
        )

        errors = parser.errors
        warnings = parser.warnings

    elif source_type == "sysmon":

        parser = SysmonParser(case_id=case_id)

        parsed_events = parser.parse_file(
            str(dest_path),
            base_date=base_date,
            timezone_name="UTC"
        )

        errors = parser.errors
        warnings = parser.warnings

    elif source_type == "registry":

        parser = RegistryParser(case_id=case_id)

        parsed_events = parser.parse_file(str(dest_path))

        errors = parser.errors
        warnings = parser.warnings

    elif source_type == "network":

        parser = NetworkParser(case_id=case_id)

        parsed_events = parser.parse_file(str(dest_path))

        errors = parser.errors
        warnings = parser.warnings

    if parsed_events:
        db.insert_events_batch(parsed_events)

    status = "Parsed" if not errors else "Parsed with Errors"

    err_text = "; ".join(errors) if errors else ""

    db.update_evidence_file_stats(
        file_id,
        record_count=len(parsed_events),
        status=status,
        errors=err_text
    )

    return {
        "file_name": uploaded_file.name,
        "file_size": file_size,
        "hash": sha256,
        "events_count": len(parsed_events),
        "errors": errors,
        "warnings": warnings
    }


def render_evidence_upload_page():

    st.markdown("## 📥 Forensic Evidence Ingestion")

    st.caption(
        "Upload and validate Process Monitor, Sysmon XML, "
        "Windows Registry, and Wireshark / PCAP evidence."
    )

    # --------------------------------------------------
    # ACTIVE INVESTIGATION
    # --------------------------------------------------

    case_id = st.session_state.get("current_case_id")

    if not case_id:

        st.warning(
            "⚠️ No active case selected. "
            "Please select or create an investigation first."
        )

        cases = db.get_all_cases()

        if cases:

            selected_case = st.selectbox(
                "Quick Select Active Case",
                options=[c["case_id"] for c in cases]
            )

            if st.button("Set Active"):

                st.session_state["current_case_id"] = selected_case

                st.rerun()

        return

    st.info(
        f"Target Investigation: **`{case_id}`** "
        f"({st.session_state.get('current_case_name', '')})"
    )

    # --------------------------------------------------
    # CONTROLLED EXPERIMENT GENERATOR
    # --------------------------------------------------

    with st.expander(
        "🧪 Controlled Experiment Evidence Generator (Harmless Test Lab)",
        expanded=False
    ):

        st.markdown(
            """
            Generate a controlled set of forensic evidence with documented ground truth:

            - **Process Monitor CSV:** Process creation and file operations
            - **Windows Registry .reg:** Dedicated safe HKCU test key
            - **Wireshark CSV:** Network packet observations
            - **Sysmon XML:** Process creation and network events
            - **Independent Ground Truth JSON:** Experiment labels recorded separately
            """
        )

        gen_col1, gen_col2 = st.columns([3, 1])

        # SCENARIO SELECTION

        with gen_col1:

            scenario_name = st.selectbox(
                "Controlled Lab Scenario (22 Scenarios Available)",
                options=AVAILABLE_SCENARIOS,
                index=5,
                key="controlled_scenario_select"
            )

            st.info(f"Selected scenario: {scenario_name}")

            st.info(f"Active investigation: {case_id}")

        # GENERATE AND INGEST

        with gen_col2:

            if st.button(
                "Generate & Ingest Lab Data",
                type="primary",
                key="generate_ingest_button"
            ):
                with st.spinner(
                    f"Generating controlled scenario {scenario_name}..."
                ):
                    try:
                        generator = ControlledExperimentGenerator(
                            case_id=case_id
                        )

                        ds = generator.generate_scenario(
                            scenario_id=scenario_name
                        )

                        # Parse and validate every available artifact before touching
                        # the current database records.
                        parsed_by_source = {}
                        evidence_records = []
                        parser_errors = []

                        artifact_specs = [
                            ("procmon_file", "process", ProcmonParser, "procmon"),
                            ("registry_file", "registry", RegistryParser, "registry"),
                            ("wireshark_file", "network", NetworkParser, "network"),
                            ("sysmon_file", "sysmon", SysmonParser, "sysmon"),
                        ]

                        parsed_counts = {
                            "process": 0,
                            "registry": 0,
                            "network": 0,
                            "sysmon": 0,
                        }

                        for file_key, source_type, parser_class, label in artifact_specs:
                            file_value = ds.get(file_key)
                            if not file_value:
                                continue

                            artifact_path = Path(file_value)
                            if not artifact_path.exists():
                                continue

                            file_size = artifact_path.stat().st_size
                            if file_size == 0:
                                continue

                            parser = parser_class(case_id)

                            if source_type == "process":
                                artifact_events = parser.parse_file(
                                    str(artifact_path),
                                    base_date="2026-11-10",
                                    timezone_name="UTC"
                                )
                            elif source_type == "network":
                                artifact_events = parser.parse_file(
                                    str(artifact_path),
                                    base_date="2026-11-10"
                                )
                            elif source_type == "sysmon":
                                artifact_events = parser.parse_file(
                                    str(artifact_path),
                                    timezone_name="UTC"
                                )
                            else:
                                artifact_events = parser.parse_file(str(artifact_path))

                            parser_errors.extend(
                                f"{artifact_path.name}: {error}"
                                for error in getattr(parser, "errors", [])
                            )

                            parsed_by_source[source_type] = artifact_events
                            parsed_counts[source_type] = len(artifact_events)

                            evidence_records.append(
                                EvidenceFile(
                                    case_id=case_id,
                                    source_type=source_type,
                                    file_name=artifact_path.name,
                                    file_path=str(artifact_path),
                                    file_size=file_size,
                                    record_count=len(artifact_events),
                                    status="Parsed" if not getattr(parser, "errors", []) else "Parsed with Errors",
                                    errors="; ".join(getattr(parser, "errors", []))
                                )
                            )

                        if parser_errors:
                            raise RuntimeError(
                                "Evidence parsing failed; existing database records were not changed. "
                                + " | ".join(parser_errors)
                            )

                        all_new_events = [
                            event
                            for group in parsed_by_source.values()
                            for event in group
                        ]

                        if not all_new_events:
                            raise RuntimeError(
                                "No events were parsed. Existing database records were not changed."
                            )

                        if any(event.case_id != case_id for event in all_new_events):
                            raise RuntimeError(
                                "A parsed event belongs to a different case. "
                                "Existing database records were not changed."
                            )

                        inserted_events, inserted_files = db.replace_case_ingestion(
                            case_id,
                            all_new_events,
                            evidence_records
                        )

                        pm_evs = parsed_by_source.get("process", [])
                        reg_evs = parsed_by_source.get("registry", [])
                        net_evs = parsed_by_source.get("network", [])
                        sm_evs = parsed_by_source.get("sysmon", [])

                        # ------------------------------------------
                        # GENERATION SUMMARY
                        # ------------------------------------------

                        st.success(
                            f"""
                            Controlled scenario `{scenario_name}` generated and ingested successfully!\n\nDatabase transaction committed: {inserted_events} events and {inserted_files} evidence-file records.

                            Dataset type: {ds['dataset_type']}

                            - Process events: {parsed_counts['process']}
                            - Registry events: {parsed_counts['registry']}
                            - Network events: {parsed_counts['network']}
                            - Sysmon events: {parsed_counts['sysmon']}

                            Ground truth:
                            - Incident events: {ds['ground_truth_events']}
                            - Expected relationships: {ds['expected_relationships']}
                            """
                        )

                        st.rerun()

                    except Exception as exc:
                        st.error(f"❌ Ingestion failed: {exc}")
                        db.logger.error("Evidence upload/generation error for case %s: %s", case_id, exc, exc_info=True)

    # --------------------------------------------------
    # MANUAL EVIDENCE UPLOAD
    # --------------------------------------------------

    st.markdown("---")

    st.markdown("### 📤 Upload Forensic Artifacts")

    capture_timezone = st.text_input(
        "Capture timezone for Procmon time-of-day records",
        value="Asia/Kolkata",
        help=(
            "Enter an IANA timezone such as Asia/Kolkata or UTC. "
            "Procmon CSV Time of Day is local wall-clock time; "
            "the date comes from the case metadata."
        )
    )

    tab_proc, tab_sysmon, tab_reg, tab_net = st.tabs(
        [
            "1. Process Evidence (Procmon)",
            "2. Sysmon XML (Event ID 1 / 3)",
            "3. Registry Evidence (.reg / CSV)",
            "4. Network Evidence (Wireshark / PCAP)"
        ]
    )

    # --------------------------------------------------
    # PROCESS EVIDENCE
    # --------------------------------------------------

    with tab_proc:

        st.markdown(
            "##### Microsoft Sysinternals Process Monitor Exports"
        )

        st.caption(
            "Supports Procmon CSV exports or XML."
        )

        proc_files = st.file_uploader(
            "Upload Procmon CSV / XML",
            type=["csv", "xml"],
            accept_multiple_files=True,
            key="proc_uploader"
        )

        if proc_files:

            if st.button(
                "Parse Process Evidence",
                key="parse_proc_btn"
            ):

                progress_bar = st.progress(0)

                for i, pf in enumerate(proc_files):

                    res = save_and_ingest_file(
                        pf,
                        case_id,
                        "process",
                        capture_timezone=capture_timezone
                    )

                    st.success(
                        f"Ingested `{res['file_name']}`: "
                        f"{res['events_count']} events "
                        f"(SHA-256: `{res['hash'][:12]}...`)"
                    )

                    if res["warnings"]:
                        st.warning(
                            f"{len(res['warnings'])} warnings during parsing."
                        )

                    if res["errors"]:
                        st.error(
                            f"Errors: {', '.join(res['errors'])}"
                        )

                    progress_bar.progress(
                        (i + 1) / len(proc_files)
                    )

                st.rerun()

    # --------------------------------------------------
    # SYSMON EVIDENCE
    # --------------------------------------------------

    with tab_sysmon:

        st.markdown(
            "##### Microsoft Sysmon exported Windows Event Log XML"
        )

        st.caption(
            "Supports Event ID 1 (process creation) and Event ID 3 "
            "(network connection). Binary EVTX is not parsed; "
            "export XML first."
        )

        sysmon_files = st.file_uploader(
            "Upload Sysmon XML",
            type=["xml"],
            accept_multiple_files=True,
            key="sysmon_uploader"
        )

        if sysmon_files:

            if st.button(
                "Parse Sysmon Evidence",
                key="parse_sysmon_btn"
            ):

                progress_bar = st.progress(0)

                for i, sf in enumerate(sysmon_files):

                    res = save_and_ingest_file(
                        sf,
                        case_id,
                        "sysmon"
                    )

                    st.success(
                        f"Ingested `{res['file_name']}`: "
                        f"{res['events_count']} events "
                        f"(SHA-256: `{res['hash'][:12]}...`)"
                    )

                    if res["warnings"]:
                        st.warning(
                            f"{len(res['warnings'])} warnings during parsing."
                        )

                    if res["errors"]:
                        st.error(
                            f"Errors: {', '.join(res['errors'])}"
                        )

                    progress_bar.progress(
                        (i + 1) / len(sysmon_files)
                    )

                st.rerun()

    # --------------------------------------------------
    # REGISTRY EVIDENCE
    # --------------------------------------------------

    with tab_reg:

        st.markdown("##### Windows Registry Evidence")

        st.caption(
            "Supports Windows .reg export scripts or RECmd / RegShot CSV exports."
        )

        reg_files = st.file_uploader(
            "Upload Registry Files (.reg, .csv)",
            type=["reg", "csv"],
            accept_multiple_files=True,
            key="reg_uploader"
        )

        if reg_files:

            if st.button(
                "Parse Registry Evidence",
                key="parse_reg_btn"
            ):

                progress_bar = st.progress(0)

                for i, rf in enumerate(reg_files):

                    res = save_and_ingest_file(
                        rf,
                        case_id,
                        "registry"
                    )

                    st.success(
                        f"Ingested `{res['file_name']}`: "
                        f"{res['events_count']} events "
                        f"(SHA-256: `{res['hash'][:12]}...`)"
                    )

                    if res["warnings"]:
                        st.warning(
                            f"{len(res['warnings'])} warnings during parsing."
                        )

                    if res["errors"]:
                        st.error(
                            f"Errors: {', '.join(res['errors'])}"
                        )

                    progress_bar.progress(
                        (i + 1) / len(reg_files)
                    )

                st.rerun()

    # --------------------------------------------------
    # NETWORK EVIDENCE
    # --------------------------------------------------

    with tab_net:

        st.markdown(
            "##### Network Packet Captures & Wireshark Exports"
        )

        st.caption(
            "Supports Wireshark CSV packet summaries and PCAP / PCAPNG files."
        )

        net_files = st.file_uploader(
            "Upload Wireshark CSV / PCAP",
            type=["csv", "pcap", "pcapng", "cap"],
            accept_multiple_files=True,
            key="net_uploader"
        )

        if net_files:

            if st.button(
                "Parse Network Evidence",
                key="parse_net_btn"
            ):

                progress_bar = st.progress(0)

                for i, nf in enumerate(net_files):

                    res = save_and_ingest_file(
                        nf,
                        case_id,
                        "network"
                    )

                    st.success(
                        f"Ingested `{res['file_name']}`: "
                        f"{res['events_count']} packets/sockets "
                        f"(SHA-256: `{res['hash'][:12]}...`)"
                    )

                    if res["warnings"]:
                        st.warning(
                            f"{len(res['warnings'])} warnings during parsing."
                        )

                    if res["errors"]:
                        st.error(
                            f"Errors: {', '.join(res['errors'])}"
                        )

                    progress_bar.progress(
                        (i + 1) / len(net_files)
                    )

                st.rerun()

    # --------------------------------------------------
    # INGESTED FILES
    # --------------------------------------------------

    st.markdown("---")

    st.markdown(
        "### 🗄️ Currently Ingested Files for this Case"
    )

    files = db.get_evidence_files(case_id)

    if files:

        for f in files:

            col_a, col_b, col_c, col_d = st.columns(
                [3, 2, 2, 2]
            )

            with col_a:

                st.markdown(
                    f"**`{f['file_name']}`** "
                    f"({f['source_type'].upper()})"
                )

            with col_b:

                st.caption(
                    f"Records: {f['record_count']}"
                )

            with col_c:

                st.caption(
                    f"Size: {f['file_size']:,} bytes"
                )

            with col_d:

                st.caption(
                    f"Status: {f['status']}"
                )

    else:

        st.info(
            "No evidence files currently attached to this case."
        )