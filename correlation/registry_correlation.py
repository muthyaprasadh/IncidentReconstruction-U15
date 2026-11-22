from typing import List, Dict, Optional
from database.models import NormalizedEvent, EventRelationship
from correlation.process_correlation import ProcessLifetimeTracker
from normalization.normalizer import Normalizer
from config.settings import logger


class RegistryCorrelator:

    @staticmethod
    def correlate_registry_events(
        events: List[NormalizedEvent],
        case_id: str,
        tracker: ProcessLifetimeTracker,
        window_seconds: float = 5.0
    ) -> List[EventRelationship]:

        relationships: List[EventRelationship] = []

        reg_events = [
            e for e in events
            if e.source == "registry" or e.registry_key
        ]

        proc_events = [
            e for e in events
            if e.source == "process"
        ]

        by_pid: Dict[int, List[NormalizedEvent]] = {}

        for pe in proc_events:
            if pe.pid is not None:
                by_pid.setdefault(pe.pid, []).append(pe)

        events_by_id = {
            e.event_id: e for e in proc_events
        }

        for reg in reg_events:

            is_snapshot = (
                (reg.metadata or {}).get("is_snapshot", False)
                or not reg.timestamp
            )

            if reg.pid is not None:

                if is_snapshot or not reg.timestamp:
                    continue

                process_guid = getattr(reg, "process_guid", "") or ""

                epoch = tracker.get_active_epoch(
                    reg.pid,
                    reg.timestamp,
                    process_guid=process_guid
                )

                if epoch is None:
                    logger.warning(
                        "Registry event %s has PID %s but no validated process attribution",
                        reg.event_id,
                        reg.pid
                    )
                    continue

                p_cand = events_by_id.get(epoch.start_event_id)

                reg_dt = Normalizer.try_parse_complete_datetime(
                    reg.timestamp
                )

                if reg_dt is not None:
                    lifecycle_candidates = []

                    for pe in by_pid.get(reg.pid, []):

                        if pe.event_type.upper() not in (
                            "PROCESS_CREATE",
                            "PROCESS_START"
                        ):
                            continue

                        if not pe.timestamp:
                            continue

                        if (
                            reg.process_name
                            and pe.process_name
                            and reg.process_name.lower() != pe.process_name.lower()
                        ):
                            continue

                        pe_dt = Normalizer.try_parse_complete_datetime(
                            pe.timestamp
                        )

                        if pe_dt is None:
                            continue

                        if pe_dt < epoch.start_time or pe_dt > reg_dt:
                            continue

                        if not tracker.is_pid_active(
                            reg.pid,
                            pe.process_name,
                            reg.timestamp,
                            process_guid=process_guid
                        ):
                            continue

                        delta = (reg_dt - pe_dt).total_seconds()

                        if delta <= window_seconds:
                            lifecycle_candidates.append((delta, pe))

                    procmon_create_candidates = [
                        item for item in lifecycle_candidates
                        if item[1].event_type.upper() == "PROCESS_CREATE"
                    ]

                    if procmon_create_candidates:
                        _, p_cand = min(
                            procmon_create_candidates,
                            key=lambda item: item[0]
                        )

                    elif p_cand is None and lifecycle_candidates:
                        _, p_cand = min(
                            lifecycle_candidates,
                            key=lambda item: item[0]
                        )

                if p_cand is None:
                    candidates = []

                    for pe in by_pid.get(reg.pid, []):
                        if not pe.timestamp:
                            continue

                        pe_dt = Normalizer.try_parse_complete_datetime(
                            pe.timestamp
                        )

                        if pe_dt is None or reg_dt is None:
                            continue

                        if pe_dt < epoch.start_time or pe_dt > reg_dt:
                            continue

                        if not tracker.is_pid_active(
                            reg.pid,
                            pe.process_name,
                            reg.timestamp,
                            process_guid=process_guid
                        ):
                            continue

                        candidates.append(pe)

                    if candidates:
                        p_cand = min(
                            candidates,
                            key=lambda pe: Normalizer.try_parse_complete_datetime(
                                pe.timestamp
                            )
                        )

                if p_cand is None:
                    logger.warning(
                        "Registry event %s has no matching process epoch start event",
                        reg.event_id
                    )
                    continue

                op = (
                    reg.registry_operation or reg.event_type
                ).upper()

                op_type = (
                    "MODIFIED"
                    if any(k in op for k in ["SET", "CREATE", "DELETE"])
                    else "ACCESSED"
                )

                epoch_reference = (
                    f"ProcessEpochStart:{epoch.start_event_id}"
                    if epoch.is_explicit_start
                    else f"ProcessEpochObservation:{epoch.start_event_id}"
                )

                attribution = (
                    f"using its validated process epoch established by process-start evidence. "
                    f"Epoch start event: {epoch.start_event_id}. "
                    f"Relationship source event: {p_cand.event_id}."
                    if epoch.is_explicit_start
                    else (
                        f"using the Registry record's PID and a process activity observation; "
                        f"no explicit process-start record was captured. Supporting process "
                        f"event: {p_cand.event_id}."
                    )
                )

                relationships.append(
                    EventRelationship(
                        source_event_id=p_cand.event_id,
                        target_event_id=reg.event_id,
                        relationship_type=op_type,
                        confidence_score=0.95 if epoch.is_explicit_start else 0.75,
                        correlation_method="Process Epoch Registry Attribution",
                        supporting_identifiers=[
                            f"PID:{reg.pid}",
                            f"Key:{reg.registry_key}",
                            epoch_reference,
                            f"Proc:{reg.process_name or p_cand.process_name}"
                        ],
                        evidence_sources=["process", "registry"],
                        explanation=(
                            f"Registry operation attributed to process "
                            f"'{reg.process_name or p_cand.process_name}' "
                            f"(PID {reg.pid}) {attribution}"
                        ),
                        relationship_category="Directly observed",
                        case_id=case_id
                    )
                )

            elif is_snapshot:

                val_data = str(
                    (reg.metadata or {}).get("value_data", "")
                ).lower()

                if not val_data:
                    continue

                for pe in proc_events:

                    f_path = str(pe.file_path or "").lower()

                    if not f_path:
                        continue

                    if f_path in val_data or val_data in f_path:

                        relationships.append(
                            EventRelationship(
                                source_event_id=pe.event_id,
                                target_event_id=reg.event_id,
                                relationship_type="ACCESSED",
                                confidence_score=0.60,
                                correlation_method="Static Artifact Reference Matching",
                                supporting_identifiers=[
                                    f"ReferencedPath:{pe.file_path}",
                                    f"SnapshotKey:{reg.registry_key}"
                                ],
                                evidence_sources=[pe.source, reg.source],
                                explanation=(
                                    "Inferred static Registry artifact reference. "
                                    "The snapshot does not establish modification time."
                                ),
                                relationship_category="Inferred",
                                case_id=case_id
                            )
                        )

                        break

            else:

                reg_dt = Normalizer.try_parse_complete_datetime(
                    reg.timestamp
                )

                if reg_dt is None:
                    continue

                best_proc: Optional[NormalizedEvent] = None
                min_diff = float("inf")

                for pe in proc_events:

                    p_dt = Normalizer.try_parse_complete_datetime(
                        pe.timestamp
                    )

                    if p_dt is None:
                        continue

                    diff = abs(
                        (reg_dt - p_dt).total_seconds()
                    )

                    if diff > window_seconds or diff >= min_diff:
                        continue

                    if pe.pid is not None and not tracker.is_pid_active(
                        pe.pid,
                        pe.process_name,
                        reg.timestamp,
                        process_guid=getattr(pe, "process_guid", "") or ""
                    ):
                        continue

                    min_diff = diff
                    best_proc = pe

                if best_proc is None:
                    continue

                op = (
                    reg.registry_operation or reg.event_type
                ).upper()

                relationships.append(
                    EventRelationship(
                        source_event_id=best_proc.event_id,
                        target_event_id=reg.event_id,
                        relationship_type=(
                            "MODIFIED" if any(
                                k in op for k in ["SET", "CREATE", "DELETE"]
                            ) else "ACCESSED"
                        ),
                        confidence_score=0.75,
                        correlation_method="Temporal Registry Correlation Window",
                        supporting_identifiers=[
                            f"Delta:{min_diff:.2f}s",
                            f"Key:{reg.registry_key}"
                        ],
                        evidence_sources=[best_proc.source, reg.source],
                        explanation=(
                            f"Temporal association between process "
                            f"'{best_proc.process_name}' and Registry event "
                            f"'{reg.registry_key}'."
                        ),
                        relationship_category="Temporal association",
                        case_id=case_id
                    )
                )

        relationships = [
            r for r in relationships
            if r.source_event_id != r.target_event_id
        ]

        return relationships