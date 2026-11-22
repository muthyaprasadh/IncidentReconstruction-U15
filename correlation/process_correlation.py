"""
Process Correlation Engine for U-15 Incident Reconstruction.
Strictly implements digital forensics standards:
- Process start events establish process lifetimes; process exit events terminate lifetimes.
- PID reuse is handled correctly across distinct temporal epochs.
- Parent-child relationships require actual process creation events.
- Registry and network events are NEVER treated as process-start events.
"""
from typing import List, Dict, Any, Tuple, Optional
from datetime import datetime
from database.models import NormalizedEvent, EventRelationship
from normalization.normalizer import Normalizer
from config.settings import logger


def event_process_guid(ev: NormalizedEvent) -> str:
    meta = ev.metadata or {}

    guid = (
        getattr(ev, "process_guid", "")
        or meta.get("ProcessGuid")
        or meta.get("process_guid")
        or ""
    )

    guid = str(guid).strip()

    if not guid:
        return ""

    normalized = guid.lower().replace("{", "").replace("}", "").replace("-", "")

    if normalized and set(normalized) == {"0"}:
        return ""

    return guid


class ProcessEpoch:
    def __init__(
        self,
        pid: int,
        process_name: str,
        start_time: datetime,
        start_event_id: str,
        is_explicit_start: bool,
        process_guid: str = ""
    ):
        self.pid = pid
        self.process_name = process_name
        self.process_guid = process_guid
        self.start_time = start_time
        self.end_time: Optional[datetime] = None
        self.start_event_id = start_event_id
        self.is_explicit_start = is_explicit_start

    def is_active_at(
        self,
        target_time: datetime,
        target_name: str = "",
        process_guid: str = ""
    ) -> bool:
        if process_guid and self.process_guid and process_guid.lower() != self.process_guid.lower():
            return False

        if target_name and self.process_name and target_name.lower() != self.process_name.lower():
            return False

        if target_time < self.start_time:
            return False

        if self.end_time is not None and target_time >= self.end_time:
            return False

        return True


class ProcessLifetimeTracker:
    def __init__(
        self,
        use_process_guid: bool = True,
        use_lifetime_validation: bool = True
    ):
        self.epochs: Dict[int, List[ProcessEpoch]] = {}
        self.use_process_guid = use_process_guid
        self.use_lifetime_validation = use_lifetime_validation

    def register_events(self, events: List[NormalizedEvent]):
        proc_events = []

        for e in events:
            if e.source != "process" or e.pid is None:
                continue

            dt = Normalizer.try_parse_complete_datetime(e.timestamp)

            if dt is None:
                continue

            proc_events.append((dt, e))

        proc_events.sort(key=lambda x: x[0])

        for dt, ev in proc_events:
            pid = ev.pid
            p_name = ev.process_name or ""
            op_up = ev.event_type.upper()

            if pid not in self.epochs:
                self.epochs[pid] = []

            if op_up == "PROCESS_START":
                guid = event_process_guid(ev)
                merged = False

                for ep in self.epochs[pid]:
                    if ep.end_time is not None:
                        continue

                    same_name = (
                        not p_name
                        or not ep.process_name
                        or p_name.lower() == ep.process_name.lower()
                    )

                    same_guid = (
                        not guid
                        or not ep.process_guid
                        or guid.lower() == ep.process_guid.lower()
                    )

                    if same_name and same_guid and ep.is_explicit_start:
                        if guid and not ep.process_guid:
                            ep.process_guid = guid

                        merged = True
                        break

                if merged:
                    continue

                for ep in self.epochs[pid]:
                    if ep.end_time is None:
                        ep.end_time = dt

                self.epochs[pid].append(
                    ProcessEpoch(
                        pid=pid,
                        process_name=p_name,
                        start_time=dt,
                        start_event_id=ev.event_id,
                        is_explicit_start=True,
                        process_guid=guid,
                    )
                )

            elif op_up == "PROCESS_EXIT":
                matched = False

                for ep in reversed(self.epochs[pid]):
                    if ep.end_time is None:
                        ep.end_time = dt
                        matched = True
                        break

                if not matched:
                    closed_ep = ProcessEpoch(
                        pid=pid,
                        process_name=p_name,
                        start_time=dt,
                        start_event_id=ev.event_id,
                        is_explicit_start=False,
                        process_guid=event_process_guid(ev),
                    )

                    closed_ep.end_time = dt
                    self.epochs[pid].append(closed_ep)

            else:
                has_open = any(
                    ep.end_time is None
                    for ep in self.epochs[pid]
                )

                if not has_open:
                    self.epochs[pid].append(
                        ProcessEpoch(
                            pid=pid,
                            process_name=p_name,
                            start_time=dt,
                            start_event_id=ev.event_id,
                            is_explicit_start=False,
                            process_guid=event_process_guid(ev),
                        )
                    )

    def is_pid_active(
        self,
        pid: int,
        process_name: str,
        timestamp_str: Optional[str],
        process_guid: str = "",
    ) -> bool:

        if not self.use_lifetime_validation:
            return pid is not None

        if not timestamp_str or pid not in self.epochs:
            return False

        target_dt = Normalizer.try_parse_complete_datetime(timestamp_str)

        if target_dt is None:
            return False

        effective_guid = process_guid if self.use_process_guid else ""

        for epoch in self.epochs[pid]:
            if epoch.is_active_at(
                target_dt,
                process_name,
                process_guid=effective_guid
            ):
                return True

        return False

    def get_active_epoch(
        self,
        pid: int,
        timestamp_str: str,
        process_guid: str = ""
    ) -> Optional[ProcessEpoch]:

        if not self.use_lifetime_validation:
            for epoch in self.epochs.get(pid, []):
                return epoch

        if not timestamp_str or pid not in self.epochs:
            return None

        target_dt = Normalizer.try_parse_complete_datetime(timestamp_str)

        if target_dt is None:
            return None

        effective_guid = process_guid if self.use_process_guid else ""

        for epoch in self.epochs[pid]:
            if epoch.is_active_at(
                target_dt,
                process_guid=effective_guid
            ):
                return epoch

        return None

    def find_by_guid(self, process_guid: str) -> Optional[ProcessEpoch]:
        if not process_guid:
            return None

        needle = process_guid.strip().lower()

        for epochs in self.epochs.values():
            for ep in epochs:
                if ep.process_guid and ep.process_guid.lower() == needle:
                    return ep

        return None


class ProcessCorrelator:

    @staticmethod
    def correlate_process_tree(
        events: List[NormalizedEvent],
        case_id: str,
        tracker: ProcessLifetimeTracker,
        window_seconds: float = 30.0
    ) -> List[EventRelationship]:

        relationships: List[EventRelationship] = []

        proc_events = [
            e for e in events
            if e.source == "process" and e.pid is not None
        ]

        child_candidates = [
            e for e in proc_events
            if e.event_type.upper() in {"PROCESS_START", "PROCESS_CREATE"}
            and e.ppid is not None
        ]

        by_pid: Dict[int, List[NormalizedEvent]] = {}

        for pe in proc_events:
            by_pid.setdefault(pe.pid, []).append(pe)

        for child in child_candidates:
            parent_pid = child.ppid

            if parent_pid not in by_pid or not child.timestamp:
                continue

            child_dt = Normalizer.try_parse_complete_datetime(child.timestamp)

            if child_dt is None:
                continue

            parent_candidates = by_pid[parent_pid]
            parent_evidence: Dict[str, NormalizedEvent] = {}

            parent_epoch = tracker.get_active_epoch(
                parent_pid,
                child.timestamp
            )

            if parent_epoch:
                for candidate in parent_candidates:
                    if not candidate.timestamp:
                        continue

                    candidate_type = candidate.event_type.upper()

                    if candidate_type == "PROCESS_CREATE":
                        try:
                            created_pid = int(
                                (candidate.metadata or {}).get("created_pid")
                            )
                        except (TypeError, ValueError):
                            continue

                        if created_pid != child.pid or candidate.pid != parent_pid:
                            continue

                    elif candidate_type != "PROCESS_START":
                        continue

                    candidate_dt = Normalizer.try_parse_complete_datetime(
                        candidate.timestamp
                    )

                    if candidate_dt is None or candidate_dt > child_dt:
                        continue

                    if candidate.event_id == parent_epoch.start_event_id:
                        parent_evidence[candidate.event_id] = candidate

                    elif (
                        candidate_type == "PROCESS_CREATE"
                        and (child_dt - candidate_dt).total_seconds() <= window_seconds
                    ):
                        parent_evidence[candidate.event_id] = candidate

                if parent_epoch.is_explicit_start:
                    parent_start = next(
                        (
                            candidate
                            for candidate in parent_candidates
                            if candidate.event_id == parent_epoch.start_event_id
                        ),
                        None
                    )

                    if parent_start:
                        parent_evidence[parent_start.event_id] = parent_start

            for parent_event in parent_evidence.values():
                parent_create_evidence = (
                    parent_event.event_type.upper() == "PROCESS_CREATE"
                )

                child_create_evidence = (
                    child.event_type.upper() == "PROCESS_CREATE"
                )

                if child_create_evidence:
                    explanation = (
                        f"Child Process Create evidence for PID {child.pid} "
                        f"explicitly reports Parent PID {child.ppid}. "
                        f"Parent PID {parent_pid} was matched to its recorded "
                        f"process instance and validated against its active epoch."
                    )

                elif parent_create_evidence:
                    explanation = (
                        f"Parent Process Create evidence explicitly names child PID {child.pid}; "
                        f"the child start record confirms Parent PID {child.ppid}, "
                        f"and the parent lifetime was validated."
                    )

                else:
                    explanation = (
                        f"Parent process start evidence for PID {parent_pid} "
                        f"and child start evidence for PID {child.pid} "
                        f"(reported PPID {child.ppid}) were validated within "
                        f"the active process epoch."
                    )

                explanation = (
                    f"{explanation} Parent process: '{parent_event.process_name}'. "
                    f"Child process: '{child.process_name}'."
                )

                rel = EventRelationship(
                    source_event_id=parent_event.event_id,
                    target_event_id=child.event_id,
                    relationship_type="SPAWNED",
                    confidence_score=(
                        0.98
                        if (parent_create_evidence or child_create_evidence)
                        else 0.95
                    ),
                    correlation_method=(
                        "Procmon Process Create Parent PID & Lifetime Validation"
                        if child_create_evidence
                        else "Parent Process Create & Child PID-PPID Lifetime Validation"
                        if parent_create_evidence
                        else "Explicit PID-PPID Lineage & Lifetime Validation"
                    ),
                    supporting_identifiers=[
                        f"ParentPID:{parent_event.pid}",
                        f"ChildPID:{child.pid}",
                        f"ReportedPPID:{child.ppid}"
                    ],
                    evidence_sources=[
                        parent_event.source,
                        child.source
                    ],
                    explanation=explanation,
                    relationship_category="Directly observed",
                    case_id=case_id
                )

                relationships.append(rel)

        return relationships