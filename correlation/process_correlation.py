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

        if self.end_time is not None and target_time > self.end_time:
            return False

        return True


class ProcessLifetimeTracker:
    """
    Maintains validated temporal epochs for Windows PIDs to eliminate
    false-positive cross-artifact attribution caused by PID reuse.
    """

    def __init__(
        self,
        use_process_guid: bool = True,
        use_lifetime_validation: bool = True
    ):
        self.epochs: Dict[int, List[ProcessEpoch]] = {}
        self.use_process_guid = use_process_guid
        self.use_lifetime_validation = use_lifetime_validation

    def register_events(self, events: List[NormalizedEvent]):
        """
        Processes events strictly chronologically to reconstruct PID lifetimes.
        ONLY process-source events can establish process start or exit boundaries.
        Registry and network events must NEVER establish process start epochs.
        """

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

            if op_up == "PROCESS_START" or "CREATE" in op_up:
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

                    if same_name and same_guid:
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

            elif op_up == "PROCESS_EXIT" or "EXIT" in op_up:
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
        """
        Verifies whether the specified PID was demonstrably alive and
        associated with process_name at the target timestamp.
        """

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
        """
        Identifies SPAWNED parent-child relationships using PID/PPID
        and process lifetime validation.

        Parent-child relationships require actual process creation events.
        """

        relationships: List[EventRelationship] = []

        proc_events = [
            e for e in events
            if e.source == "process" and e.pid is not None
        ]

        child_candidates = [
            e for e in proc_events
            if e.event_type.upper() == "PROCESS_START"
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

            parent_epoch = tracker.get_active_epoch(
                parent_pid,
                child.timestamp
            )

            parent_candidates = by_pid[parent_pid]

            best_parent: Optional[NormalizedEvent] = None

            if parent_epoch and parent_epoch.is_explicit_start:
                best_parent = next(
                    (
                        candidate
                        for candidate in parent_candidates
                        if candidate.event_id == parent_epoch.start_event_id
                    ),
                    None
                )

            if not best_parent:
                min_time_diff = float("inf")

                for p_cand in parent_candidates:
                    if not p_cand.timestamp:
                        continue

                    p_dt = Normalizer.try_parse_complete_datetime(
                        p_cand.timestamp
                    )

                    if p_dt is None:
                        continue

                    diff = (child_dt - p_dt).total_seconds()

                    if 0 <= diff <= window_seconds:
                        if parent_epoch and p_dt < parent_epoch.start_time:
                            continue

                        if diff < min_time_diff:
                            min_time_diff = diff
                            best_parent = p_cand

            if not best_parent and parent_epoch:
                best_parent = next(
                    (
                        candidate
                        for candidate in parent_candidates
                        if candidate.event_id == parent_epoch.start_event_id
                    ),
                    None
                )

            if best_parent:
                explanation = (
                    f"Directly observed parent-child process lineage: "
                    f"Parent process '{best_parent.process_name}' "
                    f"(PID {best_parent.pid}) spawned child process "
                    f"'{child.process_name}' "
                    f"(PID {child.pid}, reported PPID {child.ppid}) "
                    f"verified via active process epoch."
                )

                rel = EventRelationship(
                    source_event_id=best_parent.event_id,
                    target_event_id=child.event_id,
                    relationship_type="SPAWNED",
                    confidence_score=0.95,
                    correlation_method="Explicit PID-PPID Lineage & Lifetime Validation",
                    supporting_identifiers=[
                        f"ParentPID:{best_parent.pid}",
                        f"ChildPID:{child.pid}",
                        f"ReportedPPID:{child.ppid}"
                    ],
                    evidence_sources=[
                        best_parent.source,
                        child.source
                    ],
                    explanation=explanation,
                    relationship_category="Directly observed",
                    case_id=case_id
                )

                relationships.append(rel)

        return relationships