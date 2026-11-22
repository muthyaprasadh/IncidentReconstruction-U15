"""
Network Correlation Engine for U-15 Incident Reconstruction.

Attribution sources:
1. Sysmon Event ID 3 (process network connection telemetry) with ProcessGuid.
2. Procmon TCP/UDP operation events attributed by PID and process lifetime.
3. Wireshark / PCAP packet evidence.
4. Exact five-tuple matching (forward and reverse).
5. ProcessGuid and PID lifetime validation.
6. Complete timestamp validation.

Procmon operation events are not treated as Sysmon socket telemetry or as a
substitute for complete five-tuple evidence. Wireshark packets are never
attributed to a process using timestamps alone.
"""
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from database.models import NormalizedEvent, EventRelationship
from correlation.process_correlation import ProcessLifetimeTracker, event_process_guid
from normalization.normalizer import Normalizer
from config.settings import logger


def _is_sysmon_network(ev: NormalizedEvent) -> bool:
    meta = ev.metadata or {}
    if meta.get("sysmon_event_id") == 3 or meta.get("network_telemetry") == "sysmon_event_id_3":
        return True
    return False


def _is_wire_packet(ev: NormalizedEvent) -> bool:
    if ev.source != "network":
        return False
    if _is_sysmon_network(ev):
        return False
    return ev.event_type.upper() in ("NET_PACKET", "PACKET") or ev.pid is None


def _sysmon_timestamp_window(
    event: NormalizedEvent
) -> Optional[Tuple[datetime, datetime, bool]]:
    timestamp = Normalizer.try_parse_complete_datetime(event.timestamp)
    if timestamp is not None:
        return timestamp, timestamp, False

    metadata = event.metadata or {}
    start = Normalizer.try_parse_complete_datetime(
        metadata.get("timestamp_uncertainty_start")
    )
    end = Normalizer.try_parse_complete_datetime(
        metadata.get("timestamp_uncertainty_end")
    )
    if start is None or end is None or start > end:
        return None
    return start, end, True


class NetworkCorrelator:
    last_unattributed_event_ids: List[str] = []

    @staticmethod
    def _is_valid_five_tuple(ev: NormalizedEvent) -> bool:
        """Verifies that all five components of the transport tuple are explicitly present."""
        return bool(
            ev.src_ip and ev.dst_ip and
            ev.src_port is not None and ev.dst_port is not None and
            ev.protocol and ev.protocol != "UNKNOWN"
        )

    @staticmethod
    def _matches_five_tuple(ep: NormalizedEvent, wire: NormalizedEvent) -> Tuple[bool, str]:
        """
        Performs strict five-tuple matching across transport layer.
        Returns: (is_match, direction) where direction is 'forward' or 'reverse'.
        No wildcards: both sides must have a complete 5-tuple.
        """
        if not NetworkCorrelator._is_valid_five_tuple(ep) or not NetworkCorrelator._is_valid_five_tuple(wire):
            return False, ""

        ep_transport = ep.protocol.upper()
        wire_transport = wire.protocol.upper()
        if ep_transport != wire_transport:
            return False, ""

        if (ep.src_ip == wire.src_ip and
            ep.dst_ip == wire.dst_ip and
            ep.src_port == wire.src_port and
            ep.dst_port == wire.dst_port):
            return True, "forward"

        if (ep.src_ip == wire.dst_ip and
            ep.dst_ip == wire.src_ip and
            ep.src_port == wire.dst_port and
            ep.dst_port == wire.src_port):
            return True, "reverse"

        return False, ""

    @classmethod
    def correlate_network_events(
        cls,
        events: List[NormalizedEvent],
        case_id: str,
        tracker: ProcessLifetimeTracker,
        window_seconds: float = 5.0,
        use_five_tuple_matching: bool = True,
    ) -> List[EventRelationship]:
        relationships: List[EventRelationship] = []
        cls.last_unattributed_event_ids = []

        sysmon_net = [e for e in events if _is_sysmon_network(e)]
        wire_net = [e for e in events if _is_wire_packet(e)]
        proc_events = [e for e in events if e.source == "process"]

        by_guid: Dict[str, List[NormalizedEvent]] = {}
        by_pid: Dict[int, List[NormalizedEvent]] = {}
        events_by_id: Dict[str, NormalizedEvent] = {}
        for pe in proc_events:
            events_by_id[pe.event_id] = pe
            guid = event_process_guid(pe)
            if guid:
                by_guid.setdefault(guid.lower(), []).append(pe)
            if pe.pid is not None:
                by_pid.setdefault(pe.pid, []).append(pe)

        # 1. Procmon records the acting PID for TCP/UDP operations. Attribute
        # those records only to an active, explicitly started process epoch.
        procmon_connects = [
            e for e in proc_events
            if e.event_type.upper() in ("TCP_CONNECT", "UDP_CONNECT")
        ]
        for connection in procmon_connects:
            if connection.pid is None or not connection.timestamp:
                continue
            connection_dt = Normalizer.try_parse_complete_datetime(connection.timestamp)
            if connection_dt is None:
                continue

            guid = event_process_guid(connection)
            epoch = tracker.get_active_epoch(
                connection.pid,
                connection.timestamp,
                process_guid=guid
            )
            if (
                epoch is None
                or not epoch.is_explicit_start
                or not tracker.is_pid_active(
                    connection.pid,
                    connection.process_name,
                    connection.timestamp,
                    process_guid=guid
                )
            ):
                continue

            same_artifact_starts = []
            if connection.evidence_file:
                for candidate in by_pid.get(connection.pid, []):
                    if (
                        candidate.event_type.upper() != "PROCESS_START"
                        or candidate.evidence_file != connection.evidence_file
                        or not candidate.timestamp
                    ):
                        continue
                    candidate_dt = Normalizer.try_parse_complete_datetime(candidate.timestamp)
                    if (
                        candidate_dt is None
                        or candidate_dt < epoch.start_time
                        or candidate_dt > connection_dt
                    ):
                        continue
                    if candidate.process_name and connection.process_name and (
                        candidate.process_name.lower() != connection.process_name.lower()
                    ):
                        continue
                    same_artifact_starts.append((candidate_dt, candidate))

            process_event = (
                max(same_artifact_starts, key=lambda item: item[0])[1]
                if same_artifact_starts
                else events_by_id.get(epoch.start_event_id)
            )
            if process_event is None:
                continue

            operation = (connection.metadata or {}).get("raw_operation") or connection.event_type
            destination = (
                f"{connection.dst_ip}:{connection.dst_port}"
                if connection.dst_ip and connection.dst_port is not None
                else ""
            )
            relationships.append(EventRelationship(
                source_event_id=process_event.event_id,
                target_event_id=connection.event_id,
                relationship_type="CONNECTED_TO",
                confidence_score=0.95 if same_artifact_starts else 0.90,
                correlation_method="Procmon PID and Process-Lifetime Attribution",
                supporting_identifiers=[
                    f"PID:{connection.pid}",
                    f"Operation:{operation}",
                    f"EvidenceReference:{connection.evidence_reference}",
                    *([f"Destination:{destination}"] if destination else [])
                ],
                evidence_sources=["process", "procmon"],
                explanation=(
                    f"Procmon {operation} evidence records PID {connection.pid} "
                    f"('{connection.process_name}') connecting during its validated "
                    f"process epoch, supported by process event {process_event.event_id}."
                ),
                relationship_category="Directly observed",
                case_id=case_id
            ))

        # 2. Attribute Sysmon EID 3 only to a validated explicit process start.
        # Sysmon EID 3 is direct network telemetry; this edge records process
        # attribution and must not use an arbitrary Procmon operation as its source.
        for ep_net in sysmon_net:
            if ep_net.pid is None or not ep_net.timestamp:
                continue

            guid = event_process_guid(ep_net)
            epoch = tracker.get_active_epoch(
                ep_net.pid,
                ep_net.timestamp,
                process_guid=guid
            )

            if epoch is None or not epoch.is_explicit_start:
                continue

            process_event = events_by_id.get(epoch.start_event_id)
            if process_event is None:
                continue

            if process_event.event_type.upper() != "PROCESS_START":
                continue

            if process_event.pid != ep_net.pid:
                continue

            if (
                ep_net.process_name
                and process_event.process_name
                and ep_net.process_name.lower() != process_event.process_name.lower()
            ):
                continue

            process_guid = event_process_guid(process_event)
            if guid and process_guid and guid.lower() != process_guid.lower():
                continue

            transport = ep_net.protocol or "unknown transport"
            tuple_desc = ""
            if cls._is_valid_five_tuple(ep_net):
                tuple_desc = (
                    f"{ep_net.src_ip}:{ep_net.src_port} -> "
                    f"{ep_net.dst_ip}:{ep_net.dst_port}"
                )

            metadata = ep_net.metadata or {}
            initiated_value = metadata.get(
                "Initiated",
                metadata.get("initiated")
            )
            if isinstance(initiated_value, bool):
                initiated_value = str(initiated_value).lower()
            else:
                initiated_value = str(initiated_value or "").strip().lower()

            if initiated_value == "true":
                direction_note = "Sysmon marks the connection as initiated"
            elif initiated_value == "false":
                direction_note = "Sysmon marks the connection as not initiated"
            else:
                direction_note = "Sysmon does not specify the initiation direction"

            guid_verified = bool(
                guid and process_guid and guid.lower() == process_guid.lower()
            )
            attribution_method = (
                "ProcessGuid and Process Lifetime"
                if guid_verified
                else "PID and Process Lifetime"
            )

            process_name = ep_net.process_name or process_event.process_name or "unknown"
            socket_note = f" ({tuple_desc})" if tuple_desc else ""

            explanation = (
                f"Sysmon Event ID 3 records {transport} network activity"
                f"{socket_note} for process '{process_name}' (PID {ep_net.pid}). "
                f"{direction_note}. The process attribution is supported by "
                f"explicit process-start event {process_event.event_id} and "
                f"{attribution_method} validation."
            )

            supporting = [
                "SysmonEventID:3",
                f"PID:{ep_net.pid}",
                f"ProcessStartEvent:{process_event.event_id}",
                f"AttributionMethod:{attribution_method}"
            ]
            if guid:
                supporting.append(f"ProcessGuid:{guid}")
            if tuple_desc:
                supporting.append(f"Socket:{tuple_desc}")
            if initiated_value in ("true", "false"):
                supporting.append(f"Initiated:{initiated_value}")

            relationships.append(EventRelationship(
                source_event_id=process_event.event_id,
                target_event_id=ep_net.event_id,
                relationship_type="CONNECTED_TO",
                confidence_score=0.95 if guid_verified else 0.90,
                correlation_method=f"Sysmon Event ID 3 {attribution_method}",
                supporting_identifiers=supporting,
                evidence_sources=["process", "network"],
                explanation=explanation,
                relationship_category="Process attribution",
                case_id=case_id
            ))

        # 3. Strongly supported: Sysmon EID 3 to Wireshark via exact five-tuple and time.
        for ep_net in sysmon_net:
            timestamp_window = _sysmon_timestamp_window(ep_net)
            if timestamp_window is None:
                continue
            lower_time, upper_time, is_uncertain = timestamp_window
            if (
                is_uncertain
                and (upper_time - lower_time).total_seconds() > window_seconds
            ):
                continue
            if not cls._is_valid_five_tuple(ep_net):
                continue

            pid_attribution_created = False
            for wire in wire_net:
                wire_dt = Normalizer.try_parse_complete_datetime(wire.timestamp)
                if wire_dt is None:
                    continue
                if is_uncertain:
                    if not lower_time <= wire_dt <= upper_time:
                        continue
                else:
                    diff = abs((wire_dt - lower_time).total_seconds())
                    if diff > window_seconds:
                        continue
                is_match, direction = cls._matches_five_tuple(ep_net, wire)
                if not is_match:
                    continue

                frame_ref = wire.metadata.get("frame_number", wire.evidence_reference)
                dir_desc = "Outbound forward packet" if direction == "forward" else "Inbound reverse reply packet"
                guid = event_process_guid(ep_net)
                if is_uncertain:
                    time_note = (
                        f"packet time falls within Sysmon timestamp uncertainty "
                        f"interval [{lower_time.isoformat()}, {upper_time.isoformat()}]."
                    )
                    time_support = (
                        f"TimestampInterval:{lower_time.isoformat()}.."
                        f"{upper_time.isoformat()}"
                    )
                else:
                    time_note = f"timestamp delta {diff:.3f}s."
                    time_support = f"Delta:{diff:.3f}s"
                explanation = (
                    f"Strongly supported 5-tuple corroboration: Sysmon Event ID 3 from process "
                    f"'{ep_net.process_name}' (PID {ep_net.pid}"
                    f"{', ProcessGuid ' + guid if guid else ''}) verified on wire via packet {frame_ref} "
                    f"({dir_desc}: {wire.src_ip}:{wire.src_port} -> {wire.dst_ip}:{wire.dst_port} {wire.protocol}) "
                    f"at {wire_dt.isoformat()}; {time_note}"
                )
                relationships.append(EventRelationship(
                    source_event_id=ep_net.event_id,
                    target_event_id=wire.event_id,
                    relationship_type="OBSERVED_IN",
                    confidence_score=0.90,
                    correlation_method="Deterministic 5-Tuple Sysmon-to-Wire Corroboration",
                    supporting_identifiers=[
                        f"PID:{ep_net.pid}",
                        f"ProcessGuid:{guid}" if guid else "ProcessGuid:absent",
                        f"Direction:{direction}",
                        f"5Tuple:{wire.src_ip}:{wire.src_port}->{wire.dst_ip}:{wire.dst_port}|{wire.protocol}",
                        time_support
                    ],
                    evidence_sources=["sysmon", "network"],
                    explanation=explanation,
                    relationship_category="Strongly supported",
                    case_id=case_id
                ))

                if (
                    is_uncertain
                    and not guid
                    and ep_net.pid is not None
                    and not pid_attribution_created
                ):
                    epoch = tracker.get_active_epoch(
                        ep_net.pid,
                        wire.timestamp
                    )
                    process_event = (
                        events_by_id.get(epoch.start_event_id)
                        if epoch and epoch.is_explicit_start else None
                    )
                    if (
                        process_event is not None
                        and process_event.event_type.upper() == "PROCESS_START"
                        and process_event.pid == ep_net.pid
                    ):
                        relationships.append(EventRelationship(
                            source_event_id=process_event.event_id,
                            target_event_id=ep_net.event_id,
                            relationship_type="CONNECTED_TO",
                            confidence_score=0.90,
                            correlation_method=(
                                "Sysmon Event ID 3 PID Lifetime Validated at "
                                "Exact-Tuple Packet Time"
                            ),
                            supporting_identifiers=[
                                f"SysmonEventID:3",
                                f"PID:{ep_net.pid}",
                                f"WireFrame:{frame_ref}",
                                f"PIDValidatedAt:{wire_dt.isoformat()}",
                                f"TimestampInterval:{lower_time.isoformat()}.."
                                f"{upper_time.isoformat()}",
                                f"5Tuple:{ep_net.src_ip}:{ep_net.src_port}->"
                                f"{ep_net.dst_ip}:{ep_net.dst_port}|{ep_net.protocol}"
                            ],
                            evidence_sources=["process", "sysmon", "network"],
                            explanation=(
                                f"Sysmon Event ID 3 has no usable ProcessGuid and its "
                                f"timestamps are uncertain. The exact five-tuple was "
                                f"observed in packet {frame_ref} at {wire_dt.isoformat()}, "
                                f"when PID {ep_net.pid} belonged to process "
                                f"'{process_event.process_name}' in its validated process "
                                f"epoch; the packet time lies inside the Sysmon timestamp "
                                f"interval [{lower_time.isoformat()}, {upper_time.isoformat()}]."
                            ),
                            relationship_category="Strongly supported",
                            case_id=case_id
                        ))
                        pid_attribution_created = True

        # 4. Packets without Sysmon five-tuple corroboration are unattributed.
        # Do not bind Wireshark frames to processes using timestamps alone.
        corroborated_wire = {r.target_event_id for r in relationships if r.relationship_type == "OBSERVED_IN"}
        for wire in wire_net:
            if wire.event_id in corroborated_wire:
                continue
            cls.last_unattributed_event_ids.append(wire.event_id)

        logger.info(
            "Network correlation: %d relationships, %d unattributed packets",
            len(relationships), len(cls.last_unattributed_event_ids)
        )
        return relationships
