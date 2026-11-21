"""
Network Correlation Engine for U-15 Incident Reconstruction.

Attribution sources:
1. Sysmon Event ID 3 (process network connection telemetry) with ProcessGuid.
2. Wireshark / PCAP packet evidence.
3. Exact five-tuple matching (forward and reverse).
4. ProcessGuid and PID lifetime validation.
5. Complete timestamp validation.

Procmon does not provide TCP/UDP network connection telemetry for this engine.
Wireshark packets are never attributed to a process using timestamps alone.
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

        # 1. Directly observed: Sysmon EID 3 bound to process via ProcessGuid (preferred) or PID lifetime
        for ep_net in sysmon_net:
            if not use_five_tuple_matching:
                continue
            guid = event_process_guid(ep_net)
            p_cand: Optional[NormalizedEvent] = None
            if guid and guid.lower() in by_guid:
                for pe in by_guid[guid.lower()]:
                    if pe.event_id != ep_net.event_id:
                        p_cand = pe
                        break
            if not p_cand and ep_net.pid is not None and ep_net.pid in by_pid:
                if not ep_net.timestamp:
                    continue
                for pe in by_pid[ep_net.pid]:
                    if pe.event_id == ep_net.event_id:
                        continue
                    if not tracker.is_pid_active(
                        ep_net.pid, pe.process_name, ep_net.timestamp, process_guid=guid
                    ):
                        continue
                    if pe.process_name and ep_net.process_name and pe.process_name.lower() != ep_net.process_name.lower():
                        continue
                    p_cand = pe
                    break

            if not p_cand:
                continue

            transport = ep_net.protocol or "socket"
            tuple_desc = ""
            if cls._is_valid_five_tuple(ep_net):
                tuple_desc = f"{ep_net.src_ip}:{ep_net.src_port} -> {ep_net.dst_ip}:{ep_net.dst_port}"
            guid_note = f" ProcessGuid {guid}." if guid else " ProcessGuid not present; PID lifetime used."
            explanation = (
                f"Directly observed Sysmon Event ID 3: Process '{ep_net.process_name or p_cand.process_name}' "
                f"(PID {ep_net.pid}) initiated {transport} activity {tuple_desc}.{guid_note}"
            )
            supporting = [f"SysmonEventID:3"]
            if guid:
                supporting.append(f"ProcessGuid:{guid}")
            if ep_net.pid is not None:
                supporting.append(f"PID:{ep_net.pid}")
            if tuple_desc:
                supporting.append(f"Socket:{tuple_desc}")

            relationships.append(EventRelationship(
                source_event_id=p_cand.event_id,
                target_event_id=ep_net.event_id,
                relationship_type="CONNECTED_TO",
                confidence_score=0.95,
                correlation_method="Sysmon Event ID 3 Process Network Telemetry",
                supporting_identifiers=supporting,
                evidence_sources=["process", "network"],
                explanation=explanation,
                relationship_category="Directly observed",
                case_id=case_id
            ))

        # 2. Strongly supported: Sysmon EID 3 to Wireshark via exact 5-tuple + timestamp validation
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
                        if epoch else None
                    )
                    if process_event is not None:
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

        # 3. Packets without Sysmon 5-tuple corroboration are unattributed.
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
