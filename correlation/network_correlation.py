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
        for pe in proc_events:
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
                for pe in by_pid[ep_net.pid]:
                    if pe.event_id == ep_net.event_id:
                        continue
                    if ep_net.timestamp and not tracker.is_pid_active(
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
            ep_dt = Normalizer.try_parse_complete_datetime(ep_net.timestamp)
            if ep_dt is None:
                continue
            if not cls._is_valid_five_tuple(ep_net):
                continue

            for wire in wire_net:
                wire_dt = Normalizer.try_parse_complete_datetime(wire.timestamp)
                if wire_dt is None:
                    continue
                diff = abs((wire_dt - ep_dt).total_seconds())
                if diff > window_seconds:
                    continue
                is_match, direction = cls._matches_five_tuple(ep_net, wire)
                if not is_match:
                    continue

                frame_ref = wire.metadata.get("frame_number", wire.evidence_reference)
                dir_desc = "Outbound forward packet" if direction == "forward" else "Inbound reverse reply packet"
                guid = event_process_guid(ep_net)
                explanation = (
                    f"Strongly supported 5-tuple corroboration: Sysmon Event ID 3 from process "
                    f"'{ep_net.process_name}' (PID {ep_net.pid}"
                    f"{', ProcessGuid ' + guid if guid else ''}) verified on wire via packet {frame_ref} "
                    f"({dir_desc}: {wire.src_ip}:{wire.src_port} -> {wire.dst_ip}:{wire.dst_port} {wire.protocol}) "
                    f"with timestamp delta {diff:.3f}s."
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
                        f"Delta:{diff:.3f}s"
                    ],
                    evidence_sources=["sysmon", "network"],
                    explanation=explanation,
                    relationship_category="Strongly supported",
                    case_id=case_id
                ))

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
