"""
Incident Timeline Generator for U-15 Incident Reconstruction.
Generates an enriched chronological incident timeline with cross-artifact relationships,
supporting evidence provenance, and clear separation between empirical observation and inference.
"""
from typing import List, Dict, Any, Optional
from datetime import datetime
from dateutil import parser as date_parser

class TimelineGenerator:
    def __init__(self, events: List[Any], relationships: List[Any]):
        def _to_d(x):
            if hasattr(x, "to_dict"):
                return x.to_dict()
            if isinstance(x, dict):
                return x
            try:
                return dict(x)
            except Exception:
                return x.__dict__

        self.events = sorted([_to_d(e) for e in events], key=lambda x: x.get("timestamp", ""))
        self.relationships = [_to_d(r) for r in relationships]

    def generate_timeline(self) -> List[Dict[str, Any]]:
        """
        Produces chronological timeline entries annotated with related cross-artifact links.
        """
        # Map event_id -> list of incoming and outgoing relationships
        rel_map: Dict[str, List[Dict[str, Any]]] = {}
        for r in self.relationships:
            src = r["source_event_id"]
            tgt = r["target_event_id"]
            rel_map.setdefault(src, []).append({
                "direction": "outgoing",
                "target_id": tgt,
                "type": r["relationship_type"],
                "category": r["relationship_category"],
                "confidence": r["confidence_score"],
                "explanation": r["explanation"]
            })
            rel_map.setdefault(tgt, []).append({
                "direction": "incoming",
                "source_id": src,
                "type": r["relationship_type"],
                "category": r["relationship_category"],
                "confidence": r["confidence_score"],
                "explanation": r["explanation"]
            })

        timeline_entries: List[Dict[str, Any]] = []

        for ev in self.events:
            ev_id = ev["event_id"]
            ts = ev.get("timestamp", "")
            
            # Format display time
            try:
                dt = date_parser.parse(ts)
                display_time = dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            except Exception:
                display_time = ts

            source = ev.get("source", "unknown")
            ev_type = ev.get("event_type", "")
            proc = ev.get("process_name", "")
            pid = ev.get("pid")
            reg_key = ev.get("registry_key", "")
            reg_op = ev.get("registry_operation", "")
            dst_ip = ev.get("dst_ip", "")
            dst_port = ev.get("dst_port")
            proto = ev.get("protocol", "")
            file_p = ev.get("file_path", "")
            evidence_file = ev.get("evidence_file", "")
            evidence_ref = ev.get("evidence_reference", "")

            # Formulate human-readable description
            description, obs_type = self._formulate_event_summary(ev)

            # Gather linked relationships
            links = rel_map.get(ev_id, [])

            timeline_entries.append({
                "event_id": ev_id,
                "timestamp": ts,
                "display_time": display_time,
                "source": source,
                "event_type": ev_type,
                "process_name": proc,
                "pid": pid,
                "registry_operation": reg_op,
                "registry_key": reg_key,
                "network_destination": f"{dst_ip}:{dst_port}" if dst_ip else "",
                "protocol": proto,
                "file_path": file_p,
                "description": description,
                "observation_type": obs_type,  # 'Empirical Observation' or 'Correlated Context'
                "evidence_provenance": f"{evidence_file} ({evidence_ref})",
                "related_links": links,
                "link_count": len(links),
                "raw_metadata": ev.get("metadata", {})
            })

        return timeline_entries

    def _formulate_event_summary(self, ev: Dict[str, Any]) -> tuple[str, str]:
        source = ev.get("source", "")
        ev_type = ev.get("event_type", "")
        proc = ev.get("process_name") or "unknown"
        pid_s = f"(PID {ev.get('pid')})" if ev.get("pid") is not None else ""

        if source == "process":
            if ev_type == "PROCESS_START":
                ppid_s = f" [Parent PID {ev.get('ppid')}]" if ev.get("ppid") else ""
                return f"Process '{proc}' {pid_s} was started{ppid_s}.", "Empirical Observation"
            elif ev_type == "PROCESS_EXIT":
                return f"Process '{proc}' {pid_s} terminated.", "Empirical Observation"
            elif ev_type.startswith("FILE_"):
                return f"Process '{proc}' {pid_s} accessed file '{ev.get('file_path')}'.", "Empirical Observation"
            return f"Process '{proc}' {pid_s} executed activity {ev_type}.", "Empirical Observation"

        elif source == "registry":
            reg_op = ev.get("registry_operation") or ev_type
            key = ev.get("registry_key", "Key")
            meta = ev.get("metadata", {})
            val_name = meta.get("value_name", "")
            val_data = meta.get("value_data", "")
            detail = f" [Value: '{val_name}' = '{val_data}']" if val_name else ""
            if ev.get("pid"):
                return f"Process '{proc}' {pid_s} executed {reg_op} on Registry '{key}'{detail}.", "Empirical Observation"
            return f"Registry operation {reg_op} observed on '{key}'{detail}.", "Empirical Observation"

        elif source == "network":
            dst = f"{ev.get('dst_ip')}:{ev.get('dst_port')}" if ev.get("dst_ip") else "remote host"
            proto = ev.get("protocol", "TCP")
            meta = ev.get("metadata", {})
            info = meta.get("info", "")
            if ev.get("pid"):
                return f"Process '{proc}' {pid_s} established {proto} socket to {dst} ({info}).", "Empirical Observation"
            return f"Network packet captured: {ev.get('src_ip')} -> {dst} ({proto}) - {info}.", "Empirical Observation"

        return f"Event {ev_type} observed.", "Empirical Observation"
