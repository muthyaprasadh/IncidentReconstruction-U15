"""
Evidence Graph Builder for U-15 Incident Reconstruction.
Constructs a NetworkX MultiDiGraph representing cross-artifact entities (Processes,
Registry keys, Files, Network sockets, Events) and explainable forensic edges.
"""
import networkx as nx
import json
from typing import List, Dict, Any, Optional, Tuple
from database.models import NormalizedEvent, EventRelationship
from config.settings import logger

# Visual styling presets for forensic entities
NODE_STYLES = {
    "process": {"color": "#E53E3E", "shape": "box", "icon": "desktop"},          # Red
    "registry": {"color": "#D69E2E", "shape": "diamond", "icon": "database"},    # Amber/Yellow
    "network": {"color": "#3182CE", "shape": "dot", "icon": "globe"},            # Blue
    "file": {"color": "#38A169", "shape": "triangle", "icon": "file"},           # Green
    "event": {"color": "#805AD5", "shape": "ellipse", "icon": "clock"}           # Purple
}

EDGE_STYLES = {
    "Directly observed": {"color": "#38A169", "dashes": False, "width": 3},
    "Strongly supported": {"color": "#3182CE", "dashes": False, "width": 2},
    "Temporal association": {"color": "#ED8936", "dashes": True, "width": 1.5},
    "Inferred": {"color": "#9F7AEA", "dashes": True, "width": 1.5},
    "Unknown": {"color": "#A0AEC0", "dashes": True, "width": 1}
}

class EvidenceGraphBuilder:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.graph = nx.MultiDiGraph()

    def build_graph(
        self,
        events: List[Dict[str, Any]],
        relationships: List[Dict[str, Any]]
    ) -> nx.MultiDiGraph:
        """
        Builds the MultiDiGraph from raw event dicts and relationship records.
        """
        self.graph.clear()
        event_dict = {e["event_id"]: e for e in events}

        # 1. Add Entity and Event Nodes
        for e in events:
            ev_id = e["event_id"]
            source = e["source"]
            ts = e["timestamp"]
            evidence_reference = ":".join(
                str(value)
                for value in (e.get("evidence_file"), e.get("evidence_reference"))
                if value
            )
            provenance = [evidence_reference] if evidence_reference else []
            attribution = {
                "relationship_category": "Directly observed",
                "correlation_method": "normalized_event_attributes",
                "supporting_identifiers": provenance,
                "explanation": (
                    f"Entity attributes are present in {evidence_reference}."
                    if evidence_reference else
                    f"Entity attributes are present in normalized event {ev_id}."
                ),
                "title": (
                    f"[Directly observed] Entity attributes from "
                    f"{evidence_reference or ev_id}"
                ),
                **EDGE_STYLES["Directly observed"],
            }

            # Add specific Entity nodes representing forensics artifacts
            # Process Node
            if e.get("process_name") or e.get("pid") is not None:
                proc_label = e.get("process_name") or "unknown.exe"
                pid_str = f"PID:{e['pid']}" if e.get("pid") is not None else "PID:?"
                proc_node_id = f"proc:{proc_label}:{e.get('pid', 'any')}"
                if not self.graph.has_node(proc_node_id):
                    self.graph.add_node(
                        proc_node_id,
                        label=f"{proc_label}\n({pid_str})",
                        node_type="process",
                        entity_name=proc_label,
                        pid=e.get("pid"),
                        timestamp=ts,
                        evidence_file=e.get("evidence_file", ""),
                        title=f"Process: {proc_label} | {pid_str}\nObserved: {ts}",
                        **NODE_STYLES["process"]
                    )
                # Link event to entity
                self.graph.add_edge(
                    ev_id,
                    proc_node_id,
                    relationship_type="ATTRIBUTED_TO",
                    confidence_score=1.0,
                    **attribution
                )

            # Registry Node
            if e.get("registry_key"):
                reg_key = e["registry_key"]
                reg_node_id = f"reg:{reg_key}"
                if not self.graph.has_node(reg_node_id):
                    self.graph.add_node(
                        reg_node_id,
                        label=f"Reg:\n{reg_key[-30:] if len(reg_key)>30 else reg_key}",
                        node_type="registry",
                        key=reg_key,
                        timestamp=ts,
                        evidence_file=e.get("evidence_file", ""),
                        title=f"Registry Key:\n{reg_key}",
                        **NODE_STYLES["registry"]
                    )
                self.graph.add_edge(
                    ev_id,
                    reg_node_id,
                    relationship_type="TARGETS_KEY",
                    confidence_score=1.0,
                    **attribution
                )

            # Network Socket / IP Node
            if e.get("dst_ip") or (e.get("src_ip") and source == "network"):
                dst_socket = f"{e.get('dst_ip')}:{e.get('dst_port') or ''}".rstrip(":")
                net_node_id = f"net:{dst_socket}"
                if not self.graph.has_node(net_node_id):
                    self.graph.add_node(
                        net_node_id,
                        label=f"Net:\n{dst_socket}",
                        node_type="network",
                        socket=dst_socket,
                        protocol=e.get("protocol", "TCP"),
                        timestamp=ts,
                        evidence_file=e.get("evidence_file", ""),
                        title=f"Network Socket: {dst_socket} ({e.get('protocol')})",
                        **NODE_STYLES["network"]
                    )
                self.graph.add_edge(
                    ev_id,
                    net_node_id,
                    relationship_type="TARGETS_SOCKET",
                    confidence_score=1.0,
                    **attribution
                )

            # File Node
            if e.get("file_path") and e.get("event_type", "").startswith("FILE_"):
                f_path = e["file_path"]
                file_name = f_path.replace("/", "\\").split("\\")[-1]
                file_node_id = f"file:{f_path}"
                if not self.graph.has_node(file_node_id):
                    self.graph.add_node(
                        file_node_id,
                        label=f"File:\n{file_name}",
                        node_type="file",
                        path=f_path,
                        timestamp=ts,
                        evidence_file=e.get("evidence_file", ""),
                        title=f"File: {f_path}",
                        **NODE_STYLES["file"]
                    )
                self.graph.add_edge(
                    ev_id,
                    file_node_id,
                    relationship_type="ACCESSES_FILE",
                    confidence_score=1.0,
                    **attribution
                )

            # Add Event Node
            style = NODE_STYLES.get(source, NODE_STYLES["event"])
            ev_label = f"[{source.upper()}]\n{e.get('event_type')}\n{ts[11:19]}"
            self.graph.add_node(
                ev_id,
                label=ev_label,
                node_type="event",
                source=source,
                event_type=e.get("event_type"),
                timestamp=ts,
                evidence_reference=e.get("evidence_reference", ""),
                title=(
                    f"Event ID: {ev_id}\nSource: {source}\nType: {e.get('event_type')}\n"
                    f"Time: {ts}\nRef: {e.get('evidence_reference')}"
                ),
                **style
            )

        # 2. Add Inferred and Observed Cross-Artifact Edges from Relationships
        for rel in relationships:
            src_id = rel["source_event_id"]
            tgt_id = rel["target_event_id"]

            if not self.graph.has_node(src_id) or not self.graph.has_node(tgt_id):
                continue

            rel_type = rel.get("relationship_type", "RELATED_TO")
            category = rel.get("relationship_category", "Unknown")
            conf = float(rel.get("confidence_score", 0.5))
            style = EDGE_STYLES.get(category, EDGE_STYLES["Unknown"])

            explanation = rel.get("explanation", "")
            method = rel.get("correlation_method", "")
            supp = rel.get("supporting_identifiers", [])

            self.graph.add_edge(
                src_id,
                tgt_id,
                key=f"{rel_type}_{src_id}_{tgt_id}",
                relationship_type=rel_type,
                relationship_category=category,
                confidence_score=conf,
                correlation_method=method,
                supporting_identifiers=supp,
                explanation=explanation,
                title=f"[{category}] {rel_type}\nConf: {conf:.2f}\n{explanation}",
                **style
            )

        logger.info(
            "Evidence Graph built: %d nodes, %d edges for case '%s'",
            self.graph.number_of_nodes(), self.graph.number_of_edges(), self.case_id
        )
        return self.graph

    def to_json_dict(self) -> Dict[str, Any]:
        """Serializes graph to JSON-friendly node/edge dict."""
        nodes = []
        for n, data in self.graph.nodes(data=True):
            node_copy = dict(data)
            node_copy["id"] = n
            nodes.append(node_copy)

        edges = []
        for u, v, key, data in self.graph.edges(keys=True, data=True):
            edge_copy = dict(data)
            edge_copy["source"] = u
            edge_copy["target"] = v
            edge_copy["key"] = key
            edges.append(edge_copy)

        return {"nodes": nodes, "edges": edges}
