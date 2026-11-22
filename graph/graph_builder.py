import networkx as nx
from typing import List, Dict, Any
from config.settings import logger


NODE_STYLES = {
    "process": {"color": "#E53E3E", "shape": "box", "icon": "desktop"},
    "registry": {"color": "#D69E2E", "shape": "diamond", "icon": "database"},
    "network": {"color": "#3182CE", "shape": "dot", "icon": "globe"},
    "file": {"color": "#38A169", "shape": "triangle", "icon": "file"},
    "event": {"color": "#805AD5", "shape": "ellipse", "icon": "clock"}
}

EDGE_STYLES = {
    "Directly observed": {"color": "#38A169", "dashes": False, "width": 3},
    "Strongly supported": {"color": "#3182CE", "dashes": False, "width": 2},
    "Temporal association": {"color": "#ED8936", "dashes": True, "width": 1.5},
    "Unattributed": {"color": "#A0AEC0", "dashes": True, "width": 1},
    "Inferred": {"color": "#9F7AEA", "dashes": True, "width": 1.5},
    "Unknown": {"color": "#A0AEC0", "dashes": True, "width": 1}
}


class EvidenceGraphBuilder:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.graph = nx.MultiDiGraph()

    @staticmethod
    def _text(value: Any) -> str:
        if value is None:
            return ""
        return str(value).strip()

    @staticmethod
    def _safe_timestamp(value: Any) -> str:
        return str(value).strip() if value is not None else ""

    @staticmethod
    def _safe_confidence(value: Any, default: float = 0.5) -> float:
        try:
            confidence = float(value)
        except (TypeError, ValueError):
            return default

        if not 0.0 <= confidence <= 1.0:
            return default

        return confidence

    @staticmethod
    def _safe_identifiers(value: Any) -> List[str]:
        if value is None:
            return []

        if isinstance(value, (list, tuple, set)):
            return [str(item) for item in value if item is not None]

        return [str(value)]

    def _add_observation_edge(
        self,
        event_id: str,
        entity_id: str,
        relationship_type: str,
        evidence_reference: str,
        explanation: str
    ) -> None:
        self.graph.add_edge(
            event_id,
            entity_id,
            relationship_type=relationship_type,
            relationship_category="Directly observed",
            confidence_score=1.0,
            correlation_method="normalized_event_attributes",
            supporting_identifiers=[evidence_reference] if evidence_reference else [],
            explanation=explanation,
            title=f"[Directly observed] {relationship_type}\n{explanation}",
            **EDGE_STYLES["Directly observed"]
        )

    def _add_process_entity(self, event_id: str, event: Dict[str, Any], timestamp: str, evidence_reference: str) -> None:
        process_name = self._text(event.get("process_name"))
        pid = event.get("pid")
        process_guid = self._text(event.get("process_guid"))

        if not process_name and pid is None and not process_guid:
            return

        process_name = process_name or "unknown.exe"

        if process_guid:
            process_node_id = f"proc:guid:{process_guid}"
            identity_basis = "process_guid"
        elif pid is not None:
            process_node_id = f"proc:pid:{pid}:name:{process_name.lower()}"
            identity_basis = "pid_and_process_name"
        else:
            process_node_id = f"proc:observation:{event_id}"
            identity_basis = "event_specific_observation"

        pid_label = f"PID:{pid}" if pid is not None else "PID:?"
        guid_label = f"\nGUID:{process_guid}" if process_guid else ""

        if not self.graph.has_node(process_node_id):
            self.graph.add_node(
                process_node_id,
                label=f"{process_name}\n({pid_label})",
                node_type="process",
                entity_name=process_name,
                pid=pid,
                process_guid=process_guid,
                identity_basis=identity_basis,
                first_observed=timestamp,
                last_observed=timestamp,
                observation_count=0,
                evidence_references=[],
                title=f"Observed process context: {process_name} | {pid_label}{guid_label}\nObserved: {timestamp}\nIdentity basis: {identity_basis}",
                **NODE_STYLES["process"]
            )

        node = self.graph.nodes[process_node_id]
        node["observation_count"] += 1
        node["last_observed"] = timestamp or node.get("last_observed", "")

        if evidence_reference and evidence_reference not in node["evidence_references"]:
            node["evidence_references"].append(evidence_reference)

        self._add_observation_edge(
            event_id,
            process_node_id,
            "OBSERVED_PROCESS_CONTEXT",
            evidence_reference,
            "Process name, PID, or process GUID is recorded in this normalized event. This does not independently establish a validated process lifetime."
        )

    def _add_registry_entity(self, event_id: str, event: Dict[str, Any], timestamp: str, evidence_reference: str) -> None:
        registry_key = self._text(event.get("registry_key"))

        if not registry_key:
            return

        node_id = f"reg:{registry_key}"

        if not self.graph.has_node(node_id):
            self.graph.add_node(
                node_id,
                label=f"Reg:\n{registry_key[-30:]}",
                node_type="registry",
                key=registry_key,
                first_observed=timestamp,
                last_observed=timestamp,
                observation_count=0,
                evidence_references=[],
                title=f"Registry Key:\n{registry_key}",
                **NODE_STYLES["registry"]
            )

        node = self.graph.nodes[node_id]
        node["observation_count"] += 1
        node["last_observed"] = timestamp or node.get("last_observed", "")

        if evidence_reference and evidence_reference not in node["evidence_references"]:
            node["evidence_references"].append(evidence_reference)

        operation = self._text(event.get("registry_operation"))

        self._add_observation_edge(
            event_id,
            node_id,
            "OBSERVED_REGISTRY_TARGET",
            evidence_reference,
            f"Registry key is present in the normalized event. Operation: {operation or 'Not specified'}."
        )

    def _add_network_entity(
        self,
        event_id: str,
        event: Dict[str, Any],
        timestamp: str,
        evidence_reference: str
    ) -> None:
        source = self._text(event.get("source")).lower()
        protocol = self._text(event.get("protocol")).upper() or "Unknown"

        endpoints = [
            ("src", self._text(event.get("src_ip")), event.get("src_port")),
            ("dst", self._text(event.get("dst_ip")), event.get("dst_port"))
        ]

        for direction, ip, port in endpoints:
            if not ip:
                continue

            port_text = self._text(port)
            socket = f"{ip}:{port_text}" if port_text else ip
            node_id = f"net:{protocol}:{socket}"

            if not self.graph.has_node(node_id):
                self.graph.add_node(
                    node_id,
                    label=f"Net:\n{socket}",
                    node_type="network",
                    socket=socket,
                    ip=ip,
                    port=port,
                    protocol=protocol,
                    first_observed=timestamp,
                    last_observed=timestamp,
                    observation_count=0,
                    evidence_references=[],
                    title=f"Network Endpoint: {socket}\nProtocol: {protocol}",
                    **NODE_STYLES["network"]
                )

            node = self.graph.nodes[node_id]
            node["observation_count"] += 1
            node["last_observed"] = timestamp or node.get("last_observed", "")

            if evidence_reference and evidence_reference not in node["evidence_references"]:
                node["evidence_references"].append(evidence_reference)

            relationship_type = (
                "OBSERVED_SOURCE_ENDPOINT"
                if direction == "src"
                else "OBSERVED_DESTINATION_ENDPOINT"
            )

            self._add_observation_edge(
                event_id,
                node_id,
                relationship_type,
                evidence_reference,
                f"{direction.upper()} endpoint recorded in a {source or 'unknown'} event."
            )

    def _add_file_entity(self, event_id: str, event: Dict[str, Any], timestamp: str, evidence_reference: str) -> None:
        file_path = self._text(event.get("file_path"))
        event_type = self._text(event.get("event_type")).upper()

        if not file_path or not event_type.startswith("FILE_"):
            return

        normalized_path = file_path.replace("/", "\\")
        file_name = normalized_path.split("\\")[-1]
        node_id = f"file:{normalized_path}"

        if not self.graph.has_node(node_id):
            self.graph.add_node(
                node_id,
                label=f"File:\n{file_name}",
                node_type="file",
                path=normalized_path,
                first_observed=timestamp,
                last_observed=timestamp,
                observation_count=0,
                evidence_references=[],
                title=f"File: {normalized_path}",
                **NODE_STYLES["file"]
            )

        node = self.graph.nodes[node_id]
        node["observation_count"] += 1
        node["last_observed"] = timestamp or node.get("last_observed", "")

        if evidence_reference and evidence_reference not in node["evidence_references"]:
            node["evidence_references"].append(evidence_reference)

        self._add_observation_edge(
            event_id,
            node_id,
            "OBSERVED_FILE_TARGET",
            evidence_reference,
            "File path is recorded in the normalized event."
        )

    def build_graph(
        self,
        events: List[Dict[str, Any]],
        relationships: List[Dict[str, Any]]
    ) -> nx.MultiDiGraph:
        self.graph.clear()

        valid_event_ids = set()

        for event in events:
            event_id = self._text(event.get("event_id"))

            if not event_id:
                continue

            valid_event_ids.add(event_id)

            source = self._text(event.get("source")).lower() or "unknown"
            event_type = self._text(event.get("event_type")) or "UNKNOWN"
            timestamp = self._safe_timestamp(event.get("timestamp"))

            evidence_file = self._text(event.get("evidence_file"))
            evidence_row = self._text(event.get("evidence_reference"))

            evidence_reference = ":".join(
                value for value in (evidence_file, evidence_row) if value
            )

            time_label = timestamp[11:19] if len(timestamp) >= 19 else timestamp

            self.graph.add_node(
                event_id,
                label=f"[{source.upper()}]\n{event_type}\n{time_label}",
                node_type="event",
                source=source,
                event_type=event_type,
                timestamp=timestamp,
                original_timestamp=self._text(event.get("original_timestamp")),
                evidence_file=evidence_file,
                evidence_reference=evidence_row,
                metadata_json=event.get("metadata_json", ""),
                title=(
                    f"Event ID: {event_id}\n"
                    f"Source: {source}\n"
                    f"Type: {event_type}\n"
                    f"Time: {timestamp}\n"
                    f"Evidence: {evidence_reference}"
                ),
                **NODE_STYLES["event"]
            )

            self._add_process_entity(event_id, event, timestamp, evidence_reference)
            self._add_registry_entity(event_id, event, timestamp, evidence_reference)
            self._add_network_entity(event_id, event, timestamp, evidence_reference)
            self._add_file_entity(event_id, event, timestamp, evidence_reference)

        for relationship in relationships:
            source_id = self._text(relationship.get("source_event_id"))
            target_id = self._text(relationship.get("target_event_id"))

            if source_id not in valid_event_ids or target_id not in valid_event_ids:
                continue

            relationship_type = self._text(
                relationship.get("relationship_type")
            ) or "RELATED_TO"

            category = self._text(
                relationship.get("relationship_category")
            ) or "Unknown"

            confidence = self._safe_confidence(
                relationship.get("confidence_score")
            )

            explanation = self._text(relationship.get("explanation"))
            method = self._text(relationship.get("correlation_method"))
            supporting_identifiers = self._safe_identifiers(
                relationship.get("supporting_identifiers")
            )

            evidence_sources = self._safe_identifiers(
                relationship.get("evidence_sources")
            )

            style = EDGE_STYLES.get(category, EDGE_STYLES["Unknown"])

            edge_key = (
                f"{relationship_type}_{source_id}_{target_id}_"
                f"{self.graph.number_of_edges(source_id, target_id)}"
            )

            self.graph.add_edge(
                source_id,
                target_id,
                key=edge_key,
                relationship_type=relationship_type,
                relationship_category=category,
                confidence_score=confidence,
                correlation_method=method,
                supporting_identifiers=supporting_identifiers,
                evidence_sources=evidence_sources,
                explanation=explanation,
                title=(
                    f"[{category}] {relationship_type}\n"
                    f"Confidence: {confidence:.2f}\n"
                    f"Method: {method}\n"
                    f"{explanation}"
                ),
                **style
            )

        logger.info(
            "Evidence Graph built: %d nodes, %d edges for case '%s'",
            self.graph.number_of_nodes(),
            self.graph.number_of_edges(),
            self.case_id
        )

        return self.graph

    def to_json_dict(self) -> Dict[str, Any]:
        nodes = []

        for node_id, data in self.graph.nodes(data=True):
            node_copy = dict(data)
            node_copy["id"] = node_id
            nodes.append(node_copy)

        edges = []

        for source, target, key, data in self.graph.edges(keys=True, data=True):
            edge_copy = dict(data)
            edge_copy["source"] = source
            edge_copy["target"] = target
            edge_copy["key"] = key
            edges.append(edge_copy)

        return {
            "case_id": self.case_id,
            "nodes": nodes,
            "edges": edges
        }