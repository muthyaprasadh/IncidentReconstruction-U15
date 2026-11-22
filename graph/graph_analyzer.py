import networkx as nx
from itertools import islice
from typing import List, Dict, Any, Optional


OBSERVATION_RELATIONSHIP_TYPES = {
    "OBSERVED_PROCESS_CONTEXT",
    "OBSERVED_REGISTRY_TARGET",
    "OBSERVED_SOURCE_ENDPOINT",
    "OBSERVED_DESTINATION_ENDPOINT",
    "OBSERVED_FILE_TARGET"
}

CAUSAL_RELATIONSHIP_TYPES = {
    "SPAWNED"
}

SUPPORTED_CAUSAL_CATEGORIES = {
    "directly observed",
    "strongly supported"
}


class EvidenceGraphAnalyzer:
    def __init__(self, graph: nx.MultiDiGraph):
        self.graph = graph

    @staticmethod
    def _is_supported_causal_relationship(data: Dict[str, Any]) -> bool:
        relationship_type = str(
            data.get("relationship_type", "")
        ).strip().upper()

        category = str(
            data.get("relationship_category", "")
        ).strip().casefold()

        return (
            relationship_type in CAUSAL_RELATIONSHIP_TYPES
            and category in SUPPORTED_CAUSAL_CATEGORIES
        )

    def _edge_category_counts(self) -> Dict[str, int]:
        counts = {}

        for _, _, data in self.graph.edges(data=True):
            category = data.get("relationship_category", "Unknown")
            counts[category] = counts.get(category, 0) + 1

        return counts

    def _relationship_type_counts(self) -> Dict[str, int]:
        counts = {}

        for _, _, data in self.graph.edges(data=True):
            relationship_type = data.get(
                "relationship_type",
                "RELATED_TO"
            )
            counts[relationship_type] = counts.get(relationship_type, 0) + 1

        return counts

    def _count_observation_edges(self) -> int:
        return sum(
            1
            for _, _, data in self.graph.edges(data=True)
            if data.get("relationship_type") in OBSERVATION_RELATIONSHIP_TYPES
        )

    def _count_cross_event_relationships(self) -> int:
        return sum(
            1
            for _, _, data in self.graph.edges(data=True)
            if data.get("relationship_type") not in OBSERVATION_RELATIONSHIP_TYPES
        )

    def _count_causal_relationships(self) -> int:
        return sum(
            1
            for _, _, data in self.graph.edges(data=True)
            if self._is_supported_causal_relationship(data)
        )

    def get_summary_statistics(self) -> Dict[str, Any]:
        node_count = self.graph.number_of_nodes()
        edge_count = self.graph.number_of_edges()

        category_counts = self._edge_category_counts()
        relationship_counts = self._relationship_type_counts()

        observation_count = self._count_observation_edges()
        cross_event_count = self._count_cross_event_relationships()
        causal_count = self._count_causal_relationships()

        if node_count == 0:
            return {
                "node_count": 0,
                "edge_count": 0,
                "observation_edge_count": 0,
                "cross_event_relationship_count": 0,
                "causal_relationship_count": 0,
                "relationship_category_counts": category_counts,
                "relationship_type_counts": relationship_counts,
                "density": 0.0,
                "connected_clusters": 0,
                "cluster_sizes": [],
                "central_nodes": []
            }

        simple_digraph = nx.DiGraph()
        simple_digraph.add_nodes_from(self.graph.nodes(data=True))

        for source, target in self.graph.edges():
            simple_digraph.add_edge(source, target)

        centrality = nx.degree_centrality(simple_digraph)

        sorted_central = sorted(
            centrality.items(),
            key=lambda item: item[1],
            reverse=True
        )[:5]

        central_nodes = []

        for node_id, score in sorted_central:
            node_data = self.graph.nodes.get(node_id, {})

            central_nodes.append({
                "node_id": node_id,
                "label": node_data.get("label", node_id),
                "type": node_data.get("node_type", "unknown"),
                "centrality_score": round(score, 4),
                "degree": self.graph.degree(node_id)
            })

        clusters = list(nx.weakly_connected_components(simple_digraph))

        return {
            "node_count": node_count,
            "edge_count": edge_count,
            "observation_edge_count": observation_count,
            "cross_event_relationship_count": cross_event_count,
            "causal_relationship_count": causal_count,
            "relationship_category_counts": category_counts,
            "relationship_type_counts": relationship_counts,
            "density": round(nx.density(simple_digraph), 4),
            "connected_clusters": len(clusters),
            "cluster_sizes": [
                len(cluster)
                for cluster in sorted(clusters, key=len, reverse=True)[:5]
            ],
            "central_nodes": central_nodes
        }

    def find_causal_paths(
        self,
        source_node: str,
        target_node: str,
        max_paths: int = 100
    ) -> List[List[str]]:
        if max_paths < 1:
            raise ValueError("max_paths must be positive")

        if (
            not self.graph.has_node(source_node)
            or not self.graph.has_node(target_node)
        ):
            return []

        causal_graph = nx.DiGraph()
        causal_graph.add_nodes_from(self.graph.nodes(data=True))

        for source, target, data in self.graph.edges(data=True):
            if self._is_supported_causal_relationship(data):
                causal_graph.add_edge(source, target)

        try:
            paths = nx.all_simple_paths(
                causal_graph,
                source=source_node,
                target=target_node,
                cutoff=7
            )

            return list(islice(paths, max_paths))

        except nx.NetworkXNoPath:
            return []

    def find_evidence_paths(
        self,
        source_node: str,
        target_node: str,
        max_paths: int = 100
    ) -> List[List[str]]:
        if max_paths < 1:
            raise ValueError("max_paths must be positive")

        if (
            not self.graph.has_node(source_node)
            or not self.graph.has_node(target_node)
        ):
            return []

        evidence_graph = nx.DiGraph()
        evidence_graph.add_nodes_from(self.graph.nodes(data=True))

        for source, target in self.graph.edges():
            evidence_graph.add_edge(source, target)

        try:
            paths = nx.all_simple_paths(
                evidence_graph,
                source=source_node,
                target=target_node,
                cutoff=7
            )

            return list(islice(paths, max_paths))

        except nx.NetworkXNoPath:
            return []

    def filter_subgraph(
        self,
        min_confidence: float = 0.0,
        allowed_categories: Optional[List[str]] = None,
        allowed_node_types: Optional[List[str]] = None
    ) -> nx.MultiDiGraph:
        if not 0.0 <= min_confidence <= 1.0:
            raise ValueError("min_confidence must be between 0.0 and 1.0")

        subgraph = self.graph.copy()

        if allowed_node_types is not None:
            allowed_node_types = set(allowed_node_types)

            nodes_to_remove = [
                node_id
                for node_id, data in subgraph.nodes(data=True)
                if data.get("node_type") not in allowed_node_types
            ]

            subgraph.remove_nodes_from(nodes_to_remove)

        edges_to_remove = []

        for source, target, key, data in subgraph.edges(
            keys=True,
            data=True
        ):
            confidence = data.get("confidence_score", 0.0)

            try:
                confidence = float(confidence)
            except (TypeError, ValueError):
                confidence = 0.0

            category = data.get("relationship_category", "Unknown")

            if confidence < min_confidence:
                edges_to_remove.append((source, target, key))
                continue

            if (
                allowed_categories is not None
                and category not in allowed_categories
            ):
                edges_to_remove.append((source, target, key))

        for source, target, key in edges_to_remove:
            subgraph.remove_edge(source, target, key=key)

        isolates = list(nx.isolates(subgraph))
        subgraph.remove_nodes_from(isolates)

        return subgraph