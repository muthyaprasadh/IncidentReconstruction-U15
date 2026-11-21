"""
Evidence Graph Analyzer for U-15 Incident Reconstruction.
Calculates forensic graph metrics: degree centrality, incident clusters,
attack paths from initial execution to network egress or persistence, and anomalous subgraphs.
"""
import networkx as nx
from itertools import islice
from typing import List, Dict, Any, Optional, Set

class EvidenceGraphAnalyzer:
    def __init__(self, graph: nx.MultiDiGraph):
        self.graph = graph

    def get_summary_statistics(self) -> Dict[str, Any]:
        """Calculates topological metrics of the evidence graph."""
        n_nodes = self.graph.number_of_nodes()
        n_edges = self.graph.number_of_edges()
        if n_nodes == 0:
            return {
                "node_count": 0, "edge_count": 0, "density": 0.0,
                "connected_clusters": 0, "central_nodes": []
            }

        # Compute degree centrality on simple directed graph
        simple_digraph = nx.DiGraph(self.graph)
        centrality = nx.degree_centrality(simple_digraph)
        sorted_central = sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:5]
        
        top_central = []
        for node_id, score in sorted_central:
            node_data = self.graph.nodes.get(node_id, {})
            top_central.append({
                "node_id": node_id,
                "label": node_data.get("label", node_id),
                "type": node_data.get("node_type", "unknown"),
                "centrality_score": round(score, 4),
                "degree": self.graph.degree(node_id)
            })

        # Connected components (using weakly connected components)
        clusters = list(nx.weakly_connected_components(simple_digraph))

        return {
            "node_count": n_nodes,
            "edge_count": n_edges,
            "density": round(nx.density(simple_digraph), 4),
            "connected_clusters": len(clusters),
            "cluster_sizes": [len(c) for c in sorted(clusters, key=len, reverse=True)[:5]],
            "central_nodes": top_central
        }

    def find_causal_paths(
        self,
        source_node: str,
        target_node: str,
        max_paths: int = 100
    ) -> List[List[str]]:
        """Finds directed paths linking source to target in the evidence graph."""
        if max_paths < 1:
            raise ValueError("max_paths must be positive")
        simple_digraph = nx.DiGraph(self.graph)
        if not simple_digraph.has_node(source_node) or not simple_digraph.has_node(target_node):
            return []
        try:
            paths = nx.all_simple_paths(
                simple_digraph,
                source=source_node,
                target=target_node,
                cutoff=7,
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
        """Extracts a focused subgraph based on forensic criteria."""
        subgraph = self.graph.copy()
        
        # Filter nodes if node types specified
        if allowed_node_types:
            nodes_to_remove = [
                n for n, d in subgraph.nodes(data=True)
                if d.get("node_type") not in allowed_node_types
            ]
            subgraph.remove_nodes_from(nodes_to_remove)

        # Filter edges based on confidence and category
        edges_to_remove = []
        for u, v, k, d in subgraph.edges(keys=True, data=True):
            conf = d.get("confidence_score", 0.0)
            cat = d.get("relationship_category", "")
            if conf < min_confidence:
                edges_to_remove.append((u, v, k))
            elif allowed_categories and cat not in allowed_categories:
                edges_to_remove.append((u, v, k))

        for u, v, k in edges_to_remove:
            subgraph.remove_edge(u, v, key=k)

        # Remove isolated nodes after edge filtering if they have degree 0
        isolates = list(nx.isolates(subgraph))
        subgraph.remove_nodes_from(isolates)

        return subgraph
