
"""
Investigation Baseline Approaches for U-15 Incident Reconstruction.

BASELINE 1: Process evidence only.
BASELINE 2: Process + Registry evidence, same correlators as the proposed method (no network).
BASELINE 3: All evidence sources with conventional rule-based correlation.
PROPOSED METHOD: Provenance-aware evidence graph over the same rule-based relationships.
"""

from collections import deque
from typing import List, Dict, Any, Set, Tuple, Optional

import networkx as nx

from database.models import NormalizedEvent
from correlation.correlation_engine import CorrelationEngine
from evaluation.metrics import ForensicEvaluator


class BaselineRunner:

    GRAPH_CONFIDENCE_THRESHOLD = 0.70

    GRAPH_STRONG_CATEGORIES = {
        "Directly observed",
        "Strongly supported"
    }

    EXCLUDED_PROCESS_NAMES = {
        "svchost.exe",
        "services.exe",
        "explorer.exe",
        "smss.exe",
        "csrss.exe"
    }

    @staticmethod
    def _find_suspect_pids(
        events: List[NormalizedEvent]
    ) -> Set[int]:

        suspect_pids = set()

        for event in events:
            process_name = (event.process_name or "").lower()

            if (
                process_name
                and process_name not in BaselineRunner.EXCLUDED_PROCESS_NAMES
            ):
                if event.pid is not None:
                    suspect_pids.add(event.pid)

            elif (
                "incidentlab" in (event.file_path or "").lower()
                or "incidentlab" in (event.registry_key or "").lower()
            ):
                if event.pid is not None:
                    suspect_pids.add(event.pid)

        if not suspect_pids:
            suspect_pids = {
                event.pid
                for event in events
                if event.pid is not None
            }

        return suspect_pids

    @staticmethod
    def _chronology(
        events: List[NormalizedEvent],
        event_ids: Set[str]
    ) -> List[str]:

        predicted_events = [
            event
            for event in events
            if event.event_id in event_ids
        ]

        predicted_events.sort(
            key=lambda event: event.timestamp or ""
        )

        return [
            event.event_id
            for event in predicted_events
        ]

    @staticmethod
    def _get_seed_event_ids(
        events: List[NormalizedEvent],
        suspect_pids: Set[int]
    ) -> Set[str]:

        return {
            event.event_id
            for event in events
            if event.pid is not None
            and event.pid in suspect_pids
        }

    @classmethod
    def _is_eligible_relationship(
        cls,
        relationship
    ) -> bool:

        confidence = relationship.confidence_score or 0.0

        category = relationship.relationship_category or ""

        return (
            confidence >= cls.GRAPH_CONFIDENCE_THRESHOLD
            or category in cls.GRAPH_STRONG_CATEGORIES
        )

    @classmethod
    def _get_eligible_relationships(
        cls,
        relationships
    ):

        return [
            relationship
            for relationship in relationships
            if cls._is_eligible_relationship(relationship)
        ]

    @classmethod
    def run_method_1_process_only(
        cls,
        events: List[NormalizedEvent],
        case_id: str,
        temporal_window: float = 5.0
    ) -> Tuple[Set[str], List[Tuple[str, str, str]], List[str]]:

        proc_events = [
            event
            for event in events
            if event.source == "process"
        ]

        suspect_pids = cls._find_suspect_pids(proc_events)

        by_ppid: Dict[int, List[NormalizedEvent]] = {}

        for event in proc_events:
            if event.ppid is not None:
                by_ppid.setdefault(event.ppid, []).append(event)

        expanded_pids = set(suspect_pids)

        for suspect_pid in list(suspect_pids):
            for child in by_ppid.get(suspect_pid, []):
                if child.pid is not None:
                    expanded_pids.add(child.pid)

        predicted_events = [
            event
            for event in proc_events
            if event.pid in expanded_pids
        ]

        predicted_event_ids = {
            event.event_id
            for event in predicted_events
        }

        relationships = []

        by_pid = {
            event.pid: event
            for event in proc_events
            if event.pid is not None
            and event.event_type.upper() == "PROCESS_START"
        }

        for child in proc_events:
            if (
                child.event_type.upper() == "PROCESS_START"
                and child.ppid in by_pid
                and child.event_id in predicted_event_ids
            ):
                parent = by_pid[child.ppid]

                relationships.append(
                    (
                        parent.event_id,
                        child.event_id,
                        "SPAWNED"
                    )
                )

        return (
            predicted_event_ids,
            relationships,
            cls._chronology(proc_events, predicted_event_ids)
        )

    @classmethod
    def run_baseline_1_process_only(
        cls,
        *args,
        **kwargs
    ):

        return cls.run_method_1_process_only(*args, **kwargs)

    @classmethod
    def run_method_2_network_only(
        cls,
        events: List[NormalizedEvent],
        case_id: str,
        temporal_window: float = 5.0
    ) -> Tuple[Set[str], List[Tuple[str, str, str]], List[str]]:

        net_events = [
            event
            for event in events
            if event.source == "network"
            or event.event_type.upper() in ("NET_PACKET", "NET_CONNECT")
        ]

        suspect_event_ids = set()

        for event in net_events:
            destination_ip = event.dst_ip or ""
            source_ip = event.src_ip or ""

            if (
                destination_ip
                and not destination_ip.startswith("127.")
                and destination_ip != "localhost"
            ):
                suspect_event_ids.add(event.event_id)

            elif (
                source_ip
                and not source_ip.startswith("127.")
                and source_ip != "localhost"
            ):
                suspect_event_ids.add(event.event_id)

        if not suspect_event_ids:
            suspect_event_ids = {
                event.event_id
                for event in net_events
            }

        sysmon_net = [
            event
            for event in net_events
            if (event.metadata or {}).get("sysmon_event_id") == 3
        ]

        wire_net = [
            event
            for event in net_events
            if event not in sysmon_net
        ]

        relationships = []

        from correlation.network_correlation import NetworkCorrelator

        for sysmon_event in sysmon_net:
            for wire_event in wire_net:

                is_match, _ = NetworkCorrelator._matches_five_tuple(
                    sysmon_event,
                    wire_event
                )

                if is_match:
                    relationships.append(
                        (
                            sysmon_event.event_id,
                            wire_event.event_id,
                            "OBSERVED_IN"
                        )
                    )

                    suspect_event_ids.add(sysmon_event.event_id)
                    suspect_event_ids.add(wire_event.event_id)

        return (
            suspect_event_ids,
            relationships,
            cls._chronology(net_events, suspect_event_ids)
        )

    @classmethod
    def run_baseline_2_proc_and_reg(
        cls,
        events: List[NormalizedEvent],
        case_id: str,
        temporal_window: float = 5.0
    ) -> Tuple[Set[str], List[Tuple[str, str, str]], List[str]]:

        filtered_events = [
            event
            for event in events
            if event.source in ["process", "registry"]
        ]

        engine = CorrelationEngine(
            case_id=case_id,
            temporal_window=temporal_window
        )

        relationships = engine.run(
            filtered_events,
            save_to_db=False
        )

        suspect_pids = cls._find_suspect_pids(filtered_events)

        predicted_event_ids = {
            event.event_id
            for event in filtered_events
            if event.pid in suspect_pids
        }

        relationship_tuples = []

        for relationship in relationships:

            if (
                relationship.source_event_id in predicted_event_ids
                or relationship.target_event_id in predicted_event_ids
            ):

                relationship_tuples.append(
                    (
                        relationship.source_event_id,
                        relationship.target_event_id,
                        relationship.relationship_type
                    )
                )

                predicted_event_ids.add(
                    relationship.source_event_id
                )

                predicted_event_ids.add(
                    relationship.target_event_id
                )

        return (
            predicted_event_ids,
            relationship_tuples,
            cls._chronology(filtered_events, predicted_event_ids)
        )

    @classmethod
    def run_method_3_rule_based(
        cls,
        events: List[NormalizedEvent],
        case_id: str,
        temporal_window: float = 5.0,
        correlation_options: Optional[Dict[str, bool]] = None
    ) -> Tuple[Set[str], List[Tuple[str, str, str]], List[str]]:

        engine = CorrelationEngine(
            case_id=case_id,
            temporal_window=temporal_window,
            **(correlation_options or {})
        )

        relationships = engine.run(
            events,
            save_to_db=False
        )

        suspect_pids = cls._find_suspect_pids(events)

        seed_event_ids = cls._get_seed_event_ids(
            events,
            suspect_pids
        )

        eligible_relationships = cls._get_eligible_relationships(
            relationships
        )

        predicted_event_ids = set(seed_event_ids)

        relationship_tuples = []

        for relationship in eligible_relationships:

            touches_seed = (
                relationship.source_event_id in seed_event_ids
                or relationship.target_event_id in seed_event_ids
            )

            if touches_seed:

                relationship_tuples.append(
                    (
                        relationship.source_event_id,
                        relationship.target_event_id,
                        relationship.relationship_type
                    )
                )

                predicted_event_ids.add(
                    relationship.source_event_id
                )

                predicted_event_ids.add(
                    relationship.target_event_id
                )

        return (
            predicted_event_ids,
            relationship_tuples,
            cls._chronology(events, predicted_event_ids)
        )

    @classmethod
    def run_baseline_3_all_no_graph(
        cls,
        *args,
        **kwargs
    ):

        return cls.run_method_3_rule_based(*args, **kwargs)

    @classmethod
    def run_method_4_proposed_graph(
        cls,
        events: List[NormalizedEvent],
        case_id: str,
        temporal_window: float = 5.0,
        correlation_options: Optional[Dict[str, bool]] = None
    ) -> Tuple[Set[str], List[Tuple[str, str, str]], List[str]]:

        engine = CorrelationEngine(
            case_id=case_id,
            temporal_window=temporal_window,
            **(correlation_options or {})
        )

        relationships = engine.run(
            events,
            save_to_db=False
        )

        suspect_pids = cls._find_suspect_pids(events)

        seed_event_ids = cls._get_seed_event_ids(
            events,
            suspect_pids
        )

        eligible_relationships = cls._get_eligible_relationships(
            relationships
        )

        graph = nx.MultiGraph()

        for relationship in eligible_relationships:

            graph.add_edge(
                relationship.source_event_id,
                relationship.target_event_id,
                relationship=relationship
            )

        incident_event_ids = set(seed_event_ids)

        distance = {
            seed: 0
            for seed in seed_event_ids
            if graph.has_node(seed)
        }

        frontier = deque(distance.keys())

        while frontier:

            current = frontier.popleft()

            if distance[current] >= 7:
                continue

            for neighbor in graph.neighbors(current):

                if neighbor in distance:
                    continue

                distance[neighbor] = distance[current] + 1

                incident_event_ids.add(neighbor)

                frontier.append(neighbor)

        relationship_tuples = []

        for source_id, target_id, edge_data in graph.edges(
            data=True
        ):

            if (
                source_id in incident_event_ids
                and target_id in incident_event_ids
            ):

                relationship = edge_data["relationship"]

                relationship_tuples.append(
                    (
                        relationship.source_event_id,
                        relationship.target_event_id,
                        relationship.relationship_type
                    )
                )

        return (
            incident_event_ids,
            relationship_tuples,
            cls._chronology(events, incident_event_ids)
        )

    @classmethod
    def run_proposed_method(
        cls,
        *args,
        **kwargs
    ):

        return cls.run_method_4_proposed_graph(*args, **kwargs)

    @classmethod
    def evaluate_all_methods(
        cls,
        events: List[NormalizedEvent],
        case_id: str,
        ground_truth_incident_ids: Set[str],
        ground_truth_relationships: List[Tuple[str, str, str]],
        ground_truth_chronology: List[str],
        temporal_window: float = 5.0
    ) -> List[Dict[str, Any]]:

        all_event_ids = {
            event.event_id
            for event in events
        }

        runners = [
            (
                "Method 1: Process-Only",
                cls.run_method_1_process_only
            ),
            (
                "Method 2: Network-Only",
                cls.run_method_2_network_only
            ),
            (
                "Method 3: Rule-Based Correlation",
                cls.run_method_3_rule_based
            ),
            (
                "Method 4: Proposed Cross-Artifact Graph",
                cls.run_method_4_proposed_graph
            )
        ]

        rows = []

        for name, runner in runners:

            predicted_ids, predicted_relationships, chronology = runner(
                events,
                case_id,
                temporal_window=temporal_window
            )

            event_metrics = ForensicEvaluator.calculate_classification_metrics(
                predicted_ids,
                ground_truth_incident_ids,
                all_event_ids
            )

            relationship_metrics = ForensicEvaluator.calculate_relationship_metrics(
                predicted_relationships,
                ground_truth_relationships
            )

            timeline_accuracy = ForensicEvaluator.calculate_timeline_ordering_accuracy(
                chronology,
                ground_truth_chronology
            )

            ground_truth_count = len(ground_truth_incident_ids)

            coverage = (
                event_metrics["tp"] / ground_truth_count
                if ground_truth_count > 0
                else 1.0
            )

            rows.append({
                "method": name,
                "event_coverage": round(coverage, 4),
                **event_metrics,
                **relationship_metrics,
                "timeline_accuracy": timeline_accuracy
            })

        return rows